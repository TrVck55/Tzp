#!/usr/bin/env python3
"""Roblox profile intelligence CLI.

Features:
- Resolve a username or numeric user ID.
- Pull profile metadata, counts, previous usernames, and groups.
- Fetch friends / followers / followings with pagination.
- Compute relationship insights such as mutual followers/following.
- Export JSON, CSV, and a readable Markdown report.
- Use resilient HTTP retries and gentle rate-limit backoff.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import requests
from bs4 import BeautifulSoup

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

REQUEST_TIMEOUT = 15
DEFAULT_MAX_RETRIES = 4
PAGE_SIZE = 100
BATCH_SIZE = 100


@dataclass
class Entity:
    user_id: int
    name: str
    url: str


@dataclass
class RobloxProfile:
    user_id: int
    alias: str
    display_name: str
    description: str
    is_banned: bool
    has_verified_badge: bool
    friends_count: int
    followers_count: int
    following_count: int
    join_date: str
    previous_usernames: List[str] = field(default_factory=list)
    groups: List[Dict[str, Any]] = field(default_factory=list)
    about_me: str = "Not available"
    friends_list: List[Entity] = field(default_factory=list)
    followers_list: List[Entity] = field(default_factory=list)
    following_list: List[Entity] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def profile_url(self) -> str:
        return f"https://www.roblox.com/users/{self.user_id}/profile"

    @property
    def account_age_days(self) -> Optional[int]:
        if not self.join_date:
            return None
        try:
            joined = dt.datetime.fromisoformat(self.join_date.replace("Z", "+00:00"))
            now = dt.datetime.now(dt.timezone.utc)
            return max((now - joined).days, 0)
        except ValueError:
            return None

    @property
    def mutual_relationships(self) -> List[Entity]:
        followers = {e.user_id for e in self.followers_list}
        following = {e.user_id for e in self.following_list}
        overlap = followers & following
        return [e for e in self.following_list if e.user_id in overlap]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "alias": self.alias,
            "display_name": self.display_name,
            "description": self.description,
            "is_banned": self.is_banned,
            "has_verified_badge": self.has_verified_badge,
            "friends": self.friends_count,
            "followers": self.followers_count,
            "following": self.following_count,
            "join_date": self.join_date,
            "account_age_days": self.account_age_days,
            "previous_usernames": self.previous_usernames,
            "groups": self.groups,
            "about_me": self.about_me,
            "friends_list": [e.__dict__ for e in self.friends_list],
            "followers_list": [e.__dict__ for e in self.followers_list],
            "following_list": [e.__dict__ for e in self.following_list],
            "mutual_relationships": [e.__dict__ for e in self.mutual_relationships],
            "raw": self.raw,
            "profile_url": self.profile_url,
        }


class RobloxClient:
    def __init__(self, timeout: int = REQUEST_TIMEOUT, max_retries: int = DEFAULT_MAX_RETRIES):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()

    def _headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[requests.Response]:
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    json=json_data,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
            except requests.RequestException:
                if attempt >= self.max_retries:
                    return None
                time.sleep(min(2 ** attempt, 8))
                continue

            if response.status_code == 200:
                return response

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                try:
                    delay = int(retry_after) if retry_after else min(2 ** attempt, 8)
                except ValueError:
                    delay = min(2 ** attempt, 8)
                time.sleep(max(delay, 1))
                continue

            if 500 <= response.status_code < 600:
                if attempt >= self.max_retries:
                    return response
                time.sleep(min(2 ** attempt, 8))
                continue

            return response

        return None

    def json_or_none(self, response: Optional[requests.Response]) -> Optional[Dict[str, Any]]:
        if not response:
            return None
        try:
            data = response.json()
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def search_user_id(self, identifier: str) -> Optional[int]:
        if identifier.isdigit():
            return int(identifier)

        exact = self.request(
            "GET",
            "https://users.roblox.com/v1/users/search",
            params={"keyword": identifier, "limit": 10},
        )
        data = self.json_or_none(exact)
        if data and isinstance(data.get("data"), list):
            exact_matches = [u for u in data["data"] if str(u.get("name", "")).lower() == identifier.lower()]
            candidates = exact_matches or data["data"]
            for user in candidates:
                user_id = user.get("id") or user.get("userId")
                if isinstance(user_id, int):
                    return user_id
                if isinstance(user_id, str) and user_id.isdigit():
                    return int(user_id)

        # Fallback to profile redirect.
        try:
            response = self.request(
                "GET",
                "https://www.roblox.com/users/profile",
                params={"username": identifier},
            )
            if response and response.url and "/users/" in response.url:
                parts = response.url.split("/")
                for index, part in enumerate(parts):
                    if part == "users" and index + 1 < len(parts):
                        candidate = parts[index + 1]
                        if candidate.isdigit():
                            return int(candidate)
        except Exception:
            return None

        return None

    def previous_usernames(self, user_id: int) -> List[str]:
        response = self.request(
            "GET",
            f"https://users.roblox.com/v1/users/{user_id}/username-history",
            params={"limit": 100, "sortOrder": "Asc"},
        )
        data = self.json_or_none(response)
        if not data or not isinstance(data.get("data"), list):
            return []
        return [entry.get("name", "") for entry in data["data"] if entry.get("name")]

    def groups(self, user_id: int) -> List[Dict[str, Any]]:
        response = self.request("GET", f"https://groups.roblox.com/v2/users/{user_id}/groups/roles")
        data = self.json_or_none(response)
        if not data or not isinstance(data.get("data"), list):
            return []

        groups: List[Dict[str, Any]] = []
        for item in data["data"]:
            group_info = item.get("group", {}) if isinstance(item, dict) else {}
            group_id = group_info.get("id")
            groups.append(
                {
                    "name": group_info.get("name", "Unknown"),
                    "link": f"https://www.roblox.com/groups/{group_id}" if group_id else "",
                    "members": group_info.get("memberCount", 0),
                    "role": item.get("role", {}).get("name", "") if isinstance(item, dict) else "",
                }
            )
        return groups

    def about_me(self, user_id: int, fallback_description: str = "") -> str:
        if fallback_description.strip():
            return fallback_description.strip()

        response = self.request("GET", f"https://www.roblox.com/users/{user_id}/profile")
        if not response or response.status_code != 200:
            return "Not available"

        soup = BeautifulSoup(response.text, "html.parser")
        selectors = [
            "span.profile-about-content-text.linkify",
            "div.profile-about-content span",
            "div.about-section span",
            "[data-testid='profile-about-content']",
        ]
        for selector in selectors:
            element = soup.select_one(selector)
            if element:
                text = element.get_text(" ", strip=True)
                if text:
                    return text
        return "Not available"

    def resolve_display_names(self, user_ids: Sequence[int]) -> Dict[int, str]:
        result: Dict[int, str] = {}
        for start in range(0, len(user_ids), BATCH_SIZE):
            chunk = [int(x) for x in user_ids[start : start + BATCH_SIZE]]
            response = self.request(
                "POST",
                "https://users.roblox.com/v1/users",
                json_data={"userIds": chunk, "excludeBannedUsers": False},
            )
            data = self.json_or_none(response)
            if not data or not isinstance(data.get("data"), list):
                continue

            for user in data["data"]:
                uid = user.get("id")
                if uid is None:
                    continue
                display_name = user.get("displayName") or user.get("name") or str(uid)
                result[int(uid)] = str(display_name)

            if start + BATCH_SIZE < len(user_ids):
                time.sleep(0.2)

        return result

    def entity_list(self, user_id: int, entity_type: str) -> List[Entity]:
        ordered_ids: List[int] = []
        seen: Set[int] = set()
        cursor = ""

        while True:
            params = {"limit": PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor

            response = self.request(
                "GET",
                f"https://friends.roblox.com/v1/users/{user_id}/{entity_type}",
                params=params,
            )
            data = self.json_or_none(response)
            if not data or not isinstance(data.get("data"), list):
                break

            for entity in data["data"]:
                candidate: Optional[int] = None
                if isinstance(entity, dict):
                    user_obj = entity.get("user")
                    if isinstance(user_obj, dict) and user_obj.get("id") is not None:
                        candidate = user_obj.get("id")
                    elif entity.get("id") is not None:
                        candidate = entity.get("id")

                try:
                    candidate_int = int(candidate) if candidate is not None else None
                except (TypeError, ValueError):
                    candidate_int = None

                if candidate_int is None or candidate_int in seen:
                    continue
                seen.add(candidate_int)
                ordered_ids.append(candidate_int)

            cursor = str(data.get("nextPageCursor") or "")
            if not cursor:
                break

            time.sleep(0.25)

        if not ordered_ids:
            return []

        names = self.resolve_display_names(ordered_ids)
        return [
            Entity(user_id=uid, name=names.get(uid, str(uid)), url=f"https://www.roblox.com/users/{uid}/profile")
            for uid in ordered_ids
        ]

    def profile(self, identifier: str) -> Optional[RobloxProfile]:
        user_id = self.search_user_id(identifier)
        if not user_id:
            return None

        response = self.request("GET", f"https://users.roblox.com/v1/users/{user_id}")
        user_data = self.json_or_none(response)
        if not user_data:
            return None

        friends_count = self._count(f"https://friends.roblox.com/v1/users/{user_id}/friends/count")
        followers_count = self._count(f"https://friends.roblox.com/v1/users/{user_id}/followers/count")
        following_count = self._count(f"https://friends.roblox.com/v1/users/{user_id}/followings/count")

        previous_usernames = self.previous_usernames(user_id)
        groups = self.groups(user_id)
        about_me = self.about_me(user_id, fallback_description=str(user_data.get("description", "")))
        friends_list = self.entity_list(user_id, "friends")
        followers_list = self.entity_list(user_id, "followers")
        following_list = self.entity_list(user_id, "followings")

        return RobloxProfile(
            user_id=user_id,
            alias=str(user_data.get("name", "")),
            display_name=str(user_data.get("displayName", "")),
            description=str(user_data.get("description", "")),
            is_banned=bool(user_data.get("isBanned", False)),
            has_verified_badge=bool(user_data.get("hasVerifiedBadge", False)),
            friends_count=friends_count,
            followers_count=followers_count,
            following_count=following_count,
            join_date=str(user_data.get("created", "")),
            previous_usernames=previous_usernames,
            groups=groups,
            about_me=about_me,
            friends_list=friends_list,
            followers_list=followers_list,
            following_list=following_list,
            raw=user_data,
        )

    def _count(self, url: str) -> int:
        response = self.request("GET", url)
        data = self.json_or_none(response)
        if data and "count" in data:
            try:
                return int(data.get("count") or 0)
            except (TypeError, ValueError):
                return 0
        return 0


def export_json(data: Dict[str, Any], filename: Path) -> None:
    filename.parent.mkdir(parents=True, exist_ok=True)
    with filename.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def export_csv(rows: Sequence[Sequence[Any]], filename: Path) -> None:
    filename.parent.mkdir(parents=True, exist_ok=True)
    with filename.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter="|")
        for row in rows:
            writer.writerow([str(cell) for cell in row])


def export_markdown(profile: RobloxProfile, filename: Path) -> None:
    filename.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Roblox Profile Report — {profile.display_name or profile.alias}",
        "",
        f"- User ID: `{profile.user_id}`",
        f"- Alias: `{profile.alias or 'N/A'}`",
        f"- Display Name: `{profile.display_name or 'N/A'}`",
        f"- Profile URL: {profile.profile_url}",
        f"- Banned: {'Yes' if profile.is_banned else 'No'}",
        f"- Verified Badge: {'Yes' if profile.has_verified_badge else 'No'}",
        f"- Friends: {profile.friends_count}",
        f"- Followers: {profile.followers_count}",
        f"- Following: {profile.following_count}",
        f"- Join Date: `{profile.join_date or 'N/A'}`",
        f"- Account Age (days): {profile.account_age_days if profile.account_age_days is not None else 'Unknown'}",
        "",
        "## About",
        "",
        profile.about_me or "Not available",
        "",
        "## Previous Usernames",
        "",
        ", ".join(profile.previous_usernames) if profile.previous_usernames else "None detected",
        "",
        "## Mutual Followers / Following",
        "",
        ", ".join(entity.name for entity in profile.mutual_relationships) if profile.mutual_relationships else "None detected",
    ]
    filename.write_text("\n".join(lines), encoding="utf-8")


def build_entity_csv_rows(title: str, entities: Sequence[Entity]) -> List[List[str]]:
    rows = [[title, "Link"]]
    for entity in entities:
        rows.append([entity.name, entity.url])
    return rows


def build_groups_csv_rows(groups: Sequence[Dict[str, Any]]) -> List[List[str]]:
    rows = [["Name", "Link", "Members", "Role"]]
    for group in groups:
        rows.append(
            [
                str(group.get("name", "")),
                str(group.get("link", "")),
                str(group.get("members", 0)),
                str(group.get("role", "")),
            ]
        )
    return rows


def print_summary(profile: RobloxProfile) -> None:
    print(f"User ID: {profile.user_id}")
    print(f"Alias: {profile.alias}")
    print(f"Display Name: {profile.display_name}")
    print(f"Description: {profile.description}")
    print(f"Banned: {'Yes' if profile.is_banned else 'No'}")
    print(f"Verified Badge: {'Yes' if profile.has_verified_badge else 'No'}")
    print(f"Friends: {profile.friends_count}")
    print(f"Followers: {profile.followers_count}")
    print(f"Following: {profile.following_count}")
    print(f"Join Date: {profile.join_date}")
    print(f"Account Age (days): {profile.account_age_days if profile.account_age_days is not None else 'Unknown'}")

    previous = ", ".join(profile.previous_usernames) if profile.previous_usernames else "None detected"
    mutual = ", ".join(entity.name for entity in profile.mutual_relationships) if profile.mutual_relationships else "None detected"
    print(f"Previous Usernames: {previous}")
    print(f"Mutual Followers/Following: {mutual}")
    print(f"\nAbout Me: {profile.about_me}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect a Roblox user profile with exports and relationship insights."
    )
    parser.add_argument("identifier", help="Roblox username or numeric user ID")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for exported files (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Export the full profile as JSON",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Export a Markdown report",
    )
    parser.add_argument(
        "--no-lists",
        action="store_true",
        help="Skip exporting groups, friends, followers, and following CSV files",
    )
    parser.add_argument(
        "--lists-limit",
        type=int,
        default=0,
        help="Limit exported list items per category (0 = no limit)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=REQUEST_TIMEOUT,
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help="Maximum retries for transient failures",
    )
    args = parser.parse_args()

    client = RobloxClient(timeout=args.timeout, max_retries=args.retries)
    profile = client.profile(args.identifier)

    if not profile:
        print("User not found.")
        raise SystemExit(1)

    print_summary(profile)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.json:
        export_json(profile.as_dict(), output_dir / "user_info.json")
        print("\nFull profile exported to 'user_info.json'")

    if args.markdown:
        export_markdown(profile, output_dir / "user_report.md")
        print("Markdown report exported to 'user_report.md'")

    if args.no_lists:
        return

    def maybe_limit(items: Sequence[Any]) -> Sequence[Any]:
        return items[: args.lists_limit] if args.lists_limit and args.lists_limit > 0 else items

    print("\nGroups:")
    groups = maybe_limit(profile.groups)
    for group in groups:
        print(f"- {group.get('name', 'Unknown')} ({group.get('members', 0)} members)")
        if group.get("link"):
            print(f"  Link: {group['link']}")

    export_csv(build_groups_csv_rows(groups), output_dir / "groups.csv")
    print("Group information exported to 'groups.csv'")

    for label, entities in [
        ("friends", maybe_limit(profile.friends_list)),
        ("followers", maybe_limit(profile.followers_list)),
        ("following", maybe_limit(profile.following_list)),
    ]:
        export_csv(build_entity_csv_rows(label.capitalize(), entities), output_dir / f"{label}.csv")
        print(f"{label.capitalize()} list exported to '{label}.csv'")


if __name__ == "__main__":
    main()