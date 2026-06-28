#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
┌─────────────────────────────────────────────┐
│  WebScan Pro - Termux Edition v2.0          │
│  Web Misconfiguration & Vulnerability Tool  │
└─────────────────────────────────────────────┘
  pip install rich requests
"""

import os, sys, ssl, json, socket, re, time, threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse

# ── Dependency checks ──────────────────────────────────────
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing: pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                                TextColumn, TimeElapsedColumn, TaskProgressColumn)
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
    from rich.align import Align
    from rich.columns import Columns
    from rich.markup import escape
    from rich.padding import Padding
    from rich.live import Live
except ImportError:
    print("[!] Missing: pip install rich")
    sys.exit(1)

# ── Globals ────────────────────────────────────────────────
console   = Console()
SAVE_DIR  = Path.home() / "scanner_reports"
SAVE_DIR.mkdir(exist_ok=True)
VERSION   = "2.0-termux"
TIMEOUT   = 10
UA        = "Mozilla/5.0 (Linux; Android 13) WebScan-Pro/2.0"


# ══════════════════════════════════════════════════════════
#  VULNERABILITY DATABASE
# ══════════════════════════════════════════════════════════
class VulnDB:
    """Local CVE / CWE / exploit-signature database."""

    CVE: Dict[str, Dict] = {
        "Apache": {
            "2.4.49":  ["CVE-2021-41773", "CVE-2021-42013"],
            "2.4.50":  ["CVE-2021-42013"],
            "2.2":     ["CVE-2011-3192", "CVE-2011-3368"],
        },
        "nginx": {
            "1.3.9":   ["CVE-2013-2028"],
            "0.8":     ["CVE-2013-4547"],
        },
        "OpenSSL": {
            "1.0.1":   ["CVE-2014-0160"],   # Heartbleed
            "1.0.2":   ["CVE-2016-2107"],
            "3.0.0":   ["CVE-2022-3602", "CVE-2022-3786"],
        },
        "PHP": {
            "5":       ["CVE-2019-11043", "CVE-2012-1823"],
            "7.1":     ["CVE-2019-11043"],
            "8.0":     ["CVE-2022-31625"],
        },
        "WordPress": {
            "4":       ["CVE-2017-5487", "CVE-2017-5488"],
            "5.0":     ["CVE-2019-8943",  "CVE-2019-8942"],
        },
        "Drupal": {
            "7":       ["CVE-2018-7600"],   # Drupalgeddon2
            "8":       ["CVE-2018-7602"],
        },
        "Joomla": {
            "3.4":     ["CVE-2015-8562"],
        },
        "IIS": {
            "6.0":     ["CVE-2017-7269"],   # ScStoragePathFromUrl RCE
            "7.5":     ["CVE-2010-2730"],
        },
        "Tomcat": {
            "9.0":     ["CVE-2020-1938"],   # Ghostcat
            "10.0":    ["CVE-2022-34305"],
        },
    }

    CVE_DETAIL: Dict[str, Dict] = {
        "CVE-2021-41773": {"severity": "CRITICAL", "desc": "Path traversal & RCE in Apache 2.4.49"},
        "CVE-2021-42013": {"severity": "CRITICAL", "desc": "Path traversal bypass in Apache 2.4.50"},
        "CVE-2014-0160":  {"severity": "CRITICAL", "desc": "Heartbleed – OpenSSL memory disclosure"},
        "CVE-2022-3602":  {"severity": "CRITICAL", "desc": "OpenSSL 3.x buffer overflow"},
        "CVE-2018-7600":  {"severity": "CRITICAL", "desc": "Drupalgeddon2 – Unauthenticated RCE"},
        "CVE-2017-7269":  {"severity": "CRITICAL", "desc": "IIS 6.0 WebDAV buffer overflow RCE"},
        "CVE-2020-1938":  {"severity": "CRITICAL", "desc": "Ghostcat – Tomcat AJP file read/RCE"},
        "CVE-2019-11043": {"severity": "HIGH",     "desc": "PHP-FPM remote code execution"},
        "CVE-2013-2028":  {"severity": "HIGH",     "desc": "nginx stack-based buffer overflow"},
        "CVE-2015-8562":  {"severity": "CRITICAL", "desc": "Joomla RCE via HTTP headers"},
        "CVE-2017-5487":  {"severity": "MEDIUM",   "desc": "WordPress REST API user enumeration"},
        "CVE-2019-8943":  {"severity": "HIGH",     "desc": "WordPress arbitrary file overwrite"},
        "CVE-2011-3192":  {"severity": "HIGH",     "desc": "Apache Killer – Range header DoS"},
        "CVE-2016-2107":  {"severity": "HIGH",     "desc": "OpenSSL AES-NI padding oracle"},
    }

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "sev": "HIGH",
            "tip": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "cwe": "CWE-319",
        },
        "Content-Security-Policy": {
            "sev": "HIGH",
            "tip": "Define a restrictive CSP policy to block XSS",
            "cwe": "CWE-79",
        },
        "X-Frame-Options": {
            "sev": "MEDIUM",
            "tip": "Add: X-Frame-Options: DENY  (prevents clickjacking)",
            "cwe": "CWE-1021",
        },
        "X-Content-Type-Options": {
            "sev": "MEDIUM",
            "tip": "Add: X-Content-Type-Options: nosniff",
            "cwe": "CWE-430",
        },
        "Referrer-Policy": {
            "sev": "LOW",
            "tip": "Add: Referrer-Policy: no-referrer-when-downgrade",
            "cwe": "CWE-200",
        },
        "Permissions-Policy": {
            "sev": "LOW",
            "tip": "Add Permissions-Policy to restrict browser features",
            "cwe": "CWE-693",
        },
        "X-XSS-Protection": {
            "sev": "LOW",
            "tip": "Add: X-XSS-Protection: 1; mode=block  (legacy browsers)",
            "cwe": "CWE-79",
        },
    }

    SENSITIVE_PATHS = [
        ("/.git/HEAD",          "CRITICAL", "Git repo exposed – source code leak"),
        ("/.git/config",        "CRITICAL", "Git config exposed"),
        ("/.env",               "CRITICAL", ".env file exposed – credentials leak"),
        ("/.env.production",    "CRITICAL", "Production .env exposed"),
        ("/.env.local",         "CRITICAL", "Local .env exposed"),
        ("/config.php",         "HIGH",     "PHP config file exposed"),
        ("/wp-config.php",      "HIGH",     "WordPress config exposed"),
        ("/configuration.php",  "HIGH",     "Joomla config exposed"),
        ("/settings.py",        "HIGH",     "Django settings exposed"),
        ("/database.yml",       "HIGH",     "Rails DB credentials exposed"),
        ("/phpinfo.php",        "HIGH",     "phpinfo() leaks server internals"),
        ("/info.php",           "HIGH",     "PHP info page exposed"),
        ("/server-status",      "MEDIUM",   "Apache server-status exposed"),
        ("/server-info",        "MEDIUM",   "Apache server-info exposed"),
        ("/.htaccess",          "MEDIUM",   ".htaccess file exposed"),
        ("/web.config",         "MEDIUM",   "IIS web.config exposed"),
        ("/crossdomain.xml",    "MEDIUM",   "Flash crossdomain policy exposed"),
        ("/sitemap.xml",        "INFO",     "Sitemap reveals URL structure"),
        ("/robots.txt",         "INFO",     "robots.txt reveals disallowed paths"),
        ("/backup.zip",         "CRITICAL", "Backup archive exposed"),
        ("/backup.sql",         "CRITICAL", "Database dump exposed"),
        ("/dump.sql",           "CRITICAL", "Database dump exposed"),
        ("/composer.json",      "LOW",      "Package manifest exposed"),
        ("/package.json",       "LOW",      "Node package manifest exposed"),
        ("/.DS_Store",          "LOW",      "macOS .DS_Store leaks directory structure"),
        ("/admin",              "MEDIUM",   "Admin panel reachable"),
        ("/administrator",      "MEDIUM",   "Admin panel reachable"),
        ("/wp-admin",           "MEDIUM",   "WordPress admin exposed"),
        ("/phpmyadmin",         "HIGH",     "phpMyAdmin panel exposed"),
        ("/adminer.php",        "HIGH",     "Adminer DB tool exposed"),
        ("/.svn/entries",       "HIGH",     "SVN repo metadata exposed"),
        ("/.well-known/security.txt", "INFO", "Security.txt policy present"),
    ]

    WEAK_CIPHERS = ["DES", "RC4", "NULL", "EXPORT", "ADH", "MD5", "3DES"]
    WEAK_PROTOS  = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

    @staticmethod
    def lookup_cve(cve_id: str) -> Dict:
        return VulnDB.CVE_DETAIL.get(cve_id, {
            "severity": "MEDIUM",
            "desc":     f"Known vulnerability – see https://nvd.nist.gov/vuln/detail/{cve_id}"
        })

    @staticmethod
    def match_software(server_header: str) -> List[Tuple[str, str, List[str]]]:
        """Return [(software, detected_version, [cves]), ...]"""
        found = []
        for soft, versions in VulnDB.CVE.items():
            pattern = re.compile(rf"{soft}[/\s]+([\d\.]+)", re.I)
            m = pattern.search(server_header)
            if not m:
                continue
            ver = m.group(1)
            for prefix, cves in versions.items():
                if ver.startswith(prefix):
                    found.append((soft, ver, cves))
        return found


# ══════════════════════════════════════════════════════════
#  SCANNER ENGINE
# ══════════════════════════════════════════════════════════
SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}
SEV_ICON = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def finding(category: str, severity: str, title: str,
            description: str, recommendation: str,
            cve: str = "", cwe: str = "", url: str = "") -> Dict:
    return dict(
        category=category, severity=severity, title=title,
        description=description, recommendation=recommendation,
        cve=cve, cwe=cwe, url=url, ts=datetime.now().isoformat()
    )


class Scanner:
    def __init__(self):
        self.db       = VulnDB()
        self.findings: List[Dict] = []
        self._lock    = threading.Lock()

    def _add(self, f: Dict):
        with self._lock:
            self.findings.append(f)

    # ── helpers ───────────────────────────────────────────
    def _get(self, url: str, path: str = "", allow_redirects: bool = True,
             stream: bool = False) -> Optional[requests.Response]:
        target = url.rstrip("/") + ("/" + path.lstrip("/") if path else "")
        try:
            r = requests.get(
                target, timeout=TIMEOUT, verify=False,
                allow_redirects=allow_redirects, stream=stream,
                headers={"User-Agent": UA}
            )
            return r
        except Exception:
            return None

    def _head(self, url: str, path: str = "") -> Optional[requests.Response]:
        target = url.rstrip("/") + ("/" + path.lstrip("/") if path else "")
        try:
            r = requests.head(
                target, timeout=TIMEOUT, verify=False,
                allow_redirects=True,
                headers={"User-Agent": UA}
            )
            return r
        except Exception:
            return None

    # ── Module 1: Security Headers ────────────────────────
    def scan_headers(self, url: str, progress, task):
        r = self._get(url)
        if not r:
            progress.advance(task, len(VulnDB.SECURITY_HEADERS))
            return

        hdrs = {k.strip(): v.strip() for k, v in r.headers.items()}

        # Missing security headers
        for hdr, meta in VulnDB.SECURITY_HEADERS.items():
            if hdr not in hdrs and hdr.lower() not in {k.lower() for k in hdrs}:
                self._add(finding(
                    category="Security Headers",
                    severity=meta["sev"],
                    title=f"Missing {hdr}",
                    description=f"The response does not include {hdr}.",
                    recommendation=meta["tip"],
                    cwe=meta["cwe"],
                ))
            progress.advance(task)

        # Server version disclosure
        server = hdrs.get("Server", hdrs.get("server", ""))
        if server:
            if re.search(r"[\d\.]{3,}", server):
                self._add(finding(
                    category="Information Disclosure",
                    severity="LOW",
                    title="Server Version Disclosed",
                    description=f"Server header reveals version: {server}",
                    recommendation="Strip version numbers from the Server header.",
                    cwe="CWE-200",
                ))
            # CVE correlation
            matches = VulnDB.match_software(server)
            for soft, ver, cves in matches:
                for cve_id in cves:
                    detail = VulnDB.lookup_cve(cve_id)
                    self._add(finding(
                        category="Known CVE",
                        severity=detail["severity"],
                        title=f"{soft} {ver} — {cve_id}",
                        description=detail["desc"],
                        recommendation=f"Update {soft} to the latest stable version.",
                        cve=cve_id, cwe="CWE-1035",
                    ))

        # X-Powered-By
        powered = hdrs.get("X-Powered-By", hdrs.get("x-powered-by", ""))
        if powered:
            self._add(finding(
                category="Information Disclosure",
                severity="LOW",
                title="X-Powered-By Header Exposed",
                description=f"X-Powered-By: {powered}",
                recommendation="Remove X-Powered-By header from all responses.",
                cwe="CWE-200",
            ))
            matches2 = VulnDB.match_software(powered)
            for soft, ver, cves in matches2:
                for cve_id in cves:
                    detail = VulnDB.lookup_cve(cve_id)
                    self._add(finding(
                        category="Known CVE",
                        severity=detail["severity"],
                        title=f"{soft} {ver} — {cve_id}",
                        description=detail["desc"],
                        recommendation=f"Update {soft} to the latest stable version.",
                        cve=cve_id, cwe="CWE-1035",
                    ))

        # Cookie flags
        cookies = r.headers.get("Set-Cookie", "")
        if cookies:
            if "Secure" not in cookies:
                self._add(finding(
                    category="Cookie Security",
                    severity="MEDIUM",
                    title="Cookie Missing Secure Flag",
                    description="Session cookie transmitted without Secure flag.",
                    recommendation="Set the Secure flag on all cookies.",
                    cwe="CWE-614",
                ))
            if "HttpOnly" not in cookies:
                self._add(finding(
                    category="Cookie Security",
                    severity="MEDIUM",
                    title="Cookie Missing HttpOnly Flag",
                    description="Cookie is accessible via JavaScript.",
                    recommendation="Set the HttpOnly flag on session cookies.",
                    cwe="CWE-1004",
                ))
            if "SameSite" not in cookies:
                self._add(finding(
                    category="Cookie Security",
                    severity="LOW",
                    title="Cookie Missing SameSite Attribute",
                    description="Cookie has no SameSite attribute — CSRF risk.",
                    recommendation="Add SameSite=Strict or SameSite=Lax.",
                    cwe="CWE-352",
                ))

        # CORS check
        r2 = None
        try:
            r2 = requests.get(
                url, timeout=TIMEOUT, verify=False,
                headers={"User-Agent": UA,
                         "Origin": "https://evil-attacker.com"},
            )
        except Exception:
            pass
        if r2:
            acao = r2.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                self._add(finding(
                    category="CORS",
                    severity="MEDIUM",
                    title="Overly Permissive CORS Policy",
                    description="Access-Control-Allow-Origin: * — any origin may read responses.",
                    recommendation="Restrict CORS to specific trusted origins.",
                    cwe="CWE-942",
                ))
            elif acao and "evil-attacker.com" in acao:
                self._add(finding(
                    category="CORS",
                    severity="HIGH",
                    title="CORS Origin Reflection Vulnerability",
                    description="Server reflects arbitrary Origin header.",
                    recommendation="Validate Origin against a strict allowlist.",
                    cwe="CWE-942",
                ))

    # ── Module 2: SSL/TLS ─────────────────────────────────
    def scan_ssl(self, url: str, progress, task):
        parsed = urllib.parse.urlparse(url)
        host   = parsed.hostname or parsed.netloc
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            self._add(finding(
                category="SSL/TLS",
                severity="HIGH",
                title="Site Not Using HTTPS",
                description="Target is served over plain HTTP with no encryption.",
                recommendation="Obtain a TLS certificate and redirect all traffic to HTTPS.",
                cwe="CWE-319",
            ))
            progress.advance(task, 4)
            return

        # ── Check redirect HTTP→HTTPS
        http_url = url.replace("https://", "http://", 1)
        r_http = None
        try:
            r_http = requests.get(
                http_url, timeout=TIMEOUT, verify=False,
                allow_redirects=False, headers={"User-Agent": UA}
            )
        except Exception:
            pass
        if r_http and r_http.status_code not in (301, 302, 308):
            self._add(finding(
                category="SSL/TLS",
                severity="MEDIUM",
                title="HTTP Does Not Redirect to HTTPS",
                description="Plain HTTP access is allowed without enforced redirect.",
                recommendation="Add a 301 redirect from HTTP to HTTPS.",
                cwe="CWE-319",
            ))
        progress.advance(task)

        # ── Raw socket SSL analysis
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    proto  = tls.version()
                    cipher = tls.cipher()
                    cert   = tls.getpeercert()

                    # Protocol check
                    if proto in VulnDB.WEAK_PROTOS:
                        self._add(finding(
                            category="SSL/TLS",
                            severity="HIGH",
                            title=f"Outdated Protocol: {proto}",
                            description=f"Server negotiated {proto} which is deprecated.",
                            recommendation="Disable TLS 1.0/1.1; enable TLS 1.2 and TLS 1.3 only.",
                            cwe="CWE-327",
                            cve="CVE-2011-3389" if "TLSv1" in (proto or "") else "",
                        ))
                    progress.advance(task)

                    # Cipher check
                    if cipher:
                        cname = cipher[0]
                        if any(w in cname.upper() for w in VulnDB.WEAK_CIPHERS):
                            self._add(finding(
                                category="SSL/TLS",
                                severity="HIGH",
                                title=f"Weak Cipher Suite: {cname}",
                                description="Server negotiated a cipher considered cryptographically weak.",
                                recommendation="Configure only AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
                                cwe="CWE-327",
                            ))
                    progress.advance(task)

                    # Cert expiry
                    if cert:
                        exp_str = cert.get("notAfter", "")
                        if exp_str:
                            try:
                                exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                                days = (exp - datetime.utcnow()).days
                                if days < 0:
                                    self._add(finding(
                                        category="SSL/TLS",
                                        severity="CRITICAL",
                                        title="SSL Certificate Expired",
                                        description=f"Certificate expired {abs(days)} day(s) ago.",
                                        recommendation="Renew the certificate immediately.",
                                        cwe="CWE-298",
                                    ))
                                elif days < 30:
                                    self._add(finding(
                                        category="SSL/TLS",
                                        severity="MEDIUM",
                                        title=f"Certificate Expiring in {days} Days",
                                        description="Certificate will expire soon.",
                                        recommendation="Renew the certificate before expiry.",
                                        cwe="CWE-298",
                                    ))
                            except ValueError:
                                pass
                    progress.advance(task)

        except Exception as e:
            self._add(finding(
                category="SSL/TLS",
                severity="INFO",
                title="SSL Analysis Incomplete",
                description=str(e),
                recommendation="Verify TLS is correctly configured.",
            ))
            progress.advance(task, 3)

    # ── Module 3: Sensitive File/Path Exposure ────────────
    def scan_paths(self, url: str, progress, task):
        base = url.rstrip("/")

        def probe(path, sev, desc):
            r = self._head(base, path)
            if r and r.status_code in (200, 403):
                # 403 still confirms existence for critical paths
                actual_sev = sev if r.status_code == 200 else (
                    "MEDIUM" if sev == "CRITICAL" else "LOW"
                )
                self._add(finding(
                    category="Exposed Resource",
                    severity=actual_sev,
                    title=f"Accessible: {path}",
                    description=desc,
                    recommendation=f"Deny public access to {path} via server config.",
                    cwe="CWE-200",
                    url=base + path,
                ))
            progress.advance(task)

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(probe, p, s, d) for p, s, d in VulnDB.SENSITIVE_PATHS]
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception:
                    pass

        # Directory listing check
        for dir_path in ["/images/", "/uploads/", "/backup/", "/files/", "/static/"]:
            r = self._get(base, dir_path)
            if r and r.status_code == 200:
                body = r.text[:2000]
                if "Index of" in body or "Directory listing" in body or "<title>Index" in body:
                    self._add(finding(
                        category="Misconfiguration",
                        severity="MEDIUM",
                        title=f"Directory Listing: {dir_path}",
                        description="Web server exposes full directory contents.",
                        recommendation="Set Options -Indexes in Apache or autoindex off in nginx.",
                        cwe="CWE-548",
                        url=base + dir_path,
                    ))

    # ── Module 4: Technology & CMS Fingerprint ────────────
    def scan_fingerprint(self, url: str, progress, task):
        r = self._get(url)
        if not r:
            progress.advance(task, 6)
            return

        body    = r.text[:15000]
        headers = dict(r.headers)
        all_src = body + " " + str(headers)

        signatures = {
            "WordPress":   (r"wp-content|wp-includes|/wp-json/",   "wp-login.php"),
            "Joomla":      (r"joomla|com_content|/components/com_", "administrator"),
            "Drupal":      (r"drupal|sites/default|drupal\.js",     "user/login"),
            "Laravel":     (r"laravel|XSRF-TOKEN",                  None),
            "Django":      (r"csrfmiddlewaretoken|django",          None),
            "Ruby on Rails":(r'<meta name="csrf" |data-turbo',      None),
            "ASP.NET":     (r"__VIEWSTATE|asp\.net|\.aspx",          None),
            "Next.js":     (r"__NEXT_DATA__|/_next/",               None),
        }

        for tech, (pattern, admin_path) in signatures.items():
            if re.search(pattern, all_src, re.I):
                # Look for version
                ver_m = re.search(
                    rf"{re.escape(tech.replace('.', ''))}[\"'\s/]+v?([\d\.]+)",
                    all_src, re.I
                )
                ver = ver_m.group(1) if ver_m else "unknown"

                self._add(finding(
                    category="Tech Fingerprint",
                    severity="INFO",
                    title=f"Technology Detected: {tech}",
                    description=f"Version detected: {ver}" if ver != "unknown"
                                else "CMS/framework identified from page content.",
                    recommendation="Hide CMS version info and keep software updated.",
                    cwe="CWE-200",
                ))

                # CVE correlation if version found
                if ver != "unknown":
                    clean = tech.rstrip("\\").replace("\\.", "")
                    ver_cves = VulnDB.CVE.get(clean, {})
                    for prefix, cves in ver_cves.items():
                        if ver.startswith(prefix):
                            for cve_id in cves:
                                detail = VulnDB.lookup_cve(cve_id)
                                self._add(finding(
                                    category="Known CVE",
                                    severity=detail["severity"],
                                    title=f"{tech} {ver} — {cve_id}",
                                    description=detail["desc"],
                                    recommendation=f"Update {tech} immediately.",
                                    cve=cve_id, cwe="CWE-1035",
                                ))

                # Probe admin if available
                if admin_path:
                    ra = self._head(url, admin_path)
                    if ra and ra.status_code == 200:
                        self._add(finding(
                            category="Misconfiguration",
                            severity="MEDIUM",
                            title=f"{tech} Admin Panel Exposed",
                            description=f"Login panel reachable at /{admin_path}",
                            recommendation="Restrict access by IP or move behind VPN.",
                            cwe="CWE-425",
                            url=url.rstrip("/") + "/" + admin_path,
                        ))
            progress.advance(task)

        # Error page info leak
        r_err = self._get(url, "/this_page_does_not_exist_xyz123")
        if r_err:
            body_err = r_err.text[:3000]
            patterns = [
                (r"Warning:.*on line \d+",     "PHP error message exposed"),
                (r"Fatal error:",              "PHP fatal error exposed"),
                (r"Traceback \(most recent",   "Python traceback exposed"),
                (r"SQLException|ORA-\d{5}",   "Database error exposed"),
                (r"Microsoft OLE DB|ODBC",     "ASP/SQL Server error exposed"),
                (r"at [A-Za-z\.]+\(:[0-9]+\)","Java stack trace exposed"),
            ]
            for pat, msg in patterns:
                if re.search(pat, body_err, re.I):
                    self._add(finding(
                        category="Information Disclosure",
                        severity="MEDIUM",
                        title="Verbose Error Messages",
                        description=msg,
                        recommendation="Configure custom error pages; hide stack traces in production.",
                        cwe="CWE-209",
                    ))
                    break

    # ── Module 5: Input / Injection surface ───────────────
    def scan_injection(self, url: str, progress, task):
        """Light non-destructive injection surface detection."""

        parsed  = urllib.parse.urlparse(url)
        params  = urllib.parse.parse_qs(parsed.query)
        base    = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # If no query params, probe common param names
        test_params = list(params.keys()) if params else ["q", "id", "page", "search", "file"]

        sqli_payloads = ["'", "\"", "1 AND 1=1", "1'--"]
        xss_payloads  = ["<svg/onload=1>", "'\"<>"]
        traversal     = ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]

        sqli_errors = [
            "you have an error in your sql", "syntax error",
            "unclosed quotation", "quoted string not properly terminated",
            "pg_query", "mysql_fetch", "sqlite3", "ora-0",
        ]

        reflected_found = False
        sqli_found      = False
        traversal_found = False
        redirect_found  = False

        marker = "xssProbe83471"

        for param in test_params[:5]:  # cap to avoid hammering
            # XSS reflection test
            test_url = f"{base}?{param}={marker}"
            r = self._get(test_url)
            if r and marker in r.text and reflected_found is False:
                reflected_found = True
                self._add(finding(
                    category="Potential XSS",
                    severity="MEDIUM",
                    title=f"Reflected Input in Param: {param}",
                    description="User input is reflected in the response without encoding.",
                    recommendation="HTML-encode all user-supplied output. Implement a strict CSP.",
                    cwe="CWE-79",
                    url=test_url,
                ))
            progress.advance(task)

            # SQLi error-based detection
            for payload in sqli_payloads[:2]:
                test_url2 = f"{base}?{param}={urllib.parse.quote(payload)}"
                r2 = self._get(test_url2)
                if r2 and not sqli_found:
                    body2 = r2.text.lower()
                    if any(e in body2 for e in sqli_errors):
                        sqli_found = True
                        self._add(finding(
                            category="Potential SQLi",
                            severity="HIGH",
                            title=f"SQL Error Triggered via Param: {param}",
                            description="SQL syntax or DB error returned on injected input.",
                            recommendation="Use parameterised queries / prepared statements.",
                            cwe="CWE-89",
                            url=test_url2,
                        ))
            progress.advance(task)

            # Path traversal
            for payload in traversal:
                test_url3 = f"{base}?{param}={urllib.parse.quote(payload)}"
                r3 = self._get(test_url3)
                if r3 and not traversal_found:
                    body3 = r3.text
                    if "root:x:0" in body3 or "[extensions]" in body3:
                        traversal_found = True
                        self._add(finding(
                            category="Path Traversal",
                            severity="CRITICAL",
                            title=f"Path Traversal via Param: {param}",
                            description="Server returned sensitive file content on traversal payload.",
                            recommendation="Sanitize file paths; use allow-list for file access.",
                            cwe="CWE-22",
                            url=test_url3,
                        ))
            progress.advance(task)

        # Open redirect probe
        redirect_payloads = [
            f"?next=https://evil-attacker.com",
            f"?url=https://evil-attacker.com",
            f"?redirect=https://evil-attacker.com",
        ]
        for rp in redirect_payloads:
            r4 = self._get(base + rp, allow_redirects=False)
            if r4 and r4.status_code in (301, 302, 303, 307, 308):
                loc = r4.headers.get("Location", "")
                if "evil-attacker.com" in loc:
                    self._add(finding(
                        category="Open Redirect",
                        severity="MEDIUM",
                        title="Open Redirect Vulnerability",
                        description=f"Server redirects to attacker-controlled URL via {rp[:40]}",
                        recommendation="Validate redirect targets against an allowlist.",
                        cwe="CWE-601",
                        url=base + rp,
                    ))
                    redirect_found = True
                    break
        progress.advance(task)

    # ── Risk Score ────────────────────────────────────────
    def risk_score(self) -> int:
        W = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 6, "LOW": 2, "INFO": 0}
        return min(100, sum(W.get(f["severity"], 0) for f in self.findings))

    def summary(self) -> Dict:
        counts = {s: 0 for s in SEV_COLOR}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return {"total": len(self.findings), "by_severity": counts,
                "risk_score": self.risk_score()}

    # ── Full scan orchestrator ────────────────────────────
    def run(self, url: str, modules: Dict[str, bool], progress, tasks: Dict):
        if modules.get("headers"):
            self.scan_headers(url, progress, tasks["headers"])
        if modules.get("ssl"):
            self.scan_ssl(url, progress, tasks["ssl"])
        if modules.get("paths"):
            self.scan_paths(url, progress, tasks["paths"])
        if modules.get("fingerprint"):
            self.scan_fingerprint(url, progress, tasks["fingerprint"])
        if modules.get("injection"):
            self.scan_injection(url, progress, tasks["injection"])


# ══════════════════════════════════════════════════════════
#  REPORT / EXPORT
# ══════════════════════════════════════════════════════════
class Reporter:
    @staticmethod
    def to_json(results: Dict, target: str) -> Path:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = re.sub(r"[^a-zA-Z0-9]", "_", target)[:40]
        path = SAVE_DIR / f"scan_{name}_{ts}.json"
        path.write_text(json.dumps(results, indent=2))
        return path

    @staticmethod
    def to_html(results: Dict) -> Path:
        COLORS = {
            "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",   "LOW": "#17a2b8", "INFO": "#adb5bd"
        }
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = re.sub(r"[^a-zA-Z0-9]", "_", results["target"]["host"])[:40]
        path = SAVE_DIR / f"report_{name}_{ts}.html"

        cards = ""
        for f in results["findings"]:
            col = COLORS.get(f["severity"], "#adb5bd")
            cve = f'<span style="background:#6610f2;color:white;padding:2px 8px;border-radius:9px;font-size:0.78em">🔗 {f["cve"]}</span>' if f.get("cve") else ""
            cwe = f'<span style="background:#e83e8c;color:white;padding:2px 8px;border-radius:9px;font-size:0.78em">{f["cwe"]}</span>' if f.get("cwe") else ""
            url_badge = f'<br><a href="{f["url"]}" style="font-size:0.8em;color:#888">{f["url"]}</a>' if f.get("url") else ""
            cards += f"""
<div style="border-left:5px solid {col};background:#fff;border-radius:8px;
            box-shadow:0 2px 8px #0001;margin-bottom:18px;overflow:hidden">
  <div style="background:#f8f9fa;padding:14px 20px;display:flex;
              justify-content:space-between;align-items:center">
    <strong style="color:#2a5298">{escape(f['title'])}</strong>
    <span style="background:{col};color:white;padding:4px 12px;
                 border-radius:20px;font-size:0.82em;font-weight:700">{f['severity']}</span>
  </div>
  <div style="padding:16px 20px">
    <p style="color:#555;margin-bottom:8px">
      <span style="color:#888;font-size:0.85em">{f['category']}</span><br>
      {escape(f['description'])}</p>
    <p style="color:#333"><strong>Recommendation:</strong> {escape(f['recommendation'])}</p>
    <div style="margin-top:10px">{cve} {cwe} {url_badge}</div>
  </div>
</div>"""

        s     = results["summary"]
        score = s["risk_score"]
        s_col = "#dc3545" if score >= 70 else "#ffc107" if score >= 40 else "#28a745"

        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Security Report – {results['target']['host']}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{{box-sizing:border-box}}body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',
sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;padding:20px}}
.c{{max-width:900px;margin:auto;background:#f1f3f5;border-radius:14px;overflow:hidden;
box-shadow:0 20px 60px #0005}}.hdr{{background:linear-gradient(135deg,#1e3c72,#2a5298);
color:white;padding:36px;text-align:center}}.body{{padding:30px}}</style></head><body>
<div class="c">
<div class="hdr">
  <h1 style="margin:0 0 8px;font-size:1.9em">🛡️ Security Scan Report</h1>
  <div style="opacity:.85">{results['target']['url']}</div>
  <div style="opacity:.7;font-size:.85em">{results['target']['scan_time']}</div>
</div>
<div class="body">
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px">
    <div style="background:white;border-radius:10px;padding:20px;text-align:center;box-shadow:0 2px 8px #0001">
      <div style="color:#888;font-size:.8em;text-transform:uppercase">Risk Score</div>
      <div style="font-size:2.8em;font-weight:900;color:{s_col}">{score}</div>
    </div>
    <div style="background:white;border-radius:10px;padding:20px;text-align:center;box-shadow:0 2px 8px #0001">
      <div style="color:#888;font-size:.8em;text-transform:uppercase">Total Issues</div>
      <div style="font-size:2.8em;font-weight:900;color:#2a5298">{s['total']}</div>
    </div>
    <div style="background:white;border-radius:10px;padding:20px;box-shadow:0 2px 8px #0001">
      <div style="color:#888;font-size:.8em;text-transform:uppercase;margin-bottom:8px">Severity</div>
      {''.join(f'<div style="color:{COLORS[k]};font-weight:700">{SEV_ICON[k]} {k}: {s["by_severity"].get(k,0)}</div>' for k in COLORS)}
    </div>
  </div>
  <h2 style="color:#2a5298;border-bottom:3px solid #667eea;padding-bottom:8px">Findings</h2>
  {cards or '<p style="color:#888">No issues detected.</p>'}
</div></div></body></html>"""

        path.write_text(html)
        return path

    @staticmethod
    def to_txt(results: Dict) -> Path:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = re.sub(r"[^a-zA-Z0-9]", "_", results["target"]["host"])[:40]
        path = SAVE_DIR / f"report_{name}_{ts}.txt"
        lines = [
            "=" * 64,
            "  WEBSCAN PRO - SECURITY REPORT",
            "=" * 64,
            f"  Target : {results['target']['url']}",
            f"  Date   : {results['target']['scan_time']}",
            f"  Score  : {results['summary']['risk_score']}/100",
            f"  Issues : {results['summary']['total']}",
            "=" * 64, "",
        ]
        for i, f in enumerate(results["findings"], 1):
            lines += [
                f"[{i}] [{f['severity']}] {f['title']}",
                f"    Category : {f['category']}",
                f"    Details  : {f['description']}",
                f"    Fix      : {f['recommendation']}",
            ]
            if f.get("cve"):
                lines.append(f"    CVE      : {f['cve']}")
            if f.get("cwe"):
                lines.append(f"    CWE      : {f['cwe']}")
            if f.get("url"):
                lines.append(f"    URL      : {f['url']}")
            lines.append("")
        path.write_text("\n".join(lines))
        return path


# ══════════════════════════════════════════════════════════
#  TERMINAL UI
# ══════════════════════════════════════════════════════════
def banner():
    console.print()
    art = Text(justify="center")
    art.append("╔═══════════════════════════════════════╗\n", style="bold blue")
    art.append("║  ", style="bold blue")
    art.append("⚡ WebScan Pro", style="bold cyan")
    art.append("  –  Termux Edition v2.0  ", style="bold white")
    art.append("  ║\n", style="bold blue")
    art.append("║     Web Vulnerability & Misconfig     ║\n", style="bold blue")
    art.append("╚═══════════════════════════════════════╝", style="bold blue")
    console.print(Align.center(art))
    console.print(Align.center(Text("for authorized security testing only",
                                    style="dim italic")))
    console.print()


def main_menu() -> str:
    table = Table(box=box.ROUNDED, show_header=False, border_style="blue",
                  width=min(console.width, 44))
    table.add_column("opt",   style="bold cyan",  width=5)
    table.add_column("label", style="white")
    table.add_row("1", "🔍  Full Scan")
    table.add_row("2", "⚡  Quick Scan  (headers + SSL)")
    table.add_row("3", "💾  View Saved Reports")
    table.add_row("4", "ℹ️   About")
    table.add_row("5", "🚪  Exit")
    console.print(Align.center(table))
    return Prompt.ask("\n[cyan]›[/cyan] Choose", choices=["1","2","3","4","5"])


def pick_modules(quick: bool = False) -> Dict[str, bool]:
    if quick:
        return {"headers": True, "ssl": True,
                "paths": False, "fingerprint": False, "injection": False}

    console.print(Panel("[bold]Select Scan Modules[/bold]\n[dim]Press Enter to keep default[/dim]",
                        border_style="blue"))
    return {
        "headers":     Confirm.ask("  [cyan]Security Headers[/cyan]",     default=True),
        "ssl":         Confirm.ask("  [cyan]SSL/TLS Analysis[/cyan]",      default=True),
        "paths":       Confirm.ask("  [cyan]Sensitive Files & Paths[/cyan]", default=True),
        "fingerprint": Confirm.ask("  [cyan]Technology Fingerprint[/cyan]", default=True),
        "injection":   Confirm.ask("  [cyan]Injection Surface[/cyan]",     default=True),
    }


def build_tasks(modules: Dict[str, bool], progress: Progress) -> Dict:
    tasks = {}
    totals = {
        "headers":     len(VulnDB.SECURITY_HEADERS) + 2,
        "ssl":         4,
        "paths":       len(VulnDB.SENSITIVE_PATHS) + 1,
        "fingerprint": 8,
        "injection":   16,
    }
    labels = {
        "headers":     "Security Headers",
        "ssl":         "SSL / TLS",
        "paths":       "Sensitive Paths",
        "fingerprint": "Fingerprinting",
        "injection":   "Injection Tests",
    }
    for key, enabled in modules.items():
        if enabled:
            tasks[key] = progress.add_task(
                f"[cyan]{labels[key]}[/cyan]",
                total=totals[key]
            )
    return tasks


def display_results(scanner: Scanner):
    findings = scanner.findings
    summ     = scanner.summary()
    score    = summ["risk_score"]

    score_color = "bold red" if score >= 70 else "bold yellow" if score >= 40 else "bold green"

    # ── Summary panel
    grid = Table.grid(expand=True)
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")

    score_t = Text(str(score), style=score_color)
    score_t.append("/100", style="dim")

    sev_t = Text()
    for s, icon in SEV_ICON.items():
        n = summ["by_severity"].get(s, 0)
        sev_t.append(f"{icon} {s}: {n}\n", style=SEV_COLOR[s])

    grid.add_row(
        Panel(Align.center(score_t), title="[bold]Risk Score[/bold]",
              border_style="red" if score >= 70 else "yellow" if score >= 40 else "green"),
        Panel(Align.center(Text(str(summ["total"]), style="bold cyan")),
              title="[bold]Total Issues[/bold]", border_style="cyan"),
        Panel(sev_t, title="[bold]By Severity[/bold]", border_style="blue"),
    )
    console.print(grid)
    console.print()

    if not findings:
        console.print(Panel("[green]✓ No issues detected.[/green]", border_style="green"))
        return

    # ── Findings table
    tbl = Table(
        title="Findings",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold white on blue",
        show_lines=True,
        width=min(console.width, 110),
    )
    tbl.add_column("#",          width=3,  style="dim")
    tbl.add_column("Severity",   width=10)
    tbl.add_column("Category",   width=18, style="cyan")
    tbl.add_column("Title",      min_width=22)
    tbl.add_column("CVE/CWE",    width=16, style="dim")

    # Sort by severity
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for i, f in enumerate(sorted(findings, key=lambda x: order.get(x["severity"], 5)), 1):
        sev_text = Text(f"{SEV_ICON[f['severity']]} {f['severity']}", style=SEV_COLOR[f["severity"]])
        ref = f.get("cve") or f.get("cwe") or ""
        tbl.add_row(str(i), sev_text, f["category"], f["title"], ref)

    console.print(tbl)
    console.print()

    # ── Detailed findings on request
    if findings and Confirm.ask("[cyan]Show detailed findings?[/cyan]", default=True):
        for i, f in enumerate(sorted(findings, key=lambda x: order.get(x["severity"], 5)), 1):
            col = SEV_COLOR[f["severity"]]
            inner = Text()
            inner.append(f"Category    : ", style="dim")
            inner.append(f"{f['category']}\n")
            inner.append("Description : ", style="dim")
            inner.append(f"{f['description']}\n")
            inner.append("Fix         : ", style="dim")
            inner.append(f"{f['recommendation']}", style="green")
            if f.get("cve"):
                inner.append(f"\nCVE         : ", style="dim")
                inner.append(f['cve'], style="bold magenta")
            if f.get("cwe"):
                inner.append(f"\nCWE         : ", style="dim")
                inner.append(f['cwe'], style="magenta")
            if f.get("url"):
                inner.append(f"\nURL         : ", style="dim")
                inner.append(f['url'], style="underline blue")

            console.print(Panel(
                inner,
                title=f"[{col}]{SEV_ICON[f['severity']]} [{f['severity']}] {escape(f['title'])}[/{col}]",
                border_style=col.split()[-1],
            ))


def save_report(results: Dict):
    console.print(Rule("[bold]Save Report[/bold]", style="blue"))
    choices = {"1": "HTML", "2": "JSON", "3": "TXT", "4": "All three", "5": "Skip"}
    tbl = Table(box=box.SIMPLE, show_header=False)
    tbl.add_column(style="bold cyan", width=3)
    tbl.add_column()
    for k, v in choices.items():
        tbl.add_row(k, v)
    console.print(tbl)

    choice = Prompt.ask("[cyan]›[/cyan] Format", choices=list(choices.keys()), default="1")
    saved  = []

    if choice in ("1", "4"):
        p = Reporter.to_html(results)
        saved.append(("HTML", p))
    if choice in ("2", "4"):
        p = Reporter.to_json(results, results["target"]["host"])
        saved.append(("JSON", p))
    if choice in ("3", "4"):
        p = Reporter.to_txt(results)
        saved.append(("TXT", p))

    for fmt, path in saved:
        console.print(f"  [green]✓[/green] {fmt} saved → [bold]{path}[/bold]")


def list_reports():
    reports = sorted(SAVE_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        console.print(Panel("[dim]No reports saved yet.[/dim]", border_style="blue"))
        return
    tbl = Table(title=f"Reports in {SAVE_DIR}", box=box.ROUNDED,
                border_style="blue", header_style="bold")
    tbl.add_column("#", width=4, style="dim")
    tbl.add_column("Filename")
    tbl.add_column("Size",     width=10, justify="right")
    tbl.add_column("Modified", width=22)
    for i, p in enumerate(reports[:20], 1):
        sz  = p.stat().st_size
        mod = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        tbl.add_row(str(i), p.name,
                    f"{sz/1024:.1f} KB" if sz > 1024 else f"{sz} B", mod)
    console.print(tbl)
    console.print(f"\n[dim]Reports folder: {SAVE_DIR}[/dim]")


def about():
    txt = (
        "[bold cyan]WebScan Pro[/bold cyan] [bold]v2.0 – Termux Edition[/bold]\n\n"
        "A professional web vulnerability scanner for security researchers.\n\n"
        "[bold]Modules:[/bold]\n"
        "  • Security Headers  – HSTS, CSP, X-Frame-Options, CORS …\n"
        "  • SSL/TLS           – Protocol, cipher & cert analysis\n"
        "  • Sensitive Paths   – Exposed config, git, backups …\n"
        "  • Tech Fingerprint  – CMS, framework & CVE correlation\n"
        "  • Injection Tests   – XSS reflection, SQLi error, traversal …\n\n"
        "[bold]CVE Database:[/bold] Apache, nginx, OpenSSL, PHP, WordPress,\n"
        "  Drupal, Joomla, IIS, Tomcat and more.\n\n"
        "[dim]Reports saved to: ~/scanner_reports/[/dim]\n\n"
        "[bold red]⚠  Authorised use only.[/bold red]"
    )
    console.print(Panel(txt, title="About", border_style="blue"))


# ══════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════
def run_scan(url: str, modules: Dict[str, bool]) -> Dict:
    scanner = Scanner()

    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        tasks = build_tasks(modules, progress)
        scanner.run(url, modules, progress, tasks)

    parsed = urllib.parse.urlparse(url)
    return {
        "target": {
            "url":       url,
            "host":      parsed.netloc,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "findings": scanner.findings,
        "summary":  scanner.summary(),
    }


def main():
    banner()

    while True:
        choice = main_menu()

        if choice == "5":
            console.print("\n[dim]Goodbye.[/dim]\n")
            break

        elif choice == "4":
            about()

        elif choice == "3":
            list_reports()

        elif choice in ("1", "2"):
            quick = (choice == "2")

            url = Prompt.ask("\n[cyan]Target URL[/cyan]",
                             default="https://example.com").strip()
            if not url:
                continue

            modules = pick_modules(quick)

            if not any(modules.values()):
                console.print("[red]No modules selected.[/red]")
                continue

            console.print(Rule(f"[bold]Scanning[/bold] [cyan]{url}[/cyan]", style="blue"))

            try:
                results = run_scan(url, modules)
            except KeyboardInterrupt:
                console.print("\n[yellow]Scan interrupted.[/yellow]")
                continue
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                continue

            console.print(Rule("[bold]Results[/bold]", style="blue"))
            display_results(Scanner() if not results["findings"] else _mk_scanner(results))
            save_report(results)

        console.print()


def _mk_scanner(results: Dict) -> Scanner:
    """Reconstruct a Scanner with pre-populated findings for display."""
    s = Scanner()
    s.findings = results["findings"]
    return s


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Aborted.[/dim]")