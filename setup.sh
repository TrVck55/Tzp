#!/data/data/com.termux/files/usr/bin/bash
# WebScan Pro – Termux Setup Script
# Run once: bash setup_termux.sh

set -e

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  WebScan Pro  –  Termux Setup         ║"
echo "╚═══════════════════════════════════════╝"
echo ""

# ── Termux packages
echo "[*] Updating packages..."
pkg update -y -q

echo "[*] Installing Python..."
pkg install -y python python-pip openssl-tool -q

# ── Python dependencies
echo "[*] Installing Python dependencies..."
pip install rich requests --quiet --break-system-packages 2>/dev/null \
  || pip install rich requests --quiet

# ── Storage permission (optional – for sharing reports)
echo ""
echo "[?] Allow storage access for sharing reports? (y/n)"
read -r STORAGE
if [[ "$STORAGE" =~ ^[Yy]$ ]]; then
    termux-setup-storage 2>/dev/null && echo "[+] Storage access granted." \
        || echo "[-] Skipped (termux-setup-storage not found)."
fi

# ── Make scanner executable
chmod +x vuln_scanner.py 2>/dev/null || true

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  Setup complete!                       ║"
echo "║                                       ║"
echo "║  Run:  python3 vuln_scanner.py        ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "  Reports saved to: ~/scanner_reports/"
echo ""