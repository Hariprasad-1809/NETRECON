#!/bin/bash
# ============================================================
#  NetRecon Pro — Setup Script for Kali Linux
#  Run this once to install dependencies
# ============================================================

echo ""
echo "========================================"
echo "  NetRecon Pro — Kali Linux Setup"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "⚠  Please run as root: sudo bash setup.sh"
  exit 1
fi

echo "[*] Updating package list..."
apt-get update -qq

echo "[*] Installing nmap (should already be on Kali)..."
apt-get install -y nmap

echo "[*] Installing tshark (Wireshark CLI)..."
# Non-interactive install, allow non-root capture
DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
# Allow non-root users to capture (optional)
# dpkg-reconfigure wireshark-common

echo "[*] Installing Python Flask..."
pip3 install flask --break-system-packages 2>/dev/null || pip3 install flask

echo ""
echo "========================================"
echo "  ✓ Setup complete!"
echo ""
echo "  To start the dashboard:"
echo "  sudo python3 app.py"
echo ""
echo "  Then open Firefox:"
echo "  http://localhost:5000"
echo "========================================"
echo ""
