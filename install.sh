#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./install.sh)${NC}"
  exit
fi

echo -e "${GREEN}[+] Installing Kernel-Eye Security Agent...${NC}"
echo -e "[*] Copying binary to /usr/local/bin..."
cp kernel_eye.py /usr/local/bin/kernel_eye.py
chmod +x /usr/local/bin/kernel_eye.py
echo -e "[*] Configuring secure logging..."
touch /var/log/kernel-eye.json
chmod 600 /var/log/kernel-eye.json
echo -e "[*] Installing systemd service..."
cp kernel-eye.service /etc/systemd/system/
systemctl daemon-reload
echo -e "[*] Starting Kernel-Eye..."
systemctl enable kernel-eye
systemctl restart kernel-eye

if systemctl is-active --quiet kernel-eye; then
    echo -e "${GREEN}[SUCCESS] Kernel-Eye is running and protected!${NC}"
    echo -e "Logs: tail -f /var/log/kernel-eye.json"
else
    echo -e "${RED}[ERROR] Failed to start service. Check logs: journalctl -u kernel-eye${NC}"
fi