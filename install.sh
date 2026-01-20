#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]
  then echo -e "${RED}[!] Please run as root (sudo ./install.sh)${NC}"
  exit
fi

echo -e "${GREEN}[+] Installing Kernel-Eye...${NC}"

mkdir -p /opt/kernel-eye
cp kernel_eye.py /opt/kernel-eye/
cp eye.jpg /opt/kernel-eye/ 2>/dev/null

cp kernel-eye.service /etc/systemd/system/

echo -e "${GREEN}[+] Files copied to /opt/kernel-eye${NC}"
echo -e "${RED}[!] IMPORTANT: Please edit /etc/systemd/system/kernel-eye.service and add your DISCORD WEBHOOK URL!${NC}"
echo -e "${GREEN}[+] Then run: sudo systemctl daemon-reload && sudo systemctl start kernel-eye${NC}"