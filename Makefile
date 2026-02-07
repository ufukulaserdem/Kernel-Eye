# Kernel-Eye Makefile
# Standard Linux Installation Protocol

INSTALL_DIR = /usr/local/bin
SERVICE_DIR = /etc/systemd/system
LOG_FILE = /var/log/kernel-eye.json

.PHONY: install uninstall clean status

install:
	@echo "[+] Installing Kernel-Eye..."
	@# 1. Install Dependencies (Detect OS)
	@if [ -f /etc/debian_version ]; then \
		apt-get update && apt-get install -y bpfcc-tools python3-bpfcc python3-pip; \
	elif [ -f /etc/redhat-release ]; then \
		dnf install -y bcc-tools python3-bcc; \
	else \
		echo "[-] Unsupported OS. Please install bcc-tools manually."; \
	fi
	
	@# 2. Copy Executable
	@cp kernel_eye.py $(INSTALL_DIR)/kernel-eye
	@chmod +x $(INSTALL_DIR)/kernel-eye
	@echo "[+] Binary installed to $(INSTALL_DIR)/kernel-eye"

	@# 3. Setup Logging
	@touch $(LOG_FILE)
	@chmod 600 $(LOG_FILE)

	@# 4. Install Service
	@cp kernel-eye.service $(SERVICE_DIR)/
	@systemctl daemon-reload
	@systemctl enable kernel-eye
	@systemctl start kernel-eye
	@echo "[✔] Kernel-Eye installed and started successfully!"

uninstall:
	@echo "[-] Uninstalling Kernel-Eye..."
	@systemctl stop kernel-eye || true
	@systemctl disable kernel-eye || true
	@rm -f $(SERVICE_DIR)/kernel-eye.service
	@rm -f $(INSTALL_DIR)/kernel-eye
	@systemctl daemon-reload
	@echo "[✔] Uninstallation complete."

status:
	@systemctl status kernel-eye