# 👁️ Kernel-Eye: eBPF-Based Linux Threat Detection

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-eBPF-red?style=for-the-badge)

**Kernel-Eye** is a stealthy, kernel-level Endpoint Detection and Response (EDR) agent designed to monitor system calls directly from the source. By leveraging **eBPF (Extended Berkeley Packet Filter)**, it hooks into the Linux kernel to detect malicious activities that user-space antivirus tools might miss.

## 🚀 Features

* **🕵️‍♂️ Process Monitoring:** Hooks into sys_enter_execve to detect suspicious commands, privilege escalation (Root), and shell spawning.
* **📁 File Integrity Monitoring (FIM):** Hooks into sys_enter_openat to detect unauthorized modifications to critical system files (/etc/, /bin/, .bashrc).
* **⚡ High Performance:** Uses in-kernel filtering (C) to drop benign noise (like zsh, git, node) before it reaches user space, ensuring minimal CPU overhead.
* **🔔 Real-Time Alerting:** Integrated with Discord Webhooks for instant security notifications.
* **🛡️ Anti-Evasion:** Detects threats even if the attacker renames binary files (e.g., renaming curl to txt_reader).

## 🛠️ Installation

1. Prerequisites:
Linux Kernel 4.15+ (Supports eBPF)
BCC (BPF Compiler Collection) tools installed.
Python 3.6+
Root privileges (required for kernel interaction).

# For Fedora/RHEL
sudo dnf install bcc-tools python3-bcc python3-requests

# For Ubuntu/Debian
sudo apt-get install bpfcc-tools python3-bpfcc python3-requests

2. Clone the Repo:

git clone ...
cd Kernel-Eye

3. Configuration:
Open kernel_eye.py and set your Discord Webhook URL:

WEBHOOK_URL = "DISCORD_WEBHOOK_HERE"

## 💻 Usage

Run the agent with root privileges:
```bash
sudo python3 kernel_eye.py
```
## 🛡️ Detection Logic (Examples)

| Alert Type | Trigger Condition | Severity |
| :--- | :--- | :--- |
| **ROOT** | Any process executed with UID 0 (via sudo/su) | 🟡 Medium |
| **CRITICAL** | Access to /etc/shadow or /etc/passwd | 🔴 High |
| **SHELL** | Spawning bash or sh (Potential Reverse Shell) | 🔴 High |
| **NETWORK** | Usage of curl, wget, nc (Data Exfiltration) | 🔵 Low/Info |
| **FILE_MOD** | Writing to /etc/* or .bashrc (Persistence) | 🟣 Critical |

## 🗺️ Roadmap

- [x] Process Execution Monitoring (execve)
- [x] File Integrity Monitoring (openat)
- [x] Discord Alerting & Rate Limiting
- [ ] **Next:** Network Socket Monitoring (connect)
- [ ] **Next:** Active Blocking (Kill process on detection)

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📜 License

MIT