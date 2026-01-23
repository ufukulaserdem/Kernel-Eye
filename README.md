# 👁️ Kernel-Eye: eBPF-Based Linux Threat Detection

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-eBPF-red?style=for-the-badge)

**Kernel-Eye** is a stealthy, kernel-level Endpoint Detection and Response (EDR) agent designed to monitor system calls directly from the source. By leveraging **eBPF (Extended Berkeley Packet Filter)**, it hooks into the Linux kernel to detect malicious activities that user-space antivirus tools might miss.

It functions as both an **IDS (Intrusion Detection System)** and an **IPS (Intrusion Prevention System)**, capable of automatically blocking threats in real-time.

## 📺 Demo in Action

> **Scenario:** An attacker tries to execute a reverse shell. Kernel-Eye detects the syscalls instantly, kills the process, and pushes a Discord alert.

[kernel_eye.webm](https://github.com/user-attachments/assets/40bf9b8d-ed08-4ac5-9c83-4aebcfba08c8)

## 🚀 Features

* **🚫 Active Blocking (IPS):** Automatically terminates (SIGKILL) malicious processes like reverse shells or unauthorized file modifications instantly.
* **🌐 Network Observability:** Hooks into `sys_enter_connect` to detect and report suspicious outbound connections (C2 traffic) to non-standard ports.
* **🕵️‍♂️ Process Monitoring:** Hooks into `sys_enter_execve` to detect suspicious commands, privilege escalation (Root), and shell spawning.
* **📁 File Integrity Monitoring (FIM):** Hooks into `sys_enter_openat` to detect unauthorized modifications to critical system files (`/etc/`, `/bin/`, `.bashrc`).
* **⚡ High Performance:** Uses in-kernel filtering (C) and BPF Ring Buffers to drop benign noise (like `zsh`, `git`, `node`) before it reaches user space, ensuring minimal CPU overhead.
* **🔔 Real-Time Alerting:** Integrated with Discord Webhooks for instant security notifications.

## 🛠️ Installation

### 1. Prerequisites
* Linux Kernel 4.15+ (Supports eBPF)
* BCC (BPF Compiler Collection) tools installed.
* Python 3.6+
* Root privileges.

### **For Fedora/RHEL**
```bash
sudo dnf install bcc-tools python3-bcc python3-requests
```
### **For Ubuntu/Debian**
```bash
sudo apt-get install bpfcc-tools python3-bpfcc python3-requests
```
## 2. Automatic Install (Recommended)

This will set up the systemd service and configure the environment.
```bash
git clone https://github.com/ufukulaserdem/Kernel-Eye.git
cd Kernel-Eye
chmod +x install.sh
sudo ./install.sh
```

## 3. Configuration

After installation, you MUST add your Discord Webhook URL to the service file:
```bash
sudo nano /etc/systemd/system/kernel-eye.service
# Edit the line: Environment="DISCORD_WEBHOOK_URL"
```
Then start the agent:
```bash
sudo systemctl daemon-reload
sudo systemctl start kernel-eye
sudo systemctl enable kernel-eye
```

## 🛡️ Detection Logic (Examples)
| Alert Type | Trigger Condition | Severity | Action |
| :--- | :--- | :--- | :--- |
| **C2_CONNECT** | Connection to known hacker ports (4444, 1337) | 🔴 Critical | **KILL** |
| **PERSISTENCE** | Modification of `.bashrc` or startup files | 🔴 Critical | **KILL** |
| **CRITICAL** | Access to `/etc/shadow` or `/etc/passwd` | 🔴 High | **KILL** |
| **ROOT** | Any process executed with UID 0 (via sudo/su) | 🟡 Medium | Log |
| **SHELL** | Spawning bash or sh (Potential Reverse Shell) | 🟠 High | Log |
| **NETWORK** | Usage of `curl`, `wget`, `nc` (Data Exfiltration) | 🔵 Low | Log |

## 🗺️ Roadmap

### ✅ Phase 1: Completed
- [x] Process Execution Monitoring (sys_execve)
- [x] File Integrity Monitoring (sys_openat)
- [x] Network Socket Monitoring (sys_connect)
- [x] Active Blocking (IPS Mode) - Kill switch implementation
- [x] Systemd Service & Automated Installer
- [x] Discord Alerting & Rate Limiting

### 🚧 Phase 2: Advanced Capabilities (In Progress)
- [ ] **Content Analysis (YARA):** Deep packet/file inspection to detect malware signatures.
- [ ] **Forensic Database:** Local SQLite database to store logs for auditing.
- [ ] **Heuristic Analysis:** Parent-Child process tree analysis (e.g., detecting if Word spawns PowerShell).
- [ ] **Self-Protection:** Preventing the agent itself from being killed by unauthorized users.
    
## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 👨‍💻 Author & Contact
**Ufuk Ulaş Erdem** - CS Student & Linux Enthusiast
* 💼 **LinkedIn:** [Ufuk Ulaş Erdem](https://www.linkedin.com/in/ufukulaserdem)
* 📧 **Email:** mainufukulaserdem@gmail.com
* 🎯 **Status:** Actively looking for **Summer 2026 Internship** opportunities in Cloud Security, SOC, or Linux System Administration.

## 📜 License

MIT
