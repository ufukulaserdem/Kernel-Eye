# Kernel-Eye: eBPF-Based Linux Threat Detection

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-eBPF-red?style=for-the-badge)

**Kernel-Eye** is a stealthy, kernel-level Endpoint Detection and Response (EDR) agent designed to monitor system calls directly from the source. By leveraging **eBPF (Extended Berkeley Packet Filter)**, it hooks into the Linux kernel to detect malicious activities that user-space antivirus tools might miss.

It functions as both an **IDS (Intrusion Detection System)** and an **IPS (Intrusion Prevention System)**, capable of automatically blocking threats in real-time.

## Demo in Action

> **Scenario:** An attacker tries to execute a reverse shell or kill the agent using `kill -9`. Kernel-Eye blocks the termination attempt (Self-Protection), kills the malicious process, and generates a structured JSON log for SIEM analysis.

[kernel_eye.webm](https://github.com/user-attachments/assets/40bf9b8d-ed08-4ac5-9c83-4aebcfba08c8)

## Features

* **Immortal Mode (Anti-Tamper):** Uses **LSM (Linux Security Modules)** hooks (`task_kill`) to prevent the agent from being killed, even by the root user.
* **Anti-Spoofing (Path Validation):** Detects process masquerading (e.g., malware naming itself `code` or `systemd` but running from `/tmp`). It validates that trusted names only run from immutable system paths.
* **Zero-Trust (Fileless Detection):** Monitors `sys_enter_memfd_create` to detect and log fileless malware execution attempts residing purely in RAM.
* **Active Blocking (IPS):** Automatically terminates (SIGKILL) processes attempting to access critical files like `/etc/shadow`.
* **SIEM-Ready Logging:** Outputs structured, industry-standard JSON logs to `/var/log/kernel-eye.json`, ready for ingestion by Splunk, ELK, or Wazuh.
* **High Performance:** Powered by eBPF via BCC for minimal system overhead and deep kernel visibility.

## Installation

### 1. Prerequisites
* Linux Kernel 5.7+ (Required for LSM / Self-Protection features).
* BCC (BPF Compiler Collection) tools.
* Python 3.8+
* Root privileges.

### **For Fedora/RHEL**
```bash
sudo dnf install bcc-tools python3-bcc
```

### **For Ubuntu/Debian**
```bash
sudo apt-get install bpfcc-tools python3-bpfcc
```

## 2. Automatic Install (Recommended)

Kernel-Eye uses a standard `Makefile` for deployment, adhering to Linux conventions.

```bash
git clone https://github.com/ufukulaserdem/Kernel-Eye.git
cd Kernel-Eye
sudo make install
```

## 3. Configuration & Monitoring
Kernel-Eye runs as a systemd service and logs events locally.

**Check Service Status:**
```bash
sudo systemctl status kernel-eye
```
**View Live Security Logs:**
```bash
tail -f /var/log/kernel-eye.json
```
**Log Format Example:**
```JSON
{"timestamp": "2026-02-02T19:30:00", "severity": "CRITICAL", "event_type": "SECURITY_TAMPERING", "action": "BLOCKED", ...}
```
## Detection Logic

The following table outlines the **Active Enforcement Rules** applied by the Kernel-Eye agent. Unlike traditional EDRs that only alert, Kernel-Eye actively neutralizes threats in real-time.

| Alert Type | Trigger Condition | Severity | Action |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | Unauthorized access to `/etc/shadow`, `/etc/sudoers` or `/root/.ssh` | 🔴 Critical | **SIGKILL (Instant Block)** |
| **SUSPICIOUS** | Any binary/script executing from volatile paths (`/tmp`, `/dev/shm`) | 🟣 High | **SIGKILL (Prevent Exec)** |
| **FILELESS** | Interpreters (Python, Node, Perl) creating memory-only files via `memfd_create` | 🟡 High | **SIGKILL (Terminate)** |
| **ROOT_EXEC** | Unexpected root commands (e.g. `whoami`, `id`) from non-whitelisted processes | 🔵 Info | **Log / Monitor** |
| **TAMPER** | Attempts to send lethal signals (`SIGKILL`) to the Kernel-Eye agent | 🔴 Critical | **LSM Block (Self-Prot)** |

## Roadmap

### Completed Capabilities
- [x] **Real-Time Dashboard:** CLI-based interactive monitoring interface with color-coded alerts.
- [x] **Context-Aware Whitelisting:** Smart filtering that distinguishes legitimate tools from threats (e.g., allows `python3` but blocks if it executes `memfd_create`).
- [x] **Active IPS (Intrusion Prevention):** Automatically terminates (SIGKILL) processes accessing protected files or executing from `/tmp`.
- [x] **Anti-Tamper (Immortal Mode):** Protects the agent from being killed by root users via LSM hooks.
- [x] **Fileless Defense:** Detects malware executing purely from RAM (memory file descriptors).
- [x] **SIEM Integration:** JSON Structured Logging.

### Future Work & Engineering Goals
- [ ] **CO-RE Migration (Rust):** Porting the agent to **Rust (Aya)** to remove runtime dependencies (BCC/Clang) and create a single, portable binary (Solving "Dependency Hell").
- [ ] **Deep Kernel Blocking (LSM):** Moving the enforcement logic entirely to Kernel Space (`-EPERM`) to eliminate **TOCTOU (Time-of-Check Time-of-Use)** race conditions.
- [ ] **Signature Verification:** Implementing SHA256 hash checks and Inode verification to prevent **"Masquerading"** attacks (where malware mimics valid binary names).
- [ ] **Network Visibility:** Implementing eBPF `sock_ops` and Traffic Control (TC) filters to detect C2 (Command & Control) beaconing.
    
## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Author & Contact
**Ufuk Ulaş Erdem** - CS Student & Linux Enthusiast
* **LinkedIn:** [Ufuk Ulaş Erdem](https://www.linkedin.com/in/ufukulaserdem)
* **Email:** mainufukulaserdem@gmail.com
* **Status:** Actively looking for **Summer 2026 Internship** opportunities in Cloud Security, SOC, or Linux System Administration.

## License

MIT
