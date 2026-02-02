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
* **High Performance:** Powered by eBPF (CO-RE principles applied via BCC) for minimal system overhead.

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

This will set up the systemd service and configure the environment.

```bash
git clone [https://github.com/ufukulaserdem/Kernel-Eye.git](https://github.com/ufukulaserdem/Kernel-Eye.git)
cd Kernel-Eye
chmod +x install.sh
sudo ./install.sh
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

The following table outlines the enforcement rules applied by the eBPF agent in kernel space:

| Alert Type | Trigger Condition | Severity | Action |
| :--- | :--- | :--- | :--- |
| **SELF_PROT** | Attempt to send lethal signal (9/15) to the Agent | 🔴 Critical | **BLOCK & LOG** |
| **CRITICAL** | Unauthorized access to `/etc/shadow` | 🔴 Critical | **KILL PROCESS** |
| **FILELESS** | Usage of `memfd_create` (Malware running in RAM) | 🟠 High | Log / Detect |
| **SPOOFING** | Trusted binary name (e.g., `code`) executing from non-system path (`/tmp`, `/home`) | 🟠 High | Log / Detect |
| **ROOT** | Unexpected process execution with UID 0 | 🟡 Medium | Log |

## Roadmap

### Completed Capabilities
- [x] **Anti-Tamper:** LSM Hook implementation for self-protection.
- [x] **Context Awareness:** Parent-Child process tree analysis (`bash` -> `python` -> `malware`).
- [x] **Anti-Spoofing:** Binary path verification vs. process name.
- [x] **Fileless Defense:** Memory file descriptor monitoring.
- [x] **SIEM Integration:** JSON Structured Logging.

### Future Work
- [ ] **CO-RE Migration:** Porting from BCC (Python) to libbpf (C) for dependency-free deployment.
- [ ] **YARA Integration:** Scanning file content upon `openat`.
- [ ] **Network Module:** Re-implementing eBPF socket filters for C2 detection.
    
## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Author & Contact
**Ufuk Ulaş Erdem** - CS Student & Linux Enthusiast
* **LinkedIn:** [Ufuk Ulaş Erdem](https://www.linkedin.com/in/ufukulaserdem)
* **Email:** mainufukulaserdem@gmail.com
* **Status:** Actively looking for **Summer 2026 Internship** opportunities in Cloud Security, SOC, or Linux System Administration.

## License

MIT
