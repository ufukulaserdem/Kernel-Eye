#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Kernel-Eye: eBPF-Based Linux Threat Detection & Response Agent.
Author: Ufuk Ulas Erdem
License: MIT
Description:
    Real-time kernel-level EDR agent utilizing eBPF/LSM hooks for 
    process monitoring, fileless threat detection, and active intrusion prevention.
"""

import sys
import os
import json
import signal
import datetime
import ctypes
from bcc import BPF

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

LOG_FILE_PATH = "/var/log/kernel-eye.json"

# UI Color Definitions
C_RESET   = "\033[0m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN    = "\033[96m"
C_BOLD    = "\033[1m"

EVENT_TYPES = {
    1: "EXEC",
    2: "FILE",
    4: "MEMFD",
    99: "TAMPER"
}

# Critical System Paths (Zero-Trust Policy)
# REMOVED: /etc/passwd (Must be world-readable for system stability)
PROTECTED_PATHS = [
    b"/etc/shadow",
    b"/etc/sudoers",
    b"/root/.ssh/authorized_keys"
]

# --- WHITELIST CONFIGURATION ---
WHITELIST_PROCESSES = [
    # System Services
    b"systemd", b"dbus-daemon", b"polkitd", b"rtkit-daemon", b"sshd", 
    b"login", b"sudo", b"kworker", b"unix_chkpwd",
    b"systemd-userwor", b"systemd-userwork", b"(sd-worker)",
    b"accounts-daemon", b"quota",
    
    # Desktop Integration (Prevents browser/GUI crashes)
    b"xdg-desktop-por", b"xdg-desktop-portal", b"flatpak",
    b"gnome-shell", b"plasmashell", b"kwin_wayland", b"Xorg",
    
    # Audio & Multimedia
    b"pipewire", b"pipewire-pulse", b"wireplumber", b"spotify",
    
    # Development Tools & Browsers
    b"code", b"zen", b"ghostty", b"chrome", b"firefox", b"brave", 
    b"git",
    
    # Interpreters
    b"bash", b"zsh", b"sh", b"python3", b"node"
]

# ==============================================================================
# eBPF KERNEL PROGRAM (C SOURCE)
# ==============================================================================

BPF_PROGRAM_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_PATH_LEN 256
#define EPERM 1

struct data_t {
    u32 pid;
    u32 uid;
    u32 type;
    char comm[16];
    char filename[MAX_PATH_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_ARRAY(protected_pid, u32, 1); 

// HOOK 1: Process Execution
int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.type = 1; 

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// HOOK 2: File Access
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.type = 2; 

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    if ((data.filename[0] == '/' && data.filename[1] == 'e' && data.filename[2] == 't' && data.filename[3] == 'c') ||
        (data.filename[0] == '/' && data.filename[1] == 'r' && data.filename[2] == 'o' && data.filename[3] == 'o' && data.filename[4] == 't')) {
            events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// HOOK 3: Fileless Execution
int syscall__memfd_create(struct pt_regs *ctx, const char __user *name) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.type = 4; 

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), name);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// LSM HOOK: Anti-Tamper
LSM_PROBE(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    u32 target_pid = p->tgid;
    int key = 0;
    u32 *my_pid = protected_pid.lookup(&key);

    if (my_pid && target_pid == *my_pid) {
        if (sig == 9 || sig == 15) {
            struct data_t data = {};
            data.type = 99; 
            data.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            data.filename[0] = 'K'; data.filename[1] = 'I'; data.filename[2] = 'L'; data.filename[3] = 'L';
            events.perf_submit(ctx, &data, sizeof(data));
            return -EPERM;
        }
    }
    return 0;
}
"""

# ==============================================================================
# AGENT LOGIC
# ==============================================================================

class KernelEyeAgent:
    def __init__(self):
        self.bpf = None
        self.running = False
        self._clear_screen()
        print(f"{C_CYAN}[*] Initializing Kernel-Eye Agent...{C_RESET}")
        self._check_root()
        self._init_bpf()

    def _clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _check_root(self):
        if os.geteuid() != 0:
            print(f"{C_RED}[-] Error: Kernel-Eye requires root privileges.{C_RESET}")
            sys.exit(1)

    def _init_bpf(self):
        try:
            print(f"{C_BLUE}[*] Loading eBPF probes...{C_RESET}")
            self.bpf = BPF(text=BPF_PROGRAM_SOURCE)
            
            self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("execve"), fn_name="syscall__execve")
            self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("openat"), fn_name="syscall__openat")
            self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("memfd_create"), fn_name="syscall__memfd_create")
            
            my_pid = os.getpid()
            self.bpf["protected_pid"][ctypes.c_int(0)] = ctypes.c_uint32(my_pid)
            print(f"{C_GREEN}[+] Anti-Tamper Protection: Active (PID: {my_pid}){C_RESET}")
            
        except Exception as e:
            print(f"{C_RED}[-] Critical Error: {e}{C_RESET}")
            sys.exit(1)

    def log_event(self, event_data):
            try:
                with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
                    json.dump(event_data, f)
                    f.write("\n")
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                print(f"{C_RED}[!] LOG ERROR: Could not write to JSON: {e}{C_RESET}")

    def print_dashboard_row(self, alert_type, pid, process, details, color):
        print(f"{color}{alert_type:<12} | {pid:<6} | {process:<15} | {details}{C_RESET}")

    def enforce_policy(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        
        try:
            comm = event.comm.decode('utf-8', 'ignore').strip()
            filename = event.filename.decode('utf-8', 'ignore').strip()
        except:
            return

        # 1. TAMPER CHECK
        if event.type == 99:
             self.print_dashboard_row("TAMPER", event.pid, comm, "KILL ATTEMPT [BLOCKED]", C_RED + C_BOLD)
             return

        # 2. WHITELIST CHECK
        is_whitelisted = event.comm in WHITELIST_PROCESSES
        should_kill = False
        
        # Rule: Exec from /tmp or /dev/shm
        if event.type == 1:
            if filename.startswith("/tmp") or filename.startswith("/dev/shm"):
                should_kill = True
                is_whitelisted = False
        
        # Rule: Fileless execution by Interpreters
        if event.type == 4:
            if event.comm in [b"python3", b"node", b"perl", b"ruby", b"php"]:
                should_kill = True
                is_whitelisted = False

        if is_whitelisted and not should_kill:
            return

        # Noise Filter
        if event.type == 4 and not should_kill:
            if any(x in filename for x in ["pulseaudio", "shm", "gdk", "mozilla", "xshm", "memfd:", "render", "wayland"]): return

        event_name = EVENT_TYPES.get(event.type, "UNK")
        
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "pid": event.pid,
            "process": comm,
            "target": filename,
            "event_type": event_name,
            "severity": "LOW",
            "action": "MONITOR"
        }

        # --- ENFORCEMENT ---

        # BLOCK CRITICAL FILES
        if event.type == 2 and any(p in filename.encode() for p in PROTECTED_PATHS):
            log_entry["severity"] = "CRITICAL"
            log_entry["action"] = "BLOCKED"
            try: os.kill(event.pid, signal.SIGKILL)
            except: pass
            self.print_dashboard_row("CRITICAL", event.pid, comm, f"ACCESS DENIED: {filename} [KILL]", C_RED + C_BOLD)
            self.log_event(log_entry)

        # BLOCK MALICIOUS EXEC
        elif should_kill:
            log_entry["severity"] = "HIGH"
            log_entry["action"] = "BLOCKED"
            try: os.kill(event.pid, signal.SIGKILL)
            except: pass
            
            if event.type == 4:
                 self.print_dashboard_row("FILELESS", event.pid, comm, f"MEMFD BLOCKED: {filename} [KILL]", C_YELLOW + C_BOLD)
            else:
                 self.print_dashboard_row("SUSPICIOUS", event.pid, comm, f"EXEC BLOCKED: {filename} [KILL]", C_MAGENTA + C_BOLD)
            
            self.log_event(log_entry)

        elif event.type == 1 and event.uid == 0:
             self.print_dashboard_row("ROOT EXEC", event.pid, comm, f"CMD: {filename}", C_CYAN)

    def run(self):
        self.running = True
        print(f"{C_GREEN}[+] Kernel-Eye is Active.{C_RESET}")
        print(f"{C_CYAN}[*] IPS: Enabled | Anti-Tamper: Enabled | Logging: JSON{C_RESET}")
        print("-" * 95)
        print(f"{C_BOLD}{'ALERT TYPE':<12} | {'PID':<6} | {'PROCESS':<15} | {'DETAILS'}{C_RESET}")
        print("-" * 95)
        
        self.bpf["events"].open_perf_buffer(self.enforce_policy)
        try:
            while self.running:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print(f"\n{C_RED}[*] Stopping Kernel-Eye Agent...{C_RESET}")
            sys.exit(0)

if __name__ == "__main__":
    KernelEyeAgent().run()