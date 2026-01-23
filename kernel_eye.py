#!/usr/bin/python3
# Kernel-Eye: eBPF-based Advanced EDR for Linux
# Github: https://github.com/ufukulaserdem/Kernel-Eye

from bcc import BPF
import ctypes
import requests
import json
import threading
import datetime
import time
import socket
import struct
import os
import signal 

# --- CONFIGURATION ---
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# --- ACTIVE RESPONSE SETTINGS ---
BLOCKING_MODE = True  # If True, it kills malicious processes immediately
RATE_LIMIT_SECONDS = 60 
alert_history = {} 

# --- COLORS ---
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

# =============================================================
# KERNEL SPACE (C CODE)
# =============================================================

bpf_source_code = """
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fcntl.h> 
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>

#define TYPE_EXEC 1
#define TYPE_FILE 2
#define TYPE_NET  3

struct data_t {
    u32 type;
    u32 pid;
    u32 uid;
    char comm[16];
    char fname[128];
    char arg1[128];
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

// Hook: Process Execution
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};
    data.type = TYPE_EXEC;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    // Basic Noise Filtering in Kernel Space (Optimization)
    char *f = data.fname;
    if (f[5] == 'l' && f[6] == 'i' && f[7] == 'b') return 0; 
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    
    const char *arg1_ptr = NULL;
    bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), &args->argv[1]);
    if (arg1_ptr) bpf_probe_read_user_str(&data.arg1, sizeof(data.arg1), arg1_ptr);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Hook: File Access
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    // Filter: Only trigger on WRITE/CREATE/TRUNC flags
    int is_write = 0;
    if ((args->flags & O_WRONLY) || (args->flags & O_RDWR) || 
        (args->flags & O_CREAT)  || (args->flags & O_TRUNC)) {
        is_write = 1;
    }
    if (is_write == 0) return 0;

    struct data_t data = {};
    data.type = TYPE_FILE;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    // Basic Path Filtering
    char *n = data.fname;
    if (n[0] == '/' && n[1] == 'p') return 0; // /proc
    if (n[0] == '/' && n[1] == 's') return 0; // /sys
    if (n[0] == '/' && n[1] == 'd') return 0; // /dev

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Hook: Network Connection
TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    struct data_t data = {};
    data.type = TYPE_NET;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    struct sockaddr_in *useraddr = (struct sockaddr_in *)args->uservaddr;
    struct sockaddr_in local_addr = {};
    bpf_probe_read_user(&local_addr, sizeof(local_addr), useraddr);

    if (local_addr.sin_family == AF_INET) {
        data.daddr = local_addr.sin_addr.s_addr;
        data.dport = local_addr.sin_port;
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

# =============================================================
# USER SPACE (PYTHON)
# =============================================================

def kill_process(pid, comm):
    if not BLOCKING_MODE: return False
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except: return False

def check_rate_limit(alert_signature):
    now = time.time()
    if alert_signature in alert_history:
        if (now - alert_history[alert_signature]) < RATE_LIMIT_SECONDS:
            return False
    alert_history[alert_signature] = now
    return True

def send_discord_alert(alert_type, pid, uid, details, comm, killed):
    if "http" not in WEBHOOK_URL: return
    
    signature = f"{alert_type}:{details}"
    if not check_rate_limit(signature): return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color_code = 3447003 # Blue
    if alert_type == "ROOT" or alert_type == "NET_SUSPICIOUS": color_code = 16776960 # Yellow
    if alert_type == "CRITICAL" or alert_type == "C2_CONNECT": color_code = 16711680 # Red

    title_suffix = "🚫 [BLOCKED]" if killed else ""

    payload = {
        "username": "Kernel-Eye",
        "avatar_url": "https://raw.githubusercontent.com/ufukulaserdem/Kernel-Eye/main/eye.jpg",
        "embeds": [{
            "title": f"🚨 {alert_type} {title_suffix}",
            "color": color_code,
            "fields": [
                {"name": "Details", "value": f"`{details}`", "inline": False},
                {"name": "Context", "value": f"UID: {uid} | PID: {pid} | {comm}", "inline": True},
                {"name": "Action Taken", "value": "PROCESS KILLED (SIGKILL)" if killed else "LOGGED ONLY", "inline": False},
                {"name": "Time", "value": timestamp, "inline": False}
            ]
        }]
    }
    try: requests.post(WEBHOOK_URL, json=payload, timeout=2)
    except: pass

print(f"{CYAN}[+] Kernel-Eye v1.0: ACTIVE DEFENSE SYSTEM ONLINE...{RESET}")
try:
    b = BPF(text=bpf_source_code)
except Exception as e:
    print(f"{RED}Error: {e}{RESET}"); exit()

# --- HEADER ---
print(f"{'='*80}")
print(f"║ {'ALERT TYPE':<14} ║ {'PID':<6} ║ {'DETAILS':<51}")
print(f"{'='*80}")

# --- GLOBAL WHITELIST (Reduce False Positives) ---
# Common desktop apps and system processes to ignore
WHITELIST = [
    "code", "discord", "firefox", "spotify", "chrome", "slack", "idea",
    ".cache", ".config", ".git", "node_modules", "cpuUsage.sh", "kworker",
    "goutputstream", "gnome", "kde", "systemd", "journal"
]

def ip_to_str(addr_int):
    try: return socket.inet_ntoa(struct.pack("<I", addr_int))
    except: return "0.0.0.0"

def print_event(cpu, data, size):
    event = b["events"].event(data)
    fname = event.fname.decode('utf-8', 'ignore')
    comm = event.comm.decode('utf-8', 'ignore')
    
    full_str = (fname + comm).lower()
    for w in WHITELIST:
        if w in full_str: return

    alert_type = "INFO"
    color = RESET
    send_to_discord = False
    should_kill = False
    details = ""

    # --- PROCESS MONITORING ---
    if event.type == 1:
        arg1 = event.arg1.decode('utf-8', 'ignore')
        details = f"EXEC: {fname} {arg1}"

        # 1. CRITICAL: Access to Shadow/Passwd
        if "shadow" in arg1 or "passwd" in arg1:
            alert_type = "CRITICAL"; color = RED; send_to_discord = True; should_kill = True 
        
        # 2. WARNING: Root Activity
        elif event.uid == 0:
            alert_type = "ROOT"; color = YELLOW; send_to_discord = True
        
        # 3. SUSPICIOUS: Shell Spawning (Reverse Shell Potential)
        elif ("bash" in fname or "sh" in fname) and event.uid != 0:
             if "zsh" not in fname: # Exclude user's default shell if needed
                alert_type = "SHELL"; color = RED; send_to_discord = False

    # --- FILE INTEGRITY MONITORING (FIM) ---
    elif event.type == 2:
        details = f"MODIFIED: {fname}"
        if fname.startswith("/etc/") or fname.startswith("/boot/"):
            alert_type = "FILE_MOD"; color = MAGENTA; send_to_discord = True
        elif fname.endswith(".bashrc"):
            alert_type = "PERSISTENCE"; color = RED; send_to_discord = True; should_kill = True 
        else:
            alert_type = "FILE"; color = RESET; send_to_discord = False

    # --- NETWORK MONITORING ---
    elif event.type == 3:
        ip = ip_to_str(event.daddr)
        port = socket.ntohs(event.dport)
        details = f"CONNECT: {ip}:{port}"
        
        if ip.startswith("127.0."): return
        
        # Filter standard traffic (HTTPS/DNS/NTP) to reduce noise
        if port == 443 or port == 53 or port == 123 or port == 0: return 

        # Detect Known Hacker Ports
        if port == 4444 or port == 1337 or port == 6667: 
            alert_type = "C2_CONNECT"; color = RED; send_to_discord = True; should_kill = True 
        elif port != 80: 
            alert_type = "NET_SUSPICIOUS"; color = YELLOW; send_to_discord = True
        else:
            alert_type = "NETWORK"; color = CYAN; send_to_discord = False

    if alert_type == "INFO": return
    
    # KILL SWITCH LOGIC
    killed = False
    if should_kill:
        killed = kill_process(event.pid, comm)
        if killed:
            details += " [🚫 BLOCK]" 
            color = RED

    # --- OUTPUT ---
    print(f"{color}║ {alert_type:<14} ║ PID: {event.pid:<6} ║ {details}{RESET}")

    if send_to_discord:
        t = threading.Thread(target=send_discord_alert, args=(alert_type, event.pid, event.uid, details, comm, killed))
        t.start()

b["events"].open_perf_buffer(print_event)

while True:
    try: b.perf_buffer_poll()
    except KeyboardInterrupt: exit()
