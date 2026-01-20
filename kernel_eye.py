#!/usr/bin/python3
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

# --- CONFIGURATION ---
# To run locally: export DISCORD_WEBHOOK_HERE="your_actual_url_here"
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_HERE", "")

# --- RATE LIMIT SETTINGS ---
# Prevent spamming: Do not send the same alert signature twice within 60 seconds.
RATE_LIMIT_SECONDS = 60 
alert_history = {} 

# --- ANSI COLORS ---
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

# =============================================================
# KERNEL SPACE (C CODE / eBPF)
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
    u32 type;        // Event Type (Exec, File, or Net)
    u32 pid;         // Process ID
    u32 uid;         // User ID
    char comm[16];   // Command Name
    char fname[128]; // Filename or Path
    char arg1[128];  // First Argument (for Exec)
    u32 daddr;       // Destination IP (IPv4)
    u16 dport;       // Destination Port
};

BPF_PERF_OUTPUT(events);

// --- ENGINE 1: PROCESS EXECUTION MONITORING (sys_execve) ---
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};
    data.type = TYPE_EXEC;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    // --- NOISE FILTER (PROCESS) ---
    // Filter out standard system calls to reduce CPU overhead.
    char *f = data.fname;
    if (f[5] == 'l' && f[6] == 'i' && f[7] == 'b') return 0; // /usr/libexec/...
    if (f[1] == 'u' && f[2] == 's' && f[3] == 'r') {
        if (f[9] == 'b') { if (f[12] == 'e') return 0; } // basename
        if (f[9] == 'f') return 0; // flatpak
        if (f[9] == 'g') return 0; // grep/git
        if (f[9] == 's') return 0; // sed/sleep
        if (f[9] == 'm') return 0; // mkdir
        if (f[9] == 't') return 0; // tty
        if (f[9] == 'd') return 0; // dircolors
        if (f[9] == 'c') { if (f[10] != 'u') return 0; } // cat/clear (allow curl)
    }
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    
    // Capture the first argument (often contains the target file or parameter)
    const char *arg1_ptr = NULL;
    bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), &args->argv[1]);
    if (arg1_ptr) bpf_probe_read_user_str(&data.arg1, sizeof(data.arg1), arg1_ptr);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// --- ENGINE 2: FILE INTEGRITY MONITORING (sys_openat) ---
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    // Filter: Only interested in WRITE, CREATE, or TRUNCATE operations.
    // Ignore O_RDONLY (Read Only) to save performance.
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

    // --- NOISE FILTER (FILES) ---
    // Ignore virtual file systems
    char *n = data.fname;
    if (n[0] == '/' && n[1] == 'p') return 0; // /proc
    if (n[0] == '/' && n[1] == 's') return 0; // /sys
    if (n[0] == '/' && n[1] == 'd') return 0; // /dev
    if (n[0] == '/' && n[1] == 'r') return 0; // /run
    if (n[0] == '/' && n[1] == 't') return 0; // /tmp
    if (n[0] == '/' && n[1] == 'v' && n[2] == 'a') return 0; // /var (logs)

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// --- ENGINE 3: NETWORK MONITORING (sys_connect) ---
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

    // Only filter IPv4 traffic (AF_INET)
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

def check_rate_limit(alert_signature):
    """
    Prevents alert fatigue by limiting duplicate alerts.
    Returns: True if alert should be sent, False if suppressed.
    """
    now = time.time()
    if alert_signature in alert_history:
        if (now - alert_history[alert_signature]) < RATE_LIMIT_SECONDS:
            return False
    alert_history[alert_signature] = now
    return True

def send_discord_alert(alert_type, pid, uid, details, comm):
    """
    Sends a structured security alert to Discord via Webhook.
    """
    if "http" not in WEBHOOK_URL: return
    
    # Check rate limit before sending
    signature = f"{alert_type}:{details}"
    if not check_rate_limit(signature): return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Alert Color Coding
    color_code = 3447003 # Default Blue
    if alert_type == "ROOT" or alert_type == "NET_SUSPICIOUS": color_code = 16776960 # YELLOW
    if alert_type == "CRITICAL" or alert_type == "C2_CONNECT": color_code = 16711680 # RED

    payload = {
        "username": "Kernel-Eye",
        "avatar_url": "https://raw.githubusercontent.com/ufukulaserdem/Kernel-Eye/main/eye.jpg",
        "embeds": [{
            "title": f"🚨 {alert_type}",
            "color": color_code,
            "fields": [
                {"name": "Details", "value": f"`{details}`", "inline": False},
                {"name": "Context", "value": f"UID: {uid} | PID: {pid} | {comm}", "inline": True},
                {"name": "Time", "value": timestamp, "inline": False}
            ]
        }]
    }
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=2)
    except: pass

print(f"{CYAN}[+] Kernel-Eye v5.0: NETWORK + PROCESS + FILE Monitoring Active...{RESET}")
try:
    b = BPF(text=bpf_source_code)
except Exception as e:
    print(f"{RED}Error compiling BPF: {e}{RESET}"); exit()

print(f"{'TYPE':<10} {'PID':<8} {'UID':<6} {'DETAILS'}")
print(f"{'='*60}")

# WHITELIST: Ignore these processes/paths to reduce noise
WHITELIST = [
    "code", "discord", "firefox", "spotify", "chrome", "slack", "idea",
    ".cache", ".config", ".git", "node_modules", "cpuUsage.sh"
]

def ip_to_str(addr_int):
    """Convert 32-bit integer to dot-decimal IP string."""
    try: return socket.inet_ntoa(struct.pack("<I", addr_int))
    except: return "0.0.0.0"

def print_event(cpu, data, size):
    event = b["events"].event(data)
    fname = event.fname.decode('utf-8', 'ignore')
    comm = event.comm.decode('utf-8', 'ignore')
    
    # Apply Whitelist
    full_str = (fname + comm).lower()
    for w in WHITELIST:
        if w in full_str: return

    alert_type = "INFO"
    color = RESET
    send_to_discord = False
    details = ""

    # --- PROCESS ENGINE LOGIC ---
    if event.type == 1:
        arg1 = event.arg1.decode('utf-8', 'ignore')
        details = f"EXEC: {fname} {arg1}"
        
        if event.uid == 0:
            alert_type = "ROOT"; color = YELLOW; send_to_discord = True
        elif "shadow" in arg1 or "passwd" in arg1:
            alert_type = "CRITICAL"; color = RED; send_to_discord = True
        elif ("bash" in fname or "sh" in fname) and event.uid != 0:
             if "zsh" not in fname:
                alert_type = "SHELL"; color = RED; send_to_discord = False

    # --- FILE ENGINE LOGIC ---
    elif event.type == 2:
        details = f"MODIFIED: {fname}"
        
        if fname.startswith("/etc/") or fname.startswith("/boot/"):
            alert_type = "FILE_MOD"; color = MAGENTA; send_to_discord = True
        elif fname.endswith(".bashrc"):
            alert_type = "PERSISTENCE"; color = RED; send_to_discord = True
        else:
            alert_type = "FILE"; color = RESET; send_to_discord = False

    # --- NETWORK ENGINE LOGIC ---
    elif event.type == 3:
        ip = ip_to_str(event.daddr)
        port = socket.ntohs(event.dport)
        details = f"CONNECT: {ip}:{port}"
        
        # Ignore Localhost traffic
        if ip.startswith("127.0."): return
        
        # Suspicious Ports Logic
        if port == 4444 or port == 1337 or port == 6667: # Common C2/Reverse Shell ports
            alert_type = "C2_CONNECT"; color = RED; send_to_discord = True
        elif port != 80 and port != 443 and port != 53: # Flag non-standard web/dns traffic
            alert_type = "NET_SUSPICIOUS"; color = YELLOW; send_to_discord = True
        else:
            alert_type = "NETWORK"; color = CYAN; send_to_discord = False

    if alert_type == "INFO": return
    
    print(f"{color}{alert_type:<10} {event.pid:<8} {event.uid:<6} {details}{RESET}")

    if send_to_discord:
        t = threading.Thread(target=send_discord_alert, args=(alert_type, event.pid, event.uid, details, comm))
        t.start()

# Start polling the Perf Buffer
b["events"].open_perf_buffer(print_event)

while True:
    try: b.perf_buffer_poll()
    except KeyboardInterrupt: exit()