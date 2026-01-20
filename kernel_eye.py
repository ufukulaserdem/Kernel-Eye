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
import signal # YENI: Process oldurmek icin sinyal kutuphanesi

# --- KONFIGURASYON ---
# Terminalden: sudo DISCORD_WEBHOOK_URL="..." python3 kernel_eye.py
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# --- ACTIVE RESPONSE (ENGELLEME) AYARI ---
# Eger True ise, kirmizi alarmlarda islemi oldurur.
BLOCKING_MODE = True 

RATE_LIMIT_SECONDS = 60 
alert_history = {} 

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

# =============================================================
# KERNEL SPACE (C CODE) - Ayni kaliyor
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

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};
    data.type = TYPE_EXEC;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    char *f = data.fname;
    if (f[5] == 'l' && f[6] == 'i' && f[7] == 'b') return 0; 
    if (f[1] == 'u' && f[2] == 's' && f[3] == 'r') {
        if (f[9] == 'b') { if (f[12] == 'e') return 0; } 
        if (f[9] == 'f') return 0; 
        if (f[9] == 'g') return 0; 
        if (f[9] == 's') return 0; 
        if (f[9] == 'm') return 0; 
        if (f[9] == 't') return 0; 
        if (f[9] == 'd') return 0; 
        if (f[9] == 'c') { if (f[10] != 'u') return 0; } 
    }
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    
    const char *arg1_ptr = NULL;
    bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), &args->argv[1]);
    if (arg1_ptr) bpf_probe_read_user_str(&data.arg1, sizeof(data.arg1), arg1_ptr);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
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

    char *n = data.fname;
    if (n[0] == '/' && n[1] == 'p') return 0; 
    if (n[0] == '/' && n[1] == 's') return 0; 
    if (n[0] == '/' && n[1] == 'd') return 0; 
    if (n[0] == '/' && n[1] == 'r') return 0; 
    if (n[0] == '/' && n[1] == 't') return 0; 
    if (n[0] == '/' && n[1] == 'v' && n[2] == 'a') return 0; 

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

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
    """
    Tehlikeli islemi aninda sonlandirir (SIGKILL).
    """
    if not BLOCKING_MODE: return False
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return False # Islem zaten bitmis
    except Exception as e:
        print(f"{RED}Error killing process {pid}: {e}{RESET}")
        return False

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
    
    color_code = 3447003 
    if alert_type == "ROOT" or alert_type == "NET_SUSPICIOUS": color_code = 16776960 
    if alert_type == "CRITICAL" or alert_type == "C2_CONNECT": color_code = 16711680 

    # Eger process oldurulduyse basliga ekle
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
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=2)
    except: pass

print(f"{CYAN}[+] Kernel-Eye v6.0: ACTIVE BLOCKING MODE ENABLED!{RESET}")
try:
    b = BPF(text=bpf_source_code)
except Exception as e:
    print(f"{RED}Error: {e}{RESET}"); exit()

print(f"{'TYPE':<10} {'PID':<8} {'UID':<6} {'DETAILS'}")
print(f"{'='*60}")

WHITELIST = [
    "code", "discord", "firefox", "spotify", "chrome", "slack", "idea",
    ".cache", ".config", ".git", "node_modules", "cpuUsage.sh"
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
    should_kill = False # Oldurme karari
    details = ""

    # --- PROCESS ---
    if event.type == 1:
        arg1 = event.arg1.decode('utf-8', 'ignore')
        details = f"EXEC: {fname} {arg1}"
        if event.uid == 0:
            alert_type = "ROOT"; color = YELLOW; send_to_discord = True
        elif "shadow" in arg1 or "passwd" in arg1:
            alert_type = "CRITICAL"; color = RED; send_to_discord = True; should_kill = True # <--- OLDUR
        elif ("bash" in fname or "sh" in fname) and event.uid != 0:
             if "zsh" not in fname:
                alert_type = "SHELL"; color = RED; send_to_discord = False

    # --- FILE ---
    elif event.type == 2:
        details = f"MODIFIED: {fname}"
        if fname.startswith("/etc/") or fname.startswith("/boot/"):
            alert_type = "FILE_MOD"; color = MAGENTA; send_to_discord = True
        elif fname.endswith(".bashrc"):
            alert_type = "PERSISTENCE"; color = RED; send_to_discord = True; should_kill = True # <--- OLDUR
        else:
            alert_type = "FILE"; color = RESET; send_to_discord = False

    # --- NETWORK ---
    elif event.type == 3:
        ip = ip_to_str(event.daddr)
        port = socket.ntohs(event.dport)
        details = f"CONNECT: {ip}:{port}"
        if ip.startswith("127.0."): return
        
        if port == 4444 or port == 1337 or port == 6667: 
            alert_type = "C2_CONNECT"; color = RED; send_to_discord = True; should_kill = True # <--- OLDUR
        elif port != 80 and port != 443 and port != 53: 
            alert_type = "NET_SUSPICIOUS"; color = YELLOW; send_to_discord = True
        else:
            alert_type = "NETWORK"; color = CYAN; send_to_discord = False

    if alert_type == "INFO": return
    
    # KILL SWITCH
    killed = False
    if should_kill:
        killed = kill_process(event.pid, comm)
        if killed:
            details += " [KILLED]"
            color = RED

    print(f"{color}{alert_type:<10} {event.pid:<8} {event.uid:<6} {details}{RESET}")

    if send_to_discord:
        t = threading.Thread(target=send_discord_alert, args=(alert_type, event.pid, event.uid, details, comm, killed))
        t.start()

b["events"].open_perf_buffer(print_event)

while True:
    try: b.perf_buffer_poll()
    except KeyboardInterrupt: exit()