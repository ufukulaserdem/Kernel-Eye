#!/usr/bin/python3
from bcc import BPF
import ctypes
import requests
import json
import threading
import datetime
import time

WEBHOOK_URL = "DISCORD_WEBHOOK_HERE"

RATE_LIMIT_SECONDS = 60 
alert_history = {}

# --- RENKLER ---
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

#define TYPE_EXEC 1
#define TYPE_FILE 2

struct data_t {
    u32 type;
    u32 pid;
    u32 uid;
    char comm[16];
    char fname[128];
    char arg1[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};
    data.type = TYPE_EXEC;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    char *f = data.fname;
    if (f[5] == 'l' && f[6] == 'i' && f[7] == 'b') return 0; // libexec
    if (f[1] == 'u' && f[2] == 's' && f[3] == 'r') {
        if (f[9] == 'b') { if (f[12] == 'e') return 0; } // basename
        if (f[9] == 'f') return 0; // flatpak
        if (f[9] == 'g') return 0; // grep/git
        if (f[9] == 's') return 0; // sed/sleep
        if (f[9] == 'm') return 0; // mkdir
        if (f[9] == 't') return 0; // tty
        if (f[9] == 'd') return 0; // dircolors
        if (f[9] == 'c') { if (f[10] != 'u') return 0; } // cat/clear
    }
    if (f[1] == 'h' && f[2] == 'o' && f[3] == 'm') return 0; // /home hidden

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
    if (n[0] == '/' && n[1] == 'p') return 0; // proc
    if (n[0] == '/' && n[1] == 's') return 0; // sys
    if (n[0] == '/' && n[1] == 'd') return 0; // dev
    if (n[0] == '/' && n[1] == 'r') return 0; // run
    if (n[0] == '/' && n[1] == 't') return 0; // tmp
    if (n[0] == '/' && n[1] == 'v' && n[2] == 'a') return 0; // var

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

def check_rate_limit(alert_signature):
    now = time.time()
    if alert_signature in alert_history:
        last_time = alert_history[alert_signature]
        if (now - last_time) < RATE_LIMIT_SECONDS:
            return False
    
    alert_history[alert_signature] = now
    return True

def send_discord_alert(alert_type, pid, uid, cmd, comm):
    if "http" not in WEBHOOK_URL: return

    signature = f"{alert_type}:{cmd}"
    if not check_rate_limit(signature):
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color_code = 3447003 
    if alert_type == "ROOT": color_code = 16776960
    if alert_type == "CRITICAL": color_code = 16711680

    payload = {
        "username": "Kernel-Eye",
        "avatar_url": "eye.jpg",
        "embeds": [{
            "title": f"🚨 {alert_type}",
            "color": color_code,
            "fields": [
                {"name": "Command/File", "value": f"`{cmd}`", "inline": False},
                {"name": "User", "value": f"UID: {uid} | PID: {pid}", "inline": True},
                {"name": "Process", "value": comm, "inline": True},
                {"name": "Time", "value": timestamp, "inline": False}
            ]
        }]
    }
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=2)
    except: pass

print(f"{CYAN}[+] Kernel Eye v4.0: STABLE & SILENT MODE...{RESET}")
try:
    b = BPF(text=bpf_source_code)
except Exception as e:
    print(f"{RED}Error: {e}{RESET}"); exit()

print(f"{'TYPE':<10} {'PID':<8} {'UID':<6} {'DETAILS'}")
print(f"{'='*60}")

WHITELIST = [
    "code", "discord", "firefox", "spotify", "chrome", "slack", "idea",
    ".cache", ".config", ".git", ".local", "node_modules",
    "cpuUsage.sh", "sys_info.sh"
]

def print_event(cpu, data, size):
    event = b["events"].event(data)
    fname = event.fname.decode('utf-8', 'ignore')
    comm = event.comm.decode('utf-8', 'ignore')
    arg1 = event.arg1.decode('utf-8', 'ignore') if event.type == 1 else ""
    
    full_str = (fname + comm).lower()
    for w in WHITELIST:
        if w in full_str: return

    alert_type = "INFO"
    color = RESET
    send_to_discord = False
    details = ""

    if event.type == 1:
        details = f"{fname} {arg1}"
        if event.uid == 0:
            alert_type = "ROOT"; color = YELLOW; send_to_discord = True
        elif "shadow" in arg1 or "passwd" in arg1:
            alert_type = "CRITICAL"; color = RED; send_to_discord = True
        elif "curl" in fname or "nc" in fname:
            alert_type = "NETWORK"; color = CYAN; send_to_discord = True
        elif ("bash" in fname or "sh" in fname) and event.uid != 0:
            if "zsh" not in fname and "grepconf" not in fname:
                alert_type = "SHELL"; color = RED; send_to_discord = False

    elif event.type == 2:
        details = f"MODIFIED: {fname}"
        if fname.startswith("/etc/") or fname.startswith("/boot/"):
            alert_type = "FILE_MOD"; color = MAGENTA; send_to_discord = True
        elif fname.endswith(".bashrc"):
            alert_type = "PERSISTENCE"; color = RED; send_to_discord = True
        else:
            alert_type = "FILE"; color = RESET; send_to_discord = False

    if alert_type == "INFO": return

    print(f"{color}{alert_type:<10} {event.pid:<8} {event.uid:<6} {details}{RESET}")

    if send_to_discord:
        t = threading.Thread(target=send_discord_alert, args=(alert_type, event.pid, event.uid, details, comm))
        t.start()

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
