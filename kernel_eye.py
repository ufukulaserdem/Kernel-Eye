#!/usr/bin/python3
# Kernel-Eye: eBPF-based Linux Security Agent
# Capabilities: Anti-Tamper (LSM), Anti-Spoofing, Zero-Trust, JSON Logging
# Author: Ufuk Ulas Erdem
# License: MIT

from bcc import BPF
import ctypes
import os
import json
import logging
import datetime
import socket
import sys
import time

# --- CONSTANTS ---
TYPE_EXEC = 1
TYPE_ZERO_MEMFD = 10
TYPE_SELF_PROT = 99
EPERM = 1

# --- LOGGING CONFIGURATION ---
LOG_FILE = "/var/log/kernel-eye.json"
logger = logging.getLogger("KernelEye")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# --- TRUSTED PROCESS NAMES (WHITELIST) ---
TRUSTED_COMMS = [
    "Xwayland", "code", "kwin_wayland", "systemd", "baloo_file",
    "ghostty", "zen", "flatpak", "cpuUsage.sh", "gitstatusd",
    "fnm", "brew", "zsh", "bash", "sh", "pipewire", "wireplumber",
    "kworker", "node", "python3"
]

bpf_source = """
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bpf.h>

#define TYPE_EXEC        1
#define TYPE_ZERO_MEMFD  10
#define TYPE_SELF_PROT   99
#define EPERM            1

struct data_t {
    u32 type;
    u32 pid;
    u32 ppid;
    u32 uid;
    int sig; // Signal number (e.g. 9 for SIGKILL)
    char comm[16];
    char pcomm[16];
    char fname[128];
    u32 killed;
};

// Struct to fix BCC macro expansion issue with char arrays
struct proc_key_t {
    char name[16];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(whitelist_map, u32, u32);
BPF_HASH(trusted_comms, struct proc_key_t, u32);
BPF_ARRAY(protected_pid, u32, 1); // Stores Agent's own PID

// --- SELF-PROTECTION (LSM HOOK) ---
// Hook: Triggered before a signal is delivered to a process
LSM_PROBE(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    u32 target_pid = p->tgid;
    int key = 0;
    u32 *my_pid = protected_pid.lookup(&key);

    // Check if target is Self AND signal is lethal (SIGKILL=9, SIGTERM=15)
    if (my_pid && target_pid == *my_pid) {
        if (sig == 9 || sig == 15) {
            
            struct data_t data = {};
            data.type = TYPE_SELF_PROT;
            data.pid = bpf_get_current_pid_tgid() >> 32; // Source PID (Attacker)
            data.sig = sig;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            events.perf_submit(ctx, &data, sizeof(data));

            // Block the signal
            return -EPERM;
        }
    }
    return 0;
}

// Helper: Validate if path is a standard system directory
static int is_system_path(char *f) {
    if (f[0] == '/' && f[1] == 'u' && f[2] == 's' && f[3] == 'r') return 1; // /usr
    if (f[0] == '/' && f[1] == 'b' && f[2] == 'i' && f[3] == 'n') return 1; // /bin
    if (f[0] == '/' && f[1] == 's' && f[2] == 'b' && f[3] == 'i') return 1; // /sbin
    if (f[0] == '/' && f[1] == 's' && f[2] == 'n' && f[3] == 'a') return 1; // /snap
    return 0;
}

static void get_parent_info(struct data_t *data) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = task->real_parent;
    data->ppid = parent->tgid;
    bpf_probe_read_kernel(&data->pcomm, sizeof(data->pcomm), parent->comm);
}

// --- ZERO MODULE: Fileless Detection ---
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    struct data_t data = {};
    get_parent_info(&data);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (whitelist_map.lookup(&pid)) return 0;

    struct proc_key_t key = {};
    __builtin_memcpy(&key.name, data.comm, sizeof(key.name));
    if (trusted_comms.lookup(&key)) return 0;

    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->uname);
    
    // Noise filters for common frameworks
    if (data.fname[0] == 'g' && data.fname[1] == 'd') return 0; 
    if (data.fname[0] == 'm' && data.fname[1] == 'o') return 0;

    data.type = TYPE_ZERO_MEMFD;
    data.pid = pid;
    data.uid = bpf_get_current_uid_gid();
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// --- CORE MODULE: Execution Monitoring ---
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    get_parent_info(&data);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.type = TYPE_EXEC;
    data.killed = 0;

    char *f = data.fname;
    
    // RULE 1: Block access to shadow file
    if (f[0] == '/' && f[1] == 'e' && f[2] == 't' && f[3] == 'c' && f[5] == 'h' && f[6] == 'a') {
        bpf_send_signal(9); 
        data.killed = 1;
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    // RULE 2: Anti-Spoofing (Trust only system paths)
    if (is_system_path(f)) return 0;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

def load_settings(bpf_obj):
    # 1. Load Trusted Process Names
    for comm in TRUSTED_COMMS:
        key = bpf_obj["trusted_comms"].Key()
        key.name = comm.encode('utf-8')[:15]
        bpf_obj["trusted_comms"][key] = ctypes.c_uint32(1)
    
    my_pid = os.getpid()
    
    # 2. Whitelist Agent PID to prevent self-looping
    bpf_obj["whitelist_map"][ctypes.c_uint32(my_pid)] = ctypes.c_uint32(1)
    
    # 3. Register Agent PID for Anti-Tamper Protection
    bpf_obj["protected_pid"][ctypes.c_int(0)] = ctypes.c_uint32(my_pid)
    
    print(f"[INFO] Kernel-Eye active. PID: {my_pid}")
    print(f"[INFO] Anti-Tamper & Anti-Spoofing modules loaded.")

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    fname = event.fname.decode('utf-8', 'ignore').strip()
    comm = event.comm.decode('utf-8', 'ignore').strip()
    pcomm = event.pcomm.decode('utf-8', 'ignore').strip()
    
    # Local noise filtering for CLI tools
    if any(x in fname for x in ["fnm", "gitstatus", "cpuUsage", ".local/share"]): return

    # --- CRITICAL: TAMPER PROTECTION ALERT ---
    if event.type == TYPE_SELF_PROT:
        alert_msg = f"[CRITICAL] TAMPER BLOCKED | Source: {comm}({event.pid}) attempted signal {event.sig}."
        print(f"\033[91m{alert_msg}\033[0m")
        
        logger.info(json.dumps({
            "timestamp": datetime.datetime.now().isoformat(),
            "event_type": "SECURITY_TAMPERING",
            "severity": "CRITICAL",
            "actor": {"process_name": comm, "pid": event.pid},
            "details": f"Unauthorized termination attempt (Signal {event.sig})",
            "action": "BLOCKED"
        }))
        return

    # Determine Event Category
    if event.type == TYPE_EXEC:
        category = "PROCESS_EXECUTION"
    else:
        category = "FILELESS_ACTIVITY"

    # Determine Severity
    severity = "INFO"
    if event.killed: severity = "CRITICAL"
    elif category == "FILELESS_ACTIVITY": severity = "HIGH"
    elif "/tmp/" in fname or "/home/" in fname: 
        severity = "SUSPICIOUS" 

    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "agent": "Kernel-Eye",
        "event_type": category,
        "severity": severity,
        "action": "BLOCKED" if event.killed else "DETECTED",
        "actor": {
            "pid": event.pid,
            "uid": event.uid,
            "process_name": comm,
            "ppid": event.ppid,
            "parent_process": pcomm
        },
        "target": {
            "file_path": fname
        }
    }

    # Write to SIEM Log
    logger.info(json.dumps(log_entry))

    # Console Output (Admin View)
    color = "\033[96m" # Cyan (Info)
    if severity == "CRITICAL": color = "\033[91m" # Red
    elif severity == "HIGH": color = "\033[93m" # Yellow
    elif severity == "SUSPICIOUS": color = "\033[95m" # Magenta
    
    print(f"{color}[{severity}] {log_entry['action']} | Tree: {pcomm}({event.ppid}) -> {comm}({event.pid}) | Target: {fname}\033[0m")

try:
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()
        os.chmod(LOG_FILE, 0o600)

    b = BPF(text=bpf_source)
    load_settings(b)
    b["events"].open_perf_buffer(handle_event)
except Exception as e:
    print(f"[ERROR] Initialization failed: {e}")
    sys.exit(1)

# Main Loop
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[INFO] Stopping agent...")
        sys.exit(0)