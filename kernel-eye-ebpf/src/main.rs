#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{lsm, map},
    maps::{Array, HashMap, RingBuf},
    programs::LsmContext,
};
use kernel_eye_common::{ACTION_BLOCKED, EPERM, EVENT_FILE, EVENT_TAMPER, EventData};

#[allow(warnings)]
mod bindings;
use bindings::{file, inode, task_struct};

// ── eBPF Maps ───────────────────────────────────────────────────────

/// Inode numbers of protected files. Populated by user-space at startup.
/// Key: inode number (u64), Value: 1 (flag indicating protection).
#[map]
static PROTECTED_INODES: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// PIDs that are whitelisted from file protection checks (e.g. root shells, the agent itself).
/// Key: tgid (u32), Value: 1 (flag).
#[map]
static WHITELIST_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Single-element array holding the agent's own TGID for anti-tamper protection.
/// Index 0 = agent TGID.
#[map]
static AGENT_TGID: Array<u32> = Array::with_max_entries(1, 0);

/// Ring buffer for streaming telemetry events to user-space (256 KB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ── Helper: emit an event to the ring buffer ────────────────────────

#[inline(always)]
fn emit_event(event_type: u32, action: u32, ino: u64, label: &[u8]) {
    let mut event = EventData {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        tgid: bpf_get_current_pid_tgid() as u32,
        uid: bpf_get_current_uid_gid() as u32,
        event_type,
        action,
        ino,
        comm: [0; 16],
        filename: [0; 256],
    };
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }
    // Copy label into filename field (bounded to 255 bytes + null).
    let copy_len = if label.len() < 256 { label.len() } else { 255 };
    event.filename[..copy_len].copy_from_slice(&label[..copy_len]);
    let _ = EVENTS.output::<EventData>(&event, 0);
}

// ═══════════════════════════════════════════════════════════════════
//  LSM HOOK: file_open — Proactive file access enforcement
// ═══════════════════════════════════════════════════════════════════
//
//  Signature: int security_file_open(struct file *file)
//
//  Decision logic:
//    1. Extract inode number from file->f_inode->i_ino.
//    2. If the inode is NOT in PROTECTED_INODES → allow (return 0).
//    3. If the caller's TGID is in WHITELIST_PIDS → allow (return 0).
//    4. Otherwise → DENY (-EPERM) and emit a CRITICAL alert.

#[lsm(hook = "file_open")]
pub fn file_open_hook(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // On error, fail-open to avoid bricking the system.
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // 1. Get the struct file pointer from arg 0.
    let fp: *const file = ctx.arg(0);
    if fp.is_null() {
        return Ok(0);
    }

    // 2. Chase pointers: file → f_inode → i_ino.
    //    SAFETY: LSM hooks are BTF-typed; the verifier validates these accesses.
    let inode_ptr: *const inode = unsafe { (*fp).f_inode };
    if inode_ptr.is_null() {
        return Ok(0);
    }
    let ino: u64 = unsafe { (*inode_ptr).i_ino as u64 };

    // 3. Is this inode protected?
    if unsafe { PROTECTED_INODES.get(&ino) }.is_none() {
        return Ok(0); // Not a protected file — allow.
    }

    // 4. Is the caller whitelisted?
    let tgid = bpf_get_current_pid_tgid() as u32;
    if unsafe { WHITELIST_PIDS.get(&tgid) }.is_some() {
        return Ok(0); // Whitelisted process — allow.
    }

    // 5. DENY + emit telemetry.
    emit_event(EVENT_FILE, ACTION_BLOCKED, ino, b"file_open:BLOCKED\0");
    Ok(EPERM)
}

// ═══════════════════════════════════════════════════════════════════
//  LSM HOOK: task_kill — Anti-tamper self-protection
// ═══════════════════════════════════════════════════════════════════
//
//  Signature: int security_task_kill(struct task_struct *p,
//             struct kernel_siginfo *info, int sig,
//             const struct cred *cred)
//
//  Decision logic:
//    1. Read the agent's TGID from the AGENT_TGID array map.
//    2. If the target task's TGID matches the agent → DENY (-EPERM).
//    3. Otherwise → allow.

#[lsm(hook = "task_kill")]
pub fn task_kill_hook(ctx: LsmContext) -> i32 {
    match try_task_kill(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_task_kill(ctx: LsmContext) -> Result<i32, i32> {
    // 1. Read the agent's protected TGID.
    let agent_tgid = match AGENT_TGID.get(0) {
        Some(v) => *v,
        None => return Ok(0), // Map not yet populated — allow.
    };
    if agent_tgid == 0 {
        return Ok(0); // Not configured yet.
    }

    // 2. Read the target task's TGID.
    let target: *const task_struct = ctx.arg(0);
    if target.is_null() {
        return Ok(0);
    }
    let target_tgid = unsafe { (*target).tgid as u32 };

    // 3. Extract the SIGNAL NUMBER from arg 2
    let sig: i32 = ctx.arg(2);

    // 4. If someone is trying to kill the agent → block.
    if target_tgid == agent_tgid {
        // Don't block ourselves (the agent) from cleaning up its own threads.
        let caller_tgid = bpf_get_current_pid_tgid() as u32;
        if caller_tgid == agent_tgid {
            return Ok(0);
        }

        if sig == 9 || sig == 15 {
            emit_event(EVENT_TAMPER, ACTION_BLOCKED, 0, b"task_kill:BLOCKED\0");
            return Ok(EPERM);
        }
        return Ok(0);
    }

    Ok(0)
}

// ═══════════════════════════════════════════════════════════════════
//  LSM HOOK: task_free — Process exit telemetry / GC
// ═══════════════════════════════════════════════════════════════════

#[lsm(hook = "task_free")]
pub fn task_free_hook(ctx: LsmContext) -> i32 {
    match try_task_free(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_task_free(ctx: LsmContext) -> Result<i32, i32> {
    let task: *const task_struct = ctx.arg(0);
    let tgid = unsafe { (*task).tgid as u32 };

    // Remove the process from the whitelist if it was there (garbage collection).
    let _ = WHITELIST_PIDS.remove(&tgid);

    // Emit a lightweight process-exit event.
    //emit_event(EVENT_PROCESS_EXIT, ACTION_MONITOR, 0, b"task_free\0");

    Ok(0) // task_free must always return 0 (void hook).
}

// ── Panic handler for no_std eBPF ───────────────────────────────────
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
