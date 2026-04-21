use std::{fs, mem, os::unix::fs::MetadataExt, process};

use anyhow::{Context, Result};
use aya::{
    Btf,
    Ebpf,
    include_bytes_aligned,
    maps::{Array, HashMap, RingBuf},
    programs::{Lsm, ProgramError},
};
use kernel_eye_common::{
    ACTION_BLOCKED, ACTION_MONITOR, EVENT_FILE, EVENT_MEMFD, EVENT_PROCESS_EXIT, EVENT_TAMPER,
    EventData,
};
use log::{info, warn};
use tokio::signal;

// ── Files protected by the LSM file_open hook ───────────────────────
const PROTECTED_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/id_rsa",
    "/etc/gshadow",
];

fn cstr_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

fn event_type_str(t: u32) -> &'static str {
    match t {
        1 => "EXEC",
        2 => "FILE_ACCESS",
        4 => "FILELESS_MEMFD",
        5 => "PROCESS_EXIT",
        99 => "SECURITY_TAMPERING",
        _ => "UNKNOWN",
    }
}

fn action_str(a: u32) -> &'static str {
    match a {
        ACTION_MONITOR => "MONITOR",
        ACTION_BLOCKED => "BLOCKED",
        _ => "UNKNOWN",
    }
}

fn severity_str(event_type: u32, action: u32) -> &'static str {
    match (event_type, action) {
        (EVENT_TAMPER, ACTION_BLOCKED) => "CRITICAL",
        (EVENT_FILE, ACTION_BLOCKED) => "CRITICAL",
        (EVENT_MEMFD, _) => "HIGH",
        (EVENT_PROCESS_EXIT, _) => "INFO",
        _ => "MEDIUM",
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // ── Load eBPF object ────────────────────────────────────────────
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kernel-eye"
    )))
    .context("loading eBPF object")?;

    let btf = Btf::from_sys_fs().context("loading BTF from /sys/kernel/btf/vmlinux")?;

    // ── Attach LSM: file_open ───────────────────────────────────────
    {
        let prog = bpf
            .program_mut("file_open_hook")
            .context("finding file_open_hook program")?;
        let prog: &mut Lsm = prog
            .try_into()
            .map_err(|e: ProgramError| anyhow::anyhow!(e))
            .context("casting file_open_hook to LSM")?;
        prog.load("file_open", &btf)
            .context("loading file_open LSM")?;
        prog.attach().context("attaching file_open LSM")?;
        info!("✓ LSM file_open attached");
    }

    // ── Attach LSM: task_kill ───────────────────────────────────────
    {
        let prog = bpf
            .program_mut("task_kill_hook")
            .context("finding task_kill_hook program")?;
        let prog: &mut Lsm = prog
            .try_into()
            .map_err(|e: ProgramError| anyhow::anyhow!(e))
            .context("casting task_kill_hook to LSM")?;
        prog.load("task_kill", &btf)
            .context("loading task_kill LSM")?;
        prog.attach().context("attaching task_kill LSM")?;
        info!("✓ LSM task_kill attached");
    }

    // ── Attach LSM: task_free ───────────────────────────────────────
    {
        let prog = bpf
            .program_mut("task_free_hook")
            .context("finding task_free_hook program")?;
        let prog: &mut Lsm = prog
            .try_into()
            .map_err(|e: ProgramError| anyhow::anyhow!(e))
            .context("casting task_free_hook to LSM")?;
        prog.load("task_free", &btf)
            .context("loading task_free LSM")?;
        prog.attach().context("attaching task_free LSM")?;
        info!("✓ LSM task_free attached");
    }

    // ── Populate AGENT_TGID map (anti-tamper) ───────────────────────
    let my_pid = process::id();
    {
        let mut agent_map: Array<_, u32> = Array::try_from(
            bpf.take_map("AGENT_TGID")
                .context("taking AGENT_TGID map")?,
        )
        .context("creating AGENT_TGID array")?;
        agent_map.set(0, my_pid, 0).context("setting agent TGID")?;
        info!("✓ Anti-tamper: agent TGID {} registered", my_pid);
    }

    // ── Populate WHITELIST_PIDS (whitelist our own PID) ──────────────
    {
        let mut wl: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.take_map("WHITELIST_PIDS")
                .context("taking WHITELIST_PIDS map")?,
        )
        .context("creating WHITELIST_PIDS map")?;
        wl.insert(my_pid, 1u8, 0)
            .context("whitelisting agent PID")?;
        info!("✓ Agent PID {} whitelisted for file access", my_pid);
    }

    // ── Populate PROTECTED_INODES map ───────────────────────────────
    {
        let mut prot: HashMap<_, u64, u8> = HashMap::try_from(
            bpf.take_map("PROTECTED_INODES")
                .context("taking PROTECTED_INODES map")?,
        )
        .context("creating PROTECTED_INODES map")?;

        for path in PROTECTED_PATHS {
            match fs::metadata(path) {
                Ok(meta) => {
                    let ino = meta.ino();
                    prot.insert(ino, 1u8, 0)
                        .with_context(|| format!("inserting inode {} for {}", ino, path))?;
                    info!("✓ Protected: {} (inode {})", path, ino);
                }
                Err(e) => {
                    warn!("⚠ Skipping {} (not accessible: {})", path, e);
                }
            }
        }
    }

    // ── Open ring buffer for telemetry ──────────────────────────────
    let mut ring = RingBuf::try_from(
        bpf.take_map("EVENTS")
            .context("taking EVENTS ring buffer map")?,
    )
    .context("creating ring buffer reader")?;

    info!("══════════════════════════════════════════════════════");
    info!("  Kernel-Eye: Active — {} LSM hooks armed", 3);
    info!("  Protected files: {}", PROTECTED_PATHS.len());
    info!("  Agent PID: {} (tamper-protected)", my_pid);
    info!("══════════════════════════════════════════════════════");

    // ── Event loop ──────────────────────────────────────────────────
    loop {
        // Drain available events.
        while let Some(item) = ring.next() {
            if item.len() < mem::size_of::<EventData>() {
                continue;
            }
            // SAFETY: We verified the buffer is large enough, and the kernel side
            // writes a valid EventData struct that we also control.
            let event = unsafe { (item.as_ptr() as *const EventData).read_unaligned() };

            let comm = cstr_to_string(&event.comm);
            let label = cstr_to_string(&event.filename);
            let severity = severity_str(event.event_type, event.action);
            let event_type = event_type_str(event.event_type);
            let action = action_str(event.action);

            // Structured JSON log — SIEM-ready.
            println!(
                "{{\"severity\":\"{}\",\"event_type\":\"{}\",\"action\":\"{}\",\"pid\":{},\"tgid\":{},\"uid\":{},\"ino\":{},\"comm\":\"{}\",\"label\":\"{}\"}}",
                severity, event_type, action, event.pid, event.tgid, event.uid, event.ino, comm, label
            );
        }

        // Yield control — use tokio::select! to handle Ctrl+C gracefully.
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Ctrl+C received — shutting down gracefully.");
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                // Continue polling.
            }
        }
    }

    info!("Kernel-Eye: shutdown complete.");
    Ok(())
}
