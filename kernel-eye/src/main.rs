use std::{convert::TryInto, mem, thread, time::Duration};

use anyhow::{Context, Result};
use aya::{
    Btf,
    Ebpf,
    include_bytes_aligned,
    maps::RingBuf,
    programs::{Lsm, ProgramError},
};
use kernel_eye_common::EventData;

fn cstr_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

fn main() -> Result<()> {
    env_logger::init();

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kernel-eye"
    )))
    .context("loading eBPF object")?;

    let program = bpf
        .program_mut("task_free_hook")
        .context("finding task_free_hook program")?;
    let program: &mut Lsm = program
        .try_into()
        .map_err(|e: ProgramError| anyhow::anyhow!(e))
        .context("casting task_free_hook to LSM program")?;
    let btf = Btf::from_sys_fs().context("loading BTF from /sys/kernel/btf/vmlinux")?;
    program
        .load("task_free", &btf)
        .context("loading LSM program")?;
    program.attach().context("attaching LSM program")?;

    let mut ring = RingBuf::try_from(
        bpf.take_map("EVENTS")
            .context("taking EVENTS ring buffer map")?,
    )
    .context("creating ring buffer reader")?;

    println!("kernel-eye: loaded. waiting for task_free events...");
    loop {
        while let Some(item) = ring.next() {
            if item.len() < mem::size_of::<EventData>() {
                continue;
            }
            let event = unsafe { (item.as_ptr() as *const EventData).read_unaligned() };
            let comm = cstr_to_string(&event.comm);
            let filename = cstr_to_string(&event.filename);
            println!(
                "event_type={} action={} pid={} tgid={} uid={} comm={} label={}",
                event.event_type, event.action, event.pid, event.tgid, event.uid, comm, filename
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}
