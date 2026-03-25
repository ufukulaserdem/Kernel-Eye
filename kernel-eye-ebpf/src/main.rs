#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{lsm, map},
    maps::{HashMap, RingBuf},
    programs::LsmContext,
};
use kernel_eye_common::{ACTION_MONITOR, EVENT_TAMPER, EventData};

#[allow(warnings)]
mod bindings;
use bindings::task_struct;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessContext {
    pub original_comm: [u8; 16],
    pub is_trusted: u8,
}

// Maksimum 10240 süreç kaydı tutacak HashMap
#[map]
static PROCESS_MAP: HashMap<u32, ProcessContext> = HashMap::with_max_entries(10240, 0);

// Kullanıcı alanına log gönderecek 256 KB RingBuffer
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Süreç bellekten tamamen silinmeden hemen önce çalışan LSM kancası
#[lsm(hook = "task_free")]
pub fn task_free_hook(ctx: LsmContext) -> i32 {
    match try_task_free(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_task_free(ctx: LsmContext) -> Result<i32, i32> {
    // 1. İşaretçiyi al
    let task = ctx.arg::<*const task_struct>(0);

    // 2. Doğrudan bellek okuması (Direct Dereference).
    // LSM kancaları BTF destekli olduğu için doğrulayıcı (verifier) buna izin verir.
    let tgid = unsafe { (*task).tgid as u32 };

    // 3. Haritadan temizle (Garbage Collection)
    let _ = PROCESS_MAP.remove(&tgid);

    // 4. Minimal telemetry event to prove end-to-end pipeline.
    let mut event = EventData {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        tgid,
        uid: bpf_get_current_uid_gid() as u32,
        event_type: EVENT_TAMPER,
        action: ACTION_MONITOR,
        ino: 0,
        comm: [0; 16],
        filename: [0; 256],
    };
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }
    let label = b"task_free\0";
    event.filename[..label.len()].copy_from_slice(label);
    let _ = EVENTS.output::<EventData>(&event, 0);

    Ok(0)
}

// Çekirdek içi çökme yöneticisi
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
