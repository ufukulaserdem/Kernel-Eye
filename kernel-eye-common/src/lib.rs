#![no_std]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventData {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub action: u32,
    pub ino: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

pub const EVENT_EXEC: u32 = 1;
pub const EVENT_FILE: u32 = 2;
pub const EVENT_MEMFD: u32 = 4;
pub const EVENT_TAMPER: u32 = 99;

pub const ACTION_MONITOR: u32 = 0;
pub const ACTION_BLOCKED: u32 = 1;

#[cfg(feature = "user")]
unsafe impl aya::Pod for EventData {}
