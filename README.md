# Kernel-Eye: Development Roadmap

**Status:** Active Development (Rust/Aya Migration)
**Architecture:** `no_std` eBPF Kernel Space + Tokio Async User Space

Kernel-Eye is actively transitioning from a legacy BCC/Python prototype to a fully compiled, portable eBPF application using the Aya framework.

## Phase 1: Foundation & Stability (Current)
- [x] Migrate repository structure to a Rust multi-crate workspace (`kernel-eye`, `kernel-eye-ebpf`, `kernel-eye-common`).
- [ ] Implement robust eBPF program loading and attachment lifecycle via Aya.
- [ ] Establish a high-throughput, async Ring Buffer pipeline between kernel and user-space.
- [ ] Handle `bpf_probe_read` safely in `no_std` environment for telemetry extraction.

## Phase 2: Active Enforcement (LSM)
Moving from passive observation to deterministic prevention.
- [ ] Hook into `bprm_check_security` (LSM) to synchronously evaluate execution attempts.
- [ ] Implement O(1) decision lookups using eBPF Hash Maps for malicious file signatures.
- [ ] Eliminate race conditions entirely by denying execution (`-EPERM`) in kernel-space, discarding user-space `SIGKILL` fallbacks.

## Phase 3: Telemetry & CI/CD
- [ ] Implement structured JSON logging (SIEM-ready) in the user-space daemon.
- [ ] Set up automated GitHub Actions for `bpf-linker` compilation and `cargo fmt/clippy` checks.
- [ ] Introduce fallback mechanisms for environments lacking `CONFIG_BPF_LSM` support.

## Long-Term Vision
- Cryptographic identity verification for processes (moving beyond spoofable `comm` checks).
- Network anomaly detection via `sock_ops` or TC hooks.
