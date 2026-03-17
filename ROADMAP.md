# Kernel-Eye: Public Roadmap

**Status:** Active Development
**Goal:** Transition from a BCC-based conceptual prototype to a robust, CO-RE enabled eBPF agent for Linux endpoints.

## Phase 1: Foundation & Portability (v0.1.x)

_Current Focus_

The immediate goal is to eliminate heavy runtime dependencies and establish a reliable kernel-to-user-space pipeline.

- **CO-RE Migration:** Deprecate BCC. Rewrite eBPF probes in C using `libbpf` to ensure portability across modern Linux kernels without requiring local LLVM/Clang toolchains.
- **Telemetry Pipeline:** Implement a stable eBPF Ring Buffer architecture to stream events efficiently to the user-space daemon.
- **Lifecycle Safety:** Ensure the agent fails gracefully if required eBPF features are unavailable on the host kernel.

## Phase 2: Synchronous Enforcement (v0.2.x)

Moving from passive observation to active, deterministic prevention.

- **LSM Hook Integration:** Transition enforcement logic from asynchronous user-space reactions (e.g., `SIGKILL`) to synchronous kernel-space blocks using hooks like `bprm_check_security`.
- **Identity Hardening:** Move beyond easily spoofed `comm` (process name) checks. Enforce policies based on stable identifiers (inode, cgroup, uid).
- **Anti-Tamper:** Basic self-protection to ensure the user-space daemon cannot be trivially killed by standard unprivileged processes.

## Phase 3: Expanded Visibility (v0.3.x)

Once process execution (`execve`) and file enforcement are stable, expand the detection surface.

- **Network Hooks:** Initial visibility into outbound connections using `sock_ops` or TC (Traffic Control) to detect potential C2 beaconing.
- **Memory Events:** Basic tracking of `memfd_create` and suspicious memory mapping behaviors often used by fileless payloads.

## Long-Term Vision (v1.0)

- Fully standalone binary release.
- Comprehensive automated testing matrix.
- Structured telemetry output (JSON) ready for SIEM ingestion.
