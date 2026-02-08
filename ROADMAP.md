# Kernel-Eye Roadmap: Prototype to Production-Grade EDR

This roadmap outlines the next three major releases, focusing on portability, detection depth, and enterprise scale. Each phase includes a clear goal and concrete engineering initiatives with implementation strategy.

## Phase 1: Engineering Maturity (v3.1 – Stability)

**Goal:** Eliminate dependency fragility, improve portability, and harden delivery.

| Initiative | Objective | Technical Strategy |
| :--- | :--- | :--- |
| CO-RE Migration (BCC → libbpf or Aya) | Remove Python/BCC runtime dependencies and eliminate client-side Clang/LLVM requirements. | Replace BCC with libbpf (C) or Aya (Rust) and ship CO-RE-compatible eBPF objects; use BTF data to adapt at runtime across kernel versions, producing a single portable agent binary. |
| CI/CD + Red Team Regression Tests | Prevent regressions in blocking logic and validate security outcomes pre-release. | Build a pipeline that spins a disposable VM/container, runs the agent, and executes adversarial test cases (e.g., read `/etc/shadow`, kill agent PID, memfd payload) while asserting expected `-EPERM` or block events in telemetry. |

## Phase 2: Network & Advanced Detection (v3.5 – Visibility)

**Goal:** Expand visibility and protection beyond file system events into network and memory.

| Initiative | Objective | Technical Strategy |
| :--- | :--- | :--- |
| eBPF Socket Enforcement (sock_ops / TC) | Detect and block C2 beaconing, reverse shells, and suspicious outbound flows. | Attach `sock_ops` for connection telemetry and TC/XDP programs for enforcement; enrich events with destination metadata and apply policy thresholds for beaconing intervals, ports, and exfil patterns. |
| YARA for In-Memory Payloads | Detect fileless malware that bypasses disk visibility. | Introduce a user-space scanning pipeline that consumes memfd/exec telemetry and scans mapped memory regions with YARA rules, emitting high-confidence detections back into the logging pipeline. |

## Phase 3: Enterprise Scale (v4.0 – Fleet Management)

**Goal:** Operate thousands of agents with centralized policy and telemetry.

| Initiative | Objective | Technical Strategy |
| :--- | :--- | :--- |
| gRPC Streaming Telemetry | Replace local JSON with reliable, low-latency centralized transport. | Implement a gRPC client that streams structured events to an aggregation service, with backpressure handling, retry logic, and optional local buffering for offline nodes. |
| Kubernetes DaemonSet Deployment | Enable cloud-native rollout and node-level enforcement at scale. | Package the agent as a DaemonSet with privileged access and host PID namespace; mount BTF and kernel headers as needed and expose per-node health/metrics for cluster observability. |

---

**Versioning Note:** v3.1 focuses on stability and portability, v3.5 broadens detection surface, and v4.0 delivers fleet-grade operations. Each phase is designed to be independently shippable with measurable security outcomes.

## Milestones (High-Level)

1. v3.1: CO-RE agent build chain, reproducible releases, automated regression tests.
2. v3.5: Network visibility and fileless payload detection with measurable detection coverage.
3. v4.0: Centralized telemetry and Kubernetes-native deployment at fleet scale.

## Risk Register (Concise)

| Risk | Impact | Mitigation |
| :--- | :--- | :--- |
| Kernel instability (LSM/eBPF bugs) | System crash or node disruption | Enforce staged rollouts, strict verifier compliance, canary deployments, and a kill-switch policy. |
| Performance overhead | Latency or throughput regression | Benchmark per hook, implement sampling, and enforce event-rate budgets. |
| Distro/kernel compatibility | Agent fails to load or behaves inconsistently | CO-RE with BTF, compatibility matrix, and automated cross-distro CI. |
| Policy false positives | Service disruption due to over-blocking | Maintain allowlists, progressive enforcement modes, and audit-only fallback. |
| Telemetry loss/backpressure | Missed alerts or incomplete timelines | Buffered queues, retry with exponential backoff, and local spillover logs. |
