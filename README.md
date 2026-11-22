# Airlock

**Airlock** is a hardware-isolated execution sandbox for autonomous AI coding and tool-using agents. It runs untrusted code, shell commands, compilers, and package managers inside ephemeral Linux microVM **Chambers** gated by a host-side **Secretless Capability Broker**, with `vsock`-only networking (zero `virtio-net`), pre-mount `.env`/credential scrubbing, and an atomic Copy-on-Write **Commit Gate** (`apply`/`undo`) backed by a tamper-evident audit trail.

- **Vision & Gap Analysis:** [`intent.md`](intent.md)
- **Requirements & Architecture Spec (Phase 1, v1.0 Signed Off):** [`spec.md`](spec.md)
- **Cookbook (Recipes & Harness Integration):** [`docs/cookbook.md`](docs/cookbook.md)
- **Phase 0 (M0) Technical Spike Report:** [`docs/m0-spike-report.md`](docs/m0-spike-report.md)
- **CI & Cloud Infrastructure:** [`.github/workflows/ci-gcp.yml`](.github/workflows/ci-gcp.yml), [`cloudbuild.yaml`](cloudbuild.yaml), [`infra/gcp/README.md`](infra/gcp/README.md)

---

## What Airlock Does

Autonomous agents routinely execute arbitrary shell commands and untrusted dependencies while sitting on top of a developer's `$HOME`, `~/.ssh`, `.env` files, and unrestricted network access. Airlock enforces **five architectural invariants** to eliminate ambient authority and secret theft without breaking standard developer workflows:

1. **Dedicated Guest Kernel Boundary:** Untrusted workloads run inside hardware-virtualized Linux microVMs — Apple `Virtualization.framework` on Apple Silicon macOS and KVM + Firecracker (`jailer`) on Linux — never on the host kernel.
2. **Zero Raw Secrets in the Chamber:** No `.env` files, API keys, cloud tokens, or SSH private keys enter guest disk, RAM, or environment variables. Pre-mount scrubbing removes secrets and synthesizes safe placeholders from `.env.example`, while guest tools receive session-bound **phantom tokens** (`airlock-phantom:...`) tied to `(chamber_id, vsock_cid)` that the host broker swaps for real short-lived credentials on the wire.
3. **`vsock`-Only Egress (Zero `virtio-net`):** MicroVMs attach no virtual Ethernet NIC. All outbound traffic exits over `AF_VSOCK` through `airlock-broker`, which enforces L7 host/method/path rules, Git `git-receive-pack` branch-push guards (`refs/heads/agent/*`, no force-push), rate/spend limits, and post-DNS-resolution SSRF blocking (loopback, RFC 1918, `169.254.169.254`).
4. **Repo-Only Ephemeral CoW + Atomic Commit Gate:** Only a secret-scrubbed snapshot of the target repository is mounted read-only into the Chamber (`$HOME`, `~/.ssh`, keychains, and Docker sockets are invisible). Edits stay in an ephemeral `overlayfs` upper layer until scanned for secret leaks, symlink escapes, protected-path changes, and 3-way host conflicts, then applied atomically with a write-ahead `undo` journal.
5. **Local ↔ Remote Contract Parity:** A single `airlock.toml` (`version = "1"`) policy manifest, `airlock` CLI, and `SandboxProvider` SDK contract govern both `--target local` and `--target remote` execution.

### High-Level Architecture

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ Host Control Plane                                                         │
│  airlock CLI / Python & TS SDKs  ──▶  airlockd (CoW Scrub, Commit Gate,    │
│                                       Journaled Apply/Undo, audit.jsonl)   │
│                                  ──▶  airlock-broker (L7 TLS Proxy,        │
│                                       Phantom Token HMAC, Git pkt-line,    │
│                                       Post-DNS SSRF Guard, Budgets)        │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │ AF_VSOCK (16-byte framed mux; ZERO virtio-net)
┌────────────────────────────────────▼───────────────────────────────────────┐
│ Ephemeral MicroVM Chamber (Apple VZ on macOS / Firecracker KVM on Linux)   │
│  airlock-guestd (PID 1 init, 127.0.0.1:3128 proxy, tun0 + stub DNS)        │
│  /workspace = overlayfs(lower: scrubbed RO repo, upper: ephemeral ext4)    │
│  Env: HTTP(S)_PROXY, ephemeral CA bundle, phantom capability tokens only   │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```text
.
├── Cargo.toml                        # Rust workspace (7 pure-std crates for offline builds)
├── airlock.toml.example              # Annotated Phase 1 policy manifest example
├── crates/
│   ├── airlock-proto/                # AF_VSOCK 16-byte multiplexed framing + Phase 2/3 TLV seams
│   ├── airlock-policy/               # Pure-Rust SHA-256/HMAC, CID-bound phantom tokens, airlock.toml parser
│   ├── airlock-broker/               # Post-DNS SSRF guard, Git smart-HTTP pkt-line guard, L7 policy & scrubber
│   ├── airlock-vmm/                  # HypervisorBackend abstractions (Firecracker EROFS + Apple VZ, zero NIC)
│   ├── airlockd/                     # APFS clonefile(2) scrubber, Commit Gate, journaled apply/undo, audit.jsonl
│   ├── airlock-guestd/               # Guest bootstrap planner (overlayfs, tun0, proxy/CA env, .gitconfig)
│   └── airlock-cli/                  # clig.dev & WCAG 2.2 AA CLI (init, doctor, logs --verify, version)
├── macos/airlock-vz-helper/          # Minimal signed Swift helper holding com.apple.security.virtualization
├── guest/image/                      # Hardened Linux 6.12 LTS kernel config (CONFIG_VIRTIO_NET unset)
├── sdks/
│   ├── python/                       # Zero-dependency airlock-sdk + LangGraph/Claude/OpenAI/OpenHands adapters
│   └── typescript/                   # Zero-dependency @airlock/sdk client
├── tests/pytest/                     # Progressive pytest suite (smoke -> unit -> integration -> security)
├── scripts/ci-pytest.sh              # Staged pytest runner with JUnit XML reporting
├── .github/workflows/ci-gcp.yml      # GitHub Actions: smoke -> OS matrix -> GCE KVM -> GCP Cloud Build
├── cloudbuild.yaml                   # Google Cloud Build pipeline (keyless WIF)
├── infra/gcp/                        # One-time WIF setup & nested-KVM GCE runner provisioning scripts
└── docs/                             # Cookbook & Phase 0 (M0) technical spike report
```

---

## How to Use

### Prerequisites

- **Rust toolchain** (`cargo`, `rustc` 2021 edition) — all 7 workspace crates use pure Rust `std` and build offline.
- **Python 3.10+** (and `pytest >= 8.0` for running the progressive test suite).
- **Apple Silicon macOS** with Swift / Xcode Command Line Tools (to build and sign `macos/airlock-vz-helper`), **or** **Linux** with `/dev/kvm`, `firecracker`, `jailer`, and `mkfs.erofs` (for Firecracker VMM checks).

### 1. Build & Verify Host Readiness

```sh
# Build the Rust CLI and run all workspace unit tests
cargo build -p airlock-cli
cargo test --workspace

# On Apple Silicon macOS: build and ad-hoc sign the Virtualization.framework helper
sh "macos/airlock-vz-helper/build.sh"
"macos/airlock-vz-helper/bin/airlock-vz-helper" --probe --json

# Run host diagnostics (supports --plain, --json, and NO_COLOR=1)
./target/debug/airlock doctor
./target/debug/airlock doctor --plain
./target/debug/airlock doctor --json
```

### 2. CLI Commands

All commands follow [`clig.dev`](https://clig.dev) and WCAG 2.2 AA contrast/non-color-only badge conventions (`[SEALED]`, `[ALLOW]`, `[REVIEW]`, `[BLOCKED]`) and accept `--json` and `--plain`.

| Command | Description |
|---|---|
| `airlock init [dir] [--force]` | Auto-detects `Cargo.toml`, `package.json`, `pyproject.toml` and writes a least-privilege `airlock.toml` (`version = "1"`). Exits `78` if the file already exists unless `--force` is passed. |
| `airlock doctor` | Checks workspace path hygiene, Apple Silicon + `airlock-vz-helper` probe (macOS), or `/dev/kvm`, `firecracker`, `jailer`, and `mkfs.erofs` (Linux). |
| `airlock logs [--verify] <audit.jsonl>` | Prints an audit log, or with `--verify` validates the SHA-256 hash chain (exits `0` if intact, `79` if tampered). |
| `airlock version` | Prints the Airlock version and Phase 1 spec alignment. |

### 3. Configure `airlock.toml`

Generate a starter policy with `airlock init` or copy [`airlock.toml.example`](airlock.toml.example). A manifest declares:

- `[chamber]` — `target` (`local` | `remote`), `profile` (`standard` | `containers`), CPU/memory/disk/PID quotas, and TTLs.
- `[workspace]` — `scrub_globs` (`.env*`, `*.pem`, `*.key`, `.netrc`), `synthesize_env_from_example`, and `protected_paths` (`.git/**`, `.github/workflows/**`, `airlock.toml`, `Dockerfile`, `Makefile`).
- `[[capabilities]]` — explicit L7 HTTP and `git_http` allowlists (hosts, methods, paths, `allowed_branches`, `allow_force_push = false`, `inject_header`, `max_budget_usd`, `rate_limit_rpm`). Omit all `[[capabilities]]` blocks for zero-egress offline mode.
- `[commit_gate]` & `[audit]` — Commit Gate mode, secret scanning (`block`), max diff size, and hash-chained `audit.jsonl` settings.

See [`docs/cookbook.md`](docs/cookbook.md) for copy-pasteable policy recipes.

### 4. Python & TypeScript SDKs (Agent Harness Integration)

Install the Python SDK in editable mode:

```sh
pip install -e "sdks/python[dev]"
```

Run commands in a context-managed Chamber and integrate with `LangGraph`, `Claude Agent SDK`, `OpenAI Agents SDK`, or `OpenHands` via the `SandboxProvider` adapters:

```python
from airlock_sdk import AirlockClient, LangGraphSandbox

client = AirlockClient(target="local")  # connects to ~/.local/state/airlock/airlockd.sock

with client.chamber("/path/to/your-repo") as ch:
    sandbox = LangGraphSandbox(ch)
    res = sandbox.run_shell("pytest -q", step_id="step_run_tests")
    print(res.exit_code, res.stdout)

    diff = ch.diff()
    if not diff["protected_paths"] and not diff["secret_findings"]:
        ch.commit(approve_protected=False)
```

TypeScript (`@airlock/sdk` in [`sdks/typescript/`](sdks/typescript/)) provides the matching `AirlockClient` for remote/HTTP control planes. See [`docs/cookbook.md`](docs/cookbook.md) (Recipes 3–5) for full Python, TypeScript, and harness adapter examples.

### 5. Running Tests & Benchmarks

```sh
# Rust workspace unit tests (all 7 crates)
cargo test --workspace

# Phase 0 (M0) CoW scrubbing, vsock framing, HMAC token & Commit Gate benchmarks
cargo run --release -p airlockd --example m0_spike_bench

# Progressive pytest stages (smoke -> unit -> integration -> security)
./scripts/ci-pytest.sh --stage smoke
./scripts/ci-pytest.sh --stage more
JUNIT_DIR=reports ./scripts/ci-pytest.sh --stage all

# Fallback stdlib unittest check for Python SDK
python3 -m unittest discover -s "sdks/python/tests" -t "sdks/python" -v
```

---

## Current Status & Roadmap

Airlock is currently at **Phase 0 (M0) Complete / Phase 1 Core Scaffolded**. The Phase 1 specification (`spec.md` v1.0) and engineering decisions (`D-1`–`D-10`) are signed off, all 7 pure-Rust core crates, the macOS Virtualization probe helper, SDKs, progressive `pytest` harness, and GitHub ↔ Google Cloud WIF CI pipeline are implemented and tested. Live end-to-end microVM runtime execution (`M1`–`M5`) is the next stage of delivery.

### Milestone Progress

| Stage | Status | What Exists Today / Next Deliverables |
|---|---|---|
| **M0 — Phase 0 Technical Spikes** | **Complete (macOS) / Partial (Linux KVM)** | Signed-off `spec.md` (`D-1`–`D-10`); verified `airlock-vz-helper` zero-NIC `Virtualization.framework` config (`virtio_net_count = 0`); benchmarked APFS `clonefile(2)` + scrubbing (`100.2 ms` median on 1k files, `0` leaked secrets), `vsock` framing (`230 Gbps`), HMAC phantom tokens (`3.1 µs`), and Commit Gate scanning (`8.56 ms` on 500 files). Remaining M0 item: `mkfs.erofs` & Firecracker `AF_VSOCK` throughput benchmarks on a Linux KVM runner (see [`docs/m0-spike-report.md`](docs/m0-spike-report.md)). |
| **Phase 1 Core Crates, SDKs & CI** | **Implemented & Tested** | Core library implementations & unit tests across all 7 crates (`airlock-proto`, `airlock-policy`, `airlock-broker`, `airlock-vmm`, `airlockd`, `airlock-guestd`, `airlock-cli`); CLI `init`/`doctor`/`logs --verify`/`version`; Python (`airlock-sdk` + 4 harness adapters) & TypeScript (`@airlock/sdk`) clients; 4-tier `pytest` suite (`smoke`, `unit`, `integration`, `security`); GitHub Actions + Google Cloud Build WIF + GCE nested-KVM runner scripts. |
| **M1 — Linux Firecracker + `vsock` + EROFS Runtime** | **Planned** | Live `airlockd` Unix-socket/gRPC daemon, live `firecracker` + `jailer` VM lifecycle, `airlock-guestd` PID-1 `overlayfs`/`tun0`/`exec` RPC runtime, warm pool & crash reaper. |
| **M2 — Live Secretless Broker & Git Guard** | **Planned** | Async `tokio`/`hyper`/`rustls` L7 proxy over `AF_VSOCK`, ephemeral per-chamber CA minting, OS Keychain/vault/GitHub App credential providers, live spend/rate enforcement. |
| **M3 — macOS Apple Silicon VZ Runtime** | **Planned** | Full `airlock-vz-helper` VM boot, `virtio-fs` + `vsock` bridge, and `AT-1`–`AT-10` parity on Apple Silicon macOS. |
| **M4 — Interactive CLI Lifecycle & Commit Gate TUI** | **Planned** | End-to-end `airlock run`, `diff`, `commit`, `undo`, `ps`, `stop` subcommands and anti-habituation HITL TUI; APFS lazy hashing & batched `fsync` optimizations identified in M0. |
| **M5 — Hardening, SLSA L3 Images & GA** | **Planned** | Reproducible signed Linux 6.12 kernel/rootfs builds (`standard` & `containers` profiles), red-team pen-test (`T1`–`T10`), WCAG 2.2 AA audit, and 50-VM soak testing. |
| **Phase 2 & Phase 3 (Post-Phase 1)** | **Reserved Seams** | **Phase 2:** Per-MCP isolated Wasm/micro-container spokes (`IsolateGPT` pattern) via `principal_id` TLV seam. **Phase 3:** Guest kernel eBPF LSM taint tracking + CaMeL/FIDES semantic IFC via `taint_labels` TLV seam. |

---

## Workspace Directory Rename Notice (`D-10` / `C9`)

If your local checkout directory currently includes a trailing space (`Airlock `), rename it cleanly after closing active editor/shell sessions before pushing or invoking third-party tools:

```sh
cd ..
mv "Airlock " Airlock
```
