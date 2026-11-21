# Airlock (Phase 1)

Ephemeral microVM **Chambers** with a host-side **Secretless Capability Broker**, `vsock`-only networking (zero `virtio-net`), pre-mount `.env`/credential scrubbing, and an atomic Copy-on-Write **Commit Gate** (`airlock undo`).

- **Intent:** [`intent.md`](intent.md)
- **Requirements & Design Specification (v1.0, Signed Off):** [`spec.md`](spec.md)
- **Phase 0 (M0) Spike Report:** [`docs/m0-spike-report.md`](docs/m0-spike-report.md)

---

## Repository Layout

| Path | Role |
|---|---|
| `crates/airlock-proto` | `AF_VSOCK` 16-byte multiplexed framing protocol + Phase 2/3 Context TLV seams |
| `crates/airlock-policy` | Pure-Rust SHA-256 / HMAC-SHA256, CID-bound phantom tokens, secret-path rules, `airlock.toml` v1 parser |
| `crates/airlock-broker` | Post-DNS SSRF IP guard, Git smart-HTTP `git-receive-pack` pkt-line inspector, L7 policy & response scrubber |
| `crates/airlock-vmm` | `HypervisorBackend` abstractions for Firecracker (`EROFS` + `vsock`, zero NIC) and Apple `Virtualization.framework` |
| `crates/airlockd` | APFS `clonefile(2)` + workspace scrubber, Commit Gate validators, journaled `apply`/`undo`, hash-chained `audit.jsonl` |
| `crates/airlock-guestd` | Guest chamber bootstrap planner (`overlayfs`, `tun0`, `127.0.0.1:3128` proxy, CA trust env vars, `.gitconfig`) |
| `crates/airlock-cli` | `clig.dev` & WCAG 2.2 AA compliant `airlock` CLI (`init`, `doctor`, `logs --verify`, `version`) |
| `macos/airlock-vz-helper` | Minimal signed Swift helper holding `com.apple.security.virtualization` |
| `guest/image` | Hardened Linux 6.12 LTS guest kernel configuration (`CONFIG_VIRTIO_NET` unset) |
| `sdks/python` & `sdks/typescript` | Thin zero-dependency client SDKs + `LangGraph`, `Claude Agent SDK`, `OpenAI Agents SDK`, and `OpenHands` adapters |

---

## Quickstart & Verification

```sh
# 1. Build and sign macOS Virtualization.framework helper (Apple Silicon macOS)
sh "macos/airlock-vz-helper/build.sh"
"macos/airlock-vz-helper/bin/airlock-vz-helper" --probe --json

# 2. Run Rust workspace unit tests (all 7 crates)
cargo test --workspace

# 3. Run Phase 0 (M0) CoW, framing, HMAC, and Commit Gate benchmarks
cargo run --release -p airlockd --example m0_spike_bench

# 4. Run CLI diagnostics (supports --json, --plain, NO_COLOR=1)
cargo run -p airlock-cli -- doctor --plain

# 5. Run Python SDK & harness adapter tests
python3 -m unittest discover -s "sdks/python/tests" -t "sdks/python" -v
```

---

## Workspace Directory Rename Notice (`D-10` / `C9`)

This directory currently includes a trailing space (`Airlock `). After closing the active session, rename the folder cleanly before pushing to a remote:

```sh
cd ..
mv "Airlock " Airlock
```
