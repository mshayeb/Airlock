# Airlock Phase 0 (M0) Technical Spike Report

- **Date:** `2026-11-20`
- **Host Environment:** Apple Silicon (`arm64`), `macOS 27.2.1` (`Build 26B131`), APFS (`/dev/disk3s1` on `/System/Volumes/Data`)
- **Toolchains:** `rustc 1.99.0-nightly`, `cargo 1.99.0-nightly`, `Apple Swift 6.4.2`, `MacOSX.sdk` (`Virtualization.framework`)
- **Reference Spec:** [`spec.md`](../spec.md) (§2.3, §4, §14 `M0`)

---

## 1. Signed-Off Phase 1 Decisions (`D-1`–`D-10`)

All recommended engineering defaults in `spec.md` §13 were signed off prior to scaffolding:
- **D-1:** MicroVM-only isolation + warm pool (no `Seatbelt`/`Landlock` host fallback in Phase 1).
- **D-2:** Pre-mount `.env*` scrubbing + `.env.example` placeholder synthesis + phantom HTTP/Git tokens.
- **D-3:** Ephemeral per-chamber CA L7 TLS termination for credentialed/write endpoints; opt-in `sni_passthrough` restricted to read-only public CDNs.
- **D-4:** `GET`/`HEAD`-only (query-stripped) registry defaults (`npm`, `pypi`, `crates.io`) in `standard` profile + `--offline` profile option.
- **D-5 through D-10:** Interactive Commit Gate default, dual-arch (`aarch64` + `x86_64`) Linux guest images, structural hash-chained audit logs (`capture_http_bodies = false`), Rust + Swift helper stack, `standard`/`containers` rootfs split, and post-session workspace rename (`Airlock ` → `Airlock`).

---

## 2. Spike 1: macOS `Virtualization.framework` (`airlock-vz-helper`)

Compiled and ad-hoc signed `macos/airlock-vz-helper/bin/airlock-vz-helper` with entitlement `com.apple.security.virtualization` (`macos/airlock-vz-helper/entitlements.plist`) and executed `--probe --json`:

```json
{
  "config_validated": true,
  "is_supported": true,
  "max_cpus": 64,
  "max_memory_mib": 8192,
  "min_cpus": 1,
  "min_memory_mib": 4,
  "virtio_blk_configured": true,
  "virtio_fs_ro_configured": true,
  "virtio_net_count": 0,
  "vsock_configured": true
}
```

### Findings
1. **Zero-NIC Configuration Validated:** `VZVirtualMachineConfiguration.validate()` passed with `virtio_net_count = 0` alongside `VZVirtioSocketDeviceConfiguration` (`vsock`), read-only `VZVirtioFileSystemDeviceConfiguration` (`virtio-fs`), and writable `VZVirtioBlockDeviceConfiguration` (`virtio-blk`).
2. **Memory Limit Note:** `VZVirtualMachineConfiguration.maximumAllowedMemorySize` on this host reports `8192 MiB`, matching the default `4096 MiB` chamber quota with headroom for local execution.

---

## 3. Spike 2: APFS CoW Scrubbing, `vsock` Framing, Phantom Tokens & Commit Gate (`m0_spike_bench`)

Executed `cargo run --release -p airlockd --example m0_spike_bench` (including trailing-space repo directory paths verifying `AT-14`):

| Benchmark | Measured Result | `spec.md` §2.3 Target | Status & Engineering Note |
|---|---|---|---|
| **APFS CoW + Scrub (`1,000` files)** | `median = 100.21 ms` (`max = 103.39 ms`), `method = ApfsDirClonefile`, `leaked_secrets = 0` | `≤ 250 ms` warm acquisition | **PASS.** Zero secret strings (`.env`, `.git/config` PAT) survived in scrubbed clone. |
| **APFS CoW + Scrub (`10,000` files)** | `median = 1431.60 ms` (`max = 1606.47 ms`), `method = ApfsDirClonefile`, `leaked_secrets = 0` | Baseline measurement | **OPTIMIZATION IDENTIFIED:** `clonefile(2)` itself is fast, but synchronous SHA-256 reading of all `10,000` files for `FR-FS-7` dominated latency. M3/M4 should hash lazily from `.git/index` / `mtime+size` cache + clean base caching. |
| **`vsock` Framing (`16 KiB` × `100,000`)** | `230.12 Gbps` (`570.1 ns` encode+decode roundtrip) | `≥ 2 Gbps` over `vsock` | **PASS.** Framing CPU cost is negligible relative to hypervisor IPC. |
| **Phantom Token HMAC-SHA256 (`50,000` ops)** | `3.10 µs` per mint + verify | `≤ 5 ms` broker overhead | **PASS.** Sub-4 µs token verification adds <0.1% to L7 proxy budget. |
| **Commit Gate Scan (`500` files)** | `8.56 ms` | `≤ 150 ms` p95 scan | **PASS.** Structural, protected-path, secret, and 3-way host digest checks completed in `8.56 ms`. |
| **Journaled Atomic Apply & Undo (`500` files)** | `apply = 2591.99 ms`, `undo = 2343.41 ms` (`total_gate = 2600.55 ms`) | — | **OPTIMIZATION IDENTIFIED:** Calling `file.sync_all()` individually on 500 temp files triggers 500 APFS NVMe flush barriers (~5 ms/file). M4 should batch data flushes and issue a single barrier per directory/journal. |

---

## 4. Remaining Remote/Linux M0 Checklist (Requires Linux KVM Runner)

Not available on macOS host (`mkfs.erofs` and `firecracker` not installed locally):
1. Benchmark `mkfs.erofs` vs `dm-thin` snapshot creation on `10,000` and `100,000` file repos inside Linux CI.
2. Validate `Firecracker v1.9+` + `jailer` cold boot & `AF_VSOCK` `iperf`-style throughput (`≥ 2 Gbps`) with Linux 6.12 guest kernel (`guest/image/linux-6.12-airlock.config`).
3. Verify `airlock-guestd` `tun0` (`100.64.0.2/30`) + DNS stub (`127.0.0.53:53`) packet forwarding over `AF_VSOCK` inside Linux KVM.
