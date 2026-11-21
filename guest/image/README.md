# Airlock Guest Kernel & Rootfs Blueprint (Phase 1)

This directory holds the hardened guest kernel configuration (`linux-6.12-airlock.config`) for both:
- **`aarch64` (`Image`):** Apple Silicon `Virtualization.framework` and AWS Graviton / `arm64` Firecracker hosts (`D-6`).
- **`x86_64` (`vmlinux`):** Standard Intel/AMD Firecracker KVM hosts.

## Phase 1 Hardening Invariants (`SEC-2`, `SEC-7`, `FR-NET-1`)
1. `CONFIG_VIRTIO_NET` is explicitly unset (`# CONFIG_VIRTIO_NET is not set`); all guest egress transits `AF_VSOCK` (`CONFIG_VIRTIO_VSOCKETS=y`) via `airlock-guestd` (`127.0.0.1:3128` proxy + `tun0` capture).
2. `CONFIG_MODULES`, `CONFIG_KEXEC`, `CONFIG_DEVMEM`, and `CONFIG_KALLSYMS` are disabled; `sysctl -w kernel.io_uring_disabled=2` runs during `airlock-guestd` PID-1 init.
3. Images are built reproducibly (`SOURCE_DATE_EPOCH` pinned), signed with detached Ed25519 signatures, and SHA-256 verified by `airlockd` before booting any Chamber (`SLSA Level 3`).

## Rootfs Profiles (`D-9`)
- **`standard` (~120 MiB):** Static musl `airlock-guestd`, busybox/coreutils, `git`, `curl`, `ca-certificates`, Python/Node runtime hooks.
- **`containers` (~450 MiB):** Adds rootless `podman` + `crun` + `slirp4netns` configured to forward container egress through `airlock-guestd`.
