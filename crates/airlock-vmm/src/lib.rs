//! Hypervisor abstraction enforcing `FR-NET-1` (zero `virtio-net` NICs)
//! across Linux Firecracker (`EROFS` + `ext4` + `vsock`) and macOS Apple Silicon
//! (`Virtualization.framework` APFS `virtio-fs` + `ext4` + `vsock`).

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Platform-neutral microVM Chamber launch specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChamberSpec {
    pub chamber_id: String,
    pub vsock_cid: u32,
    pub vsock_uds_path: PathBuf,
    pub kernel_image: PathBuf,
    pub rootfs_image: PathBuf,
    pub lower_workspace: LowerWorkspaceMount,
    pub cow_upper_ext4: PathBuf,
    pub vcpus: u16,
    pub memory_mib: u32,
}

/// Platform-specific read-only scrubbed lower layer (`spec.md` §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LowerWorkspaceMount {
    /// macOS `Virtualization.framework`: APFS clone exported read-only via `virtio-fs`.
    AppleVirtioFs { host_scrubbed_dir: PathBuf, tag: String },
    /// Linux Firecracker (lacks `virtio-fs`): read-only EROFS block device (`/dev/vdb`).
    FirecrackerErofsBlock { erofs_image: PathBuf },
}

/// Errors produced when validating or probing VMM backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmmError {
    InvalidVsockCid(u32),
    ZeroResourceQuota(&'static str),
    IncompatibleLowerMount(&'static str),
    ProbeFailed(String),
}

impl fmt::Display for VmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVsockCid(cid) => {
                write!(f, "guest vsock CID must be >= 3 (got {cid})")
            }
            Self::ZeroResourceQuota(field) => write!(f, "{field} must be > 0"),
            Self::IncompatibleLowerMount(msg) => write!(f, "incompatible lower mount: {msg}"),
            Self::ProbeFailed(msg) => write!(f, "VMM probe failed: {msg}"),
        }
    }
}

impl std::error::Error for VmmError {}

/// Trait implemented by Firecracker and Apple VZ backends.
pub trait HypervisorBackend {
    fn backend_name(&self) -> &'static str;
    fn validate_spec(&self, spec: &ChamberSpec) -> Result<(), VmmError>;
    fn render_launch_descriptor(&self, spec: &ChamberSpec) -> Result<String, VmmError>;
}

/// Linux KVM + Firecracker v1.9+ backend (`spec.md` §4).
pub struct FirecrackerBackend;

impl HypervisorBackend for FirecrackerBackend {
    fn backend_name(&self) -> &'static str {
        "firecracker-kvm"
    }

    fn validate_spec(&self, spec: &ChamberSpec) -> Result<(), VmmError> {
        validate_common(spec)?;
        if !matches!(spec.lower_workspace, LowerWorkspaceMount::FirecrackerErofsBlock { .. }) {
            return Err(VmmError::IncompatibleLowerMount(
                "Firecracker omits virtio-fs; lower layer must be FirecrackerErofsBlock",
            ));
        }
        Ok(())
    }

    fn render_launch_descriptor(&self, spec: &ChamberSpec) -> Result<String, VmmError> {
        self.validate_spec(spec)?;
        let erofs = match &spec.lower_workspace {
            LowerWorkspaceMount::FirecrackerErofsBlock { erofs_image } => erofs_image,
            _ => unreachable!(),
        };
        Ok(format!(
            concat!(
                "{{\n",
                "  \"boot-source\": {{\n",
                "    \"kernel_image_path\": \"{}\",\n",
                "    \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off quiet init=/sbin/airlock-guestd\"\n",
                "  }},\n",
                "  \"drives\": [\n",
                "    {{ \"drive_id\": \"rootfs\", \"path_on_host\": \"{}\", \"is_root_device\": true, \"is_read_only\": true }},\n",
                "    {{ \"drive_id\": \"lower_ro\", \"path_on_host\": \"{}\", \"is_root_device\": false, \"is_read_only\": true }},\n",
                "    {{ \"drive_id\": \"upper_rw\", \"path_on_host\": \"{}\", \"is_root_device\": false, \"is_read_only\": false }}\n",
                "  ],\n",
                "  \"machine-config\": {{ \"vcpu_count\": {}, \"mem_size_mib\": {} }},\n",
                "  \"network-interfaces\": [],\n",
                "  \"vsock\": {{ \"guest_cid\": {}, \"uds_path\": \"{}\" }}\n",
                "}}"
            ),
            escape_json_path(&spec.kernel_image),
            escape_json_path(&spec.rootfs_image),
            escape_json_path(erofs),
            escape_json_path(&spec.cow_upper_ext4),
            spec.vcpus,
            spec.memory_mib,
            spec.vsock_cid,
            escape_json_path(&spec.vsock_uds_path),
        ))
    }
}

/// macOS Apple Silicon `Virtualization.framework` backend bridging `airlock-vz-helper`.
pub struct AppleVzBackend;

impl AppleVzBackend {
    /// Invokes `airlock-vz-helper --probe --json` and returns raw JSON hardware report.
    pub fn probe(helper_bin: &Path) -> Result<String, VmmError> {
        let output = Command::new(helper_bin)
            .args(["--probe", "--json"])
            .output()
            .map_err(|e| VmmError::ProbeFailed(format!("failed to execute {}: {e}", helper_bin.display())))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(VmmError::ProbeFailed(format!(
                "exit {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}

impl HypervisorBackend for AppleVzBackend {
    fn backend_name(&self) -> &'static str {
        "apple-virtualization"
    }

    fn validate_spec(&self, spec: &ChamberSpec) -> Result<(), VmmError> {
        validate_common(spec)?;
        if !matches!(spec.lower_workspace, LowerWorkspaceMount::AppleVirtioFs { .. }) {
            return Err(VmmError::IncompatibleLowerMount(
                "AppleVzBackend expects AppleVirtioFs read-only scrubbed clone",
            ));
        }
        Ok(())
    }

    fn render_launch_descriptor(&self, spec: &ChamberSpec) -> Result<String, VmmError> {
        self.validate_spec(spec)?;
        let (dir, tag) = match &spec.lower_workspace {
            LowerWorkspaceMount::AppleVirtioFs { host_scrubbed_dir, tag } => (host_scrubbed_dir, tag),
            _ => unreachable!(),
        };
        Ok(format!(
            concat!(
                "{{\n",
                "  \"chamber_id\": \"{}\",\n",
                "  \"kernel\": \"{}\",\n",
                "  \"rootfs\": \"{}\",\n",
                "  \"virtio_fs_ro\": {{ \"path\": \"{}\", \"tag\": \"{}\" }},\n",
                "  \"cow_upper_ext4\": \"{}\",\n",
                "  \"virtio_net\": false,\n",
                "  \"vsock_cid\": {},\n",
                "  \"vcpus\": {},\n",
                "  \"memory_mib\": {}\n",
                "}}"
            ),
            spec.chamber_id,
            escape_json_path(&spec.kernel_image),
            escape_json_path(&spec.rootfs_image),
            escape_json_path(dir),
            tag,
            escape_json_path(&spec.cow_upper_ext4),
            spec.vsock_cid,
            spec.vcpus,
            spec.memory_mib,
        ))
    }
}

fn validate_common(spec: &ChamberSpec) -> Result<(), VmmError> {
    if spec.vsock_cid < 3 {
        return Err(VmmError::InvalidVsockCid(spec.vsock_cid));
    }
    if spec.vcpus == 0 {
        return Err(VmmError::ZeroResourceQuota("vcpus"));
    }
    if spec.memory_mib == 0 {
        return Err(VmmError::ZeroResourceQuota("memory_mib"));
    }
    Ok(())
}

fn escape_json_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_config_has_zero_network_interfaces_and_ro_lower_block() {
        let spec = ChamberSpec {
            chamber_id: "chmb_test".to_owned(),
            vsock_cid: 5,
            vsock_uds_path: PathBuf::from("/tmp/airlock/chmb_test.vsock"),
            kernel_image: PathBuf::from("/var/lib/airlock/vmlinux"),
            rootfs_image: PathBuf::from("/var/lib/airlock/rootfs.ext4"),
            lower_workspace: LowerWorkspaceMount::FirecrackerErofsBlock {
                erofs_image: PathBuf::from("/tmp/airlock/base.erofs"),
            },
            cow_upper_ext4: PathBuf::from("/tmp/airlock/upper.ext4"),
            vcpus: 2,
            memory_mib: 2048,
        };
        let json = FirecrackerBackend
            .render_launch_descriptor(&spec)
            .expect("valid firecracker json");
        assert!(json.contains("\"network-interfaces\": []"));
        assert!(json.contains("\"drive_id\": \"lower_ro\""));
        assert!(json.contains("\"is_read_only\": true"));
        assert!(json.contains("\"guest_cid\": 5"));
    }

    #[test]
    fn rejects_cid_below_3_and_mismatched_lower_mount() {
        let mut spec = ChamberSpec {
            chamber_id: "chmb_bad".to_owned(),
            vsock_cid: 2,
            vsock_uds_path: PathBuf::from("/tmp/v.sock"),
            kernel_image: PathBuf::from("/k"),
            rootfs_image: PathBuf::from("/r"),
            lower_workspace: LowerWorkspaceMount::AppleVirtioFs {
                host_scrubbed_dir: PathBuf::from("/tmp/base"),
                tag: "workspace".to_owned(),
            },
            cow_upper_ext4: PathBuf::from("/tmp/upper.ext4"),
            vcpus: 2,
            memory_mib: 1024,
        };
        assert_eq!(
            AppleVzBackend.validate_spec(&spec),
            Err(VmmError::InvalidVsockCid(2))
        );
        spec.vsock_cid = 3;
        assert!(matches!(
            FirecrackerBackend.validate_spec(&spec),
            Err(VmmError::IncompatibleLowerMount(_))
        ));
    }
}
