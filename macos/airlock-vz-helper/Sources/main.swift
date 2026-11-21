import Foundation
import Virtualization

struct ProbeReport: Codable {
    let isSupported: Bool
    let minCpus: Int
    let maxCpus: Int
    let minMemoryMiB: UInt64
    let maxMemoryMiB: UInt64
    let vsockConfigured: Bool
    let virtioFsReadOnlyConfigured: Bool
    let virtioBlockConfigured: Bool
    let virtioNetCount: Int
    let configValidated: Bool
    let validationNote: String?

    enum CodingKeys: String, CodingKey {
        case isSupported = "is_supported"
        case minCpus = "min_cpus"
        case maxCpus = "max_cpus"
        case minMemoryMiB = "min_memory_mib"
        case maxMemoryMiB = "max_memory_mib"
        case vsockConfigured = "vsock_configured"
        case virtioFsReadOnlyConfigured = "virtio_fs_ro_configured"
        case virtioBlockConfigured = "virtio_blk_configured"
        case virtioNetCount = "virtio_net_count"
        case configValidated = "config_validated"
        case validationNote = "validation_note"
    }
}

func runProbe() -> Int32 {
    let fm = FileManager.default
    let tmpDir = fm.temporaryDirectory.appendingPathComponent("airlock-vz-probe-\(ProcessInfo.processInfo.processIdentifier)")
    let sharedPath = tmpDir.appendingPathComponent("base")
    let upperImgPath = tmpDir.appendingPathComponent("upper.img")
    let kernelPath = tmpDir.appendingPathComponent("vmlinux-stub")

    defer {
        try? fm.removeItem(at: tmpDir)
    }

    var vsockOk = false
    var virtioFsOk = false
    var virtioBlkOk = false
    var configValidated = false
    var validationNote: String? = nil
    var netCount = -1

    do {
        try fm.createDirectory(at: sharedPath, withIntermediateDirectories: true)
        fm.createFile(atPath: upperImgPath.path, contents: Data(count: 65536))
        fm.createFile(atPath: kernelPath.path, contents: Data(count: 4096))

        let config = VZVirtualMachineConfiguration()
        config.cpuCount = min(2, VZVirtualMachineConfiguration.maximumAllowedCPUCount)
        config.memorySize = max(
            512 * 1024 * 1024,
            VZVirtualMachineConfiguration.minimumAllowedMemorySize
        )
        config.platform = VZGenericPlatformConfiguration()
        config.bootLoader = VZLinuxBootLoader(kernelURL: kernelPath)

        // Phase 1 invariant FR-NET-1: zero virtio-net devices attached.
        config.networkDevices = []
        netCount = config.networkDevices.count

        // vsock channel (`VZVirtioSocketDeviceConfiguration`).
        let vsock = VZVirtioSocketDeviceConfiguration()
        config.socketDevices = [vsock]
        vsockOk = config.socketDevices.count == 1

        // Read-only scrubbed workspace via APFS clone + virtio-fs.
        let sharedDir = VZSharedDirectory(url: sharedPath, readOnly: true)
        let fsDev = VZVirtioFileSystemDeviceConfiguration(tag: "workspace")
        fsDev.share = VZSingleDirectoryShare(directory: sharedDir)
        config.directorySharingDevices = [fsDev]
        virtioFsOk = config.directorySharingDevices.count == 1

        // Ephemeral CoW upper sparse ext4 block device.
        let blkAttachment = try VZDiskImageStorageDeviceAttachment(url: upperImgPath, readOnly: false)
        let blkDev = VZVirtioBlockDeviceConfiguration(attachment: blkAttachment)
        config.storageDevices = [blkDev]
        virtioBlkOk = config.storageDevices.count == 1

        config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

        do {
            try config.validate()
            configValidated = true
        } catch {
            configValidated = false
            validationNote = error.localizedDescription
        }
    } catch {
        validationNote = error.localizedDescription
    }

    let report = ProbeReport(
        isSupported: VZVirtualMachine.isSupported,
        minCpus: VZVirtualMachineConfiguration.minimumAllowedCPUCount,
        maxCpus: VZVirtualMachineConfiguration.maximumAllowedCPUCount,
        minMemoryMiB: VZVirtualMachineConfiguration.minimumAllowedMemorySize / (1024 * 1024),
        maxMemoryMiB: VZVirtualMachineConfiguration.maximumAllowedMemorySize / (1024 * 1024),
        vsockConfigured: vsockOk,
        virtioFsReadOnlyConfigured: virtioFsOk,
        virtioBlockConfigured: virtioBlkOk,
        virtioNetCount: netCount,
        configValidated: configValidated,
        validationNote: validationNote
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    if let data = try? encoder.encode(report), let text = String(data: data, encoding: .utf8) {
        print(text)
    }
    return report.isSupported ? 0 : 2
}

let args = CommandLine.arguments
if args.contains("--probe") {
    exit(runProbe())
} else {
    fputs("Usage: airlock-vz-helper --probe --json\n", stderr)
    exit(1)
}
