//! DriverManager bootstrap protocol message constants.

/// DriverHost reported it is starting.
pub const INPUT_HOST_STARTING: &str = "driver-host:input:starting";
/// DriverHost reported all mandatory startup checks passed.
pub const INPUT_HOST_READY: &str = "driver-host:input:ready";
/// Input host keyboard service is ready.
pub const KEYBOARD_SERVICE_READY: &str = "service:keyboard:ready";
/// Input host keyboard service failed.
pub const KEYBOARD_SERVICE_FAILED: &str = "service:keyboard:failed";
/// Input host heartbeat prefix.
pub const INPUT_HEARTBEAT: &str = "heartbeat:input";
/// Generic input host error.
pub const INPUT_HOST_ERROR: &str = "driver-host:input:error";

/// Init passes a DriverManager service registry channel with this message.
pub const REGISTRY_CHANNEL: &str = "registry-channel";
/// Client asks DriverManager to open the keyboard service.
pub const OPEN_KEYBOARD: &str = "open:keyboard";
/// DriverManager responds with a keyboard service channel.
pub const KEYBOARD_CHANNEL: &str = "service:keyboard:channel";
/// DriverManager tells input-host about a new keyboard client channel.
pub const ATTACH_KEYBOARD_CLIENT: &str = "keyboard-client";

/// Init passes the BOOTFS image as a VMO handle with this message.
pub const BOOTFS_VMO: &str = "bootfs-vmo";
/// Init passes the kernel-produced storage boot-info VMO with this message.
pub const STORAGE_BOOT_VMO: &str = "storage-boot-vmo";
/// Init tells DriverManager that every `resource:*` grant for a
/// specific driver has been transferred and DriverManager is now
/// free to spawn that DriverHost. Full label:
/// `manifest:grants-complete:<driver-name>` (e.g.
/// `manifest:grants-complete:input-host`). This closes the race
/// where DM used to start a host as soon as the BOOTFS VMO
/// arrived and then had no handles to forward to it because init
/// was still busy minting them.
pub const MANIFEST_GRANTS_COMPLETE_PREFIX: &str = "manifest:grants-complete:";

/// DriverManager writes this on a DriverHost's bootstrap channel
/// immediately after the last resource handle it forwards, so the
/// child's `consume_manifest_resources` drain loop has a
/// deterministic exit condition instead of relying on the kernel's
/// `WaitSetWait` timeout (which is not honoured today). Sent even
/// when the manifest declared no grants so the child does not need
/// to know that up front.
pub const RESOURCE_TRANSFER_COMPLETE: &str = "resource:transfer-complete";
/// Init passes the immutable ACPI table archive with this message.
pub const ACPI_TABLES_VMO: &str = "acpi-tables-vmo";
/// Init passes the unique deny-by-default ACPI broker capability.
pub const ACPI_BROKER: &str = "acpi-broker";
/// DriverManager passes the archive to the isolated ACPI manager.
pub const ACPI_MANAGER_TABLES: &str = "acpi-tables-vmo";
/// DriverManager passes the unique broker capability to the ACPI manager.
pub const ACPI_MANAGER_BROKER: &str = "acpi-broker";
/// ACPI manager completed archive validation.
pub const ACPI_MANAGER_READY: &str = "acpi-manager:ready";
/// ACPI manager heartbeat.
pub const ACPI_HEARTBEAT: &str = "heartbeat:acpi";
/// Client asks DriverManager to open FileSystemService.
pub const OPEN_FILESYSTEM: &str = "open:filesystem";
/// DriverManager responds with a FileSystemService channel.
pub const FILESYSTEM_CHANNEL: &str = "service:filesystem:channel";
/// Client asks DriverManager to open the NVMe-backed async BlockDevice service.
pub const OPEN_BLOCK_NVME: &str = "open:block:nvme";
/// Client asks DriverManager to open the system volume.
pub const OPEN_VOLUME_SYSTEM: &str = "open:volume:system";
/// DriverManager responds with an NVMe BlockDevice service channel.
pub const BLOCK_NVME_CHANNEL: &str = "service:block:nvme:channel";
/// DriverManager tells NVMe DriverHost about a new block client channel.
pub const ATTACH_BLOCK_NVME_CLIENT: &str = "block:nvme-client";
/// NVMe block service is not currently online.
pub const BLOCK_NVME_UNAVAILABLE: &str = "err:block:nvme-unavailable";
/// DriverManager responds with a system Volume channel.
pub const VOLUME_SYSTEM_CHANNEL: &str = "service:volume:system:channel";
/// System volume is not currently available.
pub const VOLUME_SYSTEM_UNAVAILABLE: &str = "err:volume:system-unavailable";
/// VolumeManager responds with a range-relative BlockDevice channel.
pub const VOLUME_BLOCK_RANGE_CHANNEL: &str = "service:volume:block-range:channel";
/// VolumeManager responds with the first filesystem-candidate BlockDevice channel.
pub const VOLUME_FS_CANDIDATE_CHANNEL: &str = "service:volume:fs-candidate:channel";
/// NVMe DriverHost reported it is starting.
pub const NVME_HOST_STARTING: &str = "driver-host:nvme:starting";
/// NVMe DriverHost has received the Stage-A hardware resources.
pub const NVME_HOST_RESOURCES_READY: &str = "driver-host:nvme:resources-ready";
/// NVMe DriverHost reported its resource set is missing/incomplete.
pub const NVME_HOST_MISSING_RESOURCES: &str = "service:block:nvme:missing-resources";
/// NVMe DriverHost reported ready. In Stage A this means resources are present,
/// not that a real BlockDevice channel is available.
pub const NVME_HOST_READY: &str = "driver-host:nvme:ready";
/// NVMe DriverHost completed Identify Controller/Namespace on target.
pub const NVME_BLOCK_IDENTIFIED: &str = "service:block:nvme:identified";
/// NVMe DriverHost failed controller bring-up after resources mapped.
pub const NVME_BLOCK_BRINGUP_FAILED: &str = "service:block:nvme:bringup-failed";
/// NVMe skeleton compatibility message for resource-only readiness.
pub const NVME_BLOCK_READY: &str = "service:block:nvme:ready";
