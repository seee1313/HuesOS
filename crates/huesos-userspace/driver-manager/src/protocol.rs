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
/// Init delegates the unique KeyBroker generation-grant channel.
pub const KEY_BROKER_MANAGER: &str = "key-broker:manager-channel";
/// Init delegates the unique `PciConfigMint` authority (AP-8). DriverManager
/// is the only component besides `init` that ever holds it; it mints
/// generation-bound read-only ECAM capabilities for PCI Manager and never
/// duplicates or re-transfers the authority itself.
pub const CONFIG_MINT_AUTHORITY: &str = "pci-config-mint:manager-authority";
/// Init delegates the unique `DeviceLeaseAuthority` capability (AP-20) to
/// DriverManager, which forwards a copy to PCI Manager so it can mint
/// kernel-enforced `DeviceLease` handles.
pub const DEVICE_LEASE_AUTHORITY: &str = "pci-lease-auth";
/// DriverManager passes the archive to the isolated ACPI manager.
pub const ACPI_MANAGER_TABLES: &str = "acpi-tables-vmo";
/// DriverManager passes the unique broker capability to the ACPI manager.
pub const ACPI_MANAGER_BROKER: &str = "acpi-broker";
/// DriverManager passes the child process's own root VMAR capability.
pub const ACPI_MANAGER_SELF_VMAR: &str = "acpi-self-vmar";
/// ACPI manager transfers the validated `HMCF` config-window snapshot
/// with this label. The VMO carries `READ | DUPLICATE | TRANSFER` rights
/// only; DriverManager validates the envelope/size/generation and
/// retains it immutably for the current manager generation.
pub const ACPI_MANAGER_HMCF: &str = "acpi-hmcf-vmo";
/// Client asks DriverManager to open FileSystemService.
pub const OPEN_FILESYSTEM: &str = "open:filesystem";
/// Client asks DriverManager to open DevFS.
pub const OPEN_DEVFS: &str = "open:devfs";
/// Client asks DriverManager to open BlobFS.
pub const OPEN_BLOBFS: &str = "open:blobfs";
/// DriverManager responds with a FileSystemService channel.
pub const FILESYSTEM_CHANNEL: &str = "service:filesystem:channel";
/// DriverManager responds with a DevFS channel.
pub const DEVFS_CHANNEL: &str = "service:devfs:channel";
/// DevFS is not currently available.
pub const DEVFS_UNAVAILABLE: &str = "err:devfs-unavailable";
/// DriverManager responds with a BlobFS channel.
pub const BLOBFS_CHANNEL: &str = "service:blobfs:channel";
/// BlobFS is not currently mounted/available.
pub const BLOBFS_UNAVAILABLE: &str = "err:blobfs-unavailable";
/// BlobFS returns an opened blob as a VMO handle.
pub const BLOBFS_BLOB_VMO: &str = "service:blobfs:blob-vmo";
/// Client asks DriverManager to open Hxfs.
pub const OPEN_HXFS: &str = "open:hxfs";
/// DriverManager responds with an Hxfs service channel.
pub const HXFS_CHANNEL: &str = "service:hxfs:channel";
/// Hxfs is not mounted/available.
pub const HXFS_UNAVAILABLE: &str = "err:hxfs-unavailable";
/// DriverManager passes a filesystem-candidate BlockDevice to Hxfs service.
pub const HXFS_BLOCK_DEVICE: &str = "hxfs:block-device";
/// DriverManager attaches an Hxfs client channel to Hxfs service.
pub const ATTACH_HXFS_CLIENT: &str = "hxfs-client";
/// Hxfs service mounted successfully.
pub const HXFS_READY: &str = "service:hxfs:ready";
/// Hxfs service failed to mount.
pub const HXFS_SERVICE_UNAVAILABLE: &str = "service:hxfs:unavailable";
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
/// Client queries PCI topology/root-bridge/lease summary as TSV text.
pub const QUERY_PCI: &str = "query:pci";
/// Client requests a read-only duplicate of the `HPIN` PCI inventory VMO (Stage D.3).
pub const QUERY_PCI_VMO: &str = "query:pci:vmo";
/// DriverManager replies with a read-only `HPIN` PCI inventory VMO handle.
pub const PCI_INVENTORY_VMO_REPLY: &str = "service:pci:inventory-vmo";
/// DriverManager replies when the `HPIN` PCI inventory VMO is not yet published.
pub const PCI_INVENTORY_UNAVAILABLE: &str = "err:pci-inventory-unavailable";
/// Client queries ACPI archive/manager summary as TSV text.
pub const QUERY_ACPI: &str = "query:acpi";
/// Client queries DriverManager-supervised processes and services as TSV text.
pub const QUERY_PS: &str = "query:ps";
/// Client requests a dedicated read-only query channel (`query:pci`/`acpi`/`ps`).
pub const OPEN_QUERY: &str = "open:query";
/// DriverManager returns a read-only query channel handle.
pub const QUERY_CHANNEL: &str = "service:query:channel";
/// Client asks DriverManager to open a full-access (`net=rw`) `net-service` channel.
pub const OPEN_NET: &str = "open:net";
/// Client asks DriverManager to open a read-only (`net=ro`) `net-service` channel.
pub const OPEN_NET_RO: &str = "open:net:ro";
/// DriverManager responds with a `net-service` channel.
pub const NET_CHANNEL: &str = "service:net:channel";
/// `net-service` is not currently available.
pub const NET_UNAVAILABLE: &str = "err:net-unavailable";
/// DriverManager attaches a RW client channel to `net-service`.
pub const ATTACH_NET_CLIENT: &str = "net-client";
/// DriverManager attaches a RO client channel to `net-service`.
pub const ATTACH_NET_CLIENT_RO: &str = "net-client:ro";
/// `net-service` reported ready.
pub const NET_READY: &str = "service:net:ready";
/// Client asks DriverManager to open an admin (`wlan=admin`) `wlan-service` channel.
pub const OPEN_WLAN: &str = "open:wlan";
/// Client asks DriverManager to open a read-only (`wlan=ro`) `wlan-service` channel.
pub const OPEN_WLAN_RO: &str = "open:wlan:ro";
/// DriverManager responds with a `wlan-service` channel.
pub const WLAN_CHANNEL: &str = "service:wlan:channel";
/// `wlan-service` is not currently available.
pub const WLAN_UNAVAILABLE: &str = "err:wlan-unavailable";
/// DriverManager attaches an admin client channel to `wlan-service`.
pub const ATTACH_WLAN_CLIENT: &str = "wlan-client";
/// DriverManager attaches a RO client channel to `wlan-service`.
pub const ATTACH_WLAN_CLIENT_RO: &str = "wlan-client:ro";
/// `wlan-service` reported ready.
pub const WLAN_READY: &str = "service:wlan:ready";

/// Client asks DriverManager to open the USB HID mouse service.
pub const OPEN_MOUSE: &str = "open:mouse";
/// DriverManager responds with a mouse service channel.
pub const MOUSE_CHANNEL: &str = "service:mouse:channel";
/// Mouse service is not currently available.
pub const MOUSE_UNAVAILABLE: &str = "err:mouse-unavailable";
/// DriverManager attaches a mouse client channel to `driver-host-xhci`.
pub const ATTACH_MOUSE_CLIENT: &str = "mouse-client";

/// Client asks DriverManager to open the USB BOT async BlockDevice service.
pub const OPEN_BLOCK_USB: &str = "open:block:usb";
/// DriverManager responds with a USB BOT BlockDevice service channel.
pub const BLOCK_USB_CHANNEL: &str = "service:block:usb:channel";
/// USB BOT BlockDevice service is not currently online.
pub const BLOCK_USB_UNAVAILABLE: &str = "err:block:usb-unavailable";
/// DriverManager attaches a USB BOT block client channel to `driver-host-xhci`.
pub const ATTACH_BLOCK_USB_CLIENT: &str = "block:usb-client";

/// xHCI DriverHost reported it is starting.
pub const XHCI_HOST_STARTING: &str = "driver-host:xhci:starting";
/// xHCI DriverHost has received its MMIO/IRQ/DMA resources.
pub const XHCI_HOST_RESOURCES_READY: &str = "driver-host:xhci:resources-ready";
/// xHCI DriverHost reported ready.
pub const XHCI_HOST_READY: &str = "driver-host:xhci:ready";
/// xHCI DriverHost USB HID input service is ready.
pub const USB_HID_READY: &str = "service:usb:hid:ready";
/// xHCI DriverHost USB BOT block service is ready.
pub const BLOCK_USB_READY: &str = "service:block:usb:ready";
/// xHCI DriverHost bring-up failed.
pub const USB_BRINGUP_FAILED: &str = "service:usb:bringup-failed";
/// xHCI DriverHost missing required resources.
pub const USB_MISSING_RESOURCES: &str = "service:usb:missing-resources";
/// xHCI DriverHost observed `PORT_PACKET_DEVICE_GONE`.
pub const USB_DEVICE_GONE: &str = "service:usb:device-gone";
/// xHCI DriverHost published a read-only `HUSB` inventory VMO.
pub const USB_INVENTORY_VMO_UPDATE: &str = "service:usb:inventory-vmo";
/// DriverManager asks `driver-host-xhci` to refresh its `HUSB` inventory VMO.
pub const USB_REFRESH_VMO: &str = "usb:refresh-vmo";

/// Client queries USB controller & attached device inventory as TSV text.
pub const QUERY_USB: &str = "query:usb";
/// Client requests a read-only duplicate of the `HUSB` USB inventory VMO.
pub const QUERY_USB_VMO: &str = "query:usb:vmo";
/// DriverManager replies with a read-only `HUSB` USB inventory VMO handle.
pub const USB_INVENTORY_VMO_REPLY: &str = "service:usb:inventory-vmo";
/// DriverManager replies when no `HUSB` USB inventory VMO is published.
pub const USB_INVENTORY_UNAVAILABLE: &str = "err:usb-inventory-unavailable";
