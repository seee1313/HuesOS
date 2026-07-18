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
/// Init passes the immutable ACPI table archive with this message.
pub const ACPI_TABLES_VMO: &str = "acpi-tables-vmo";
/// DriverManager passes the archive to the isolated ACPI manager.
pub const ACPI_MANAGER_TABLES: &str = "acpi-tables-vmo";
/// ACPI manager completed archive validation.
pub const ACPI_MANAGER_READY: &str = "acpi-manager:ready";
/// ACPI manager heartbeat.
pub const ACPI_HEARTBEAT: &str = "heartbeat:acpi";
/// Client asks DriverManager to open FileSystemService.
pub const OPEN_FILESYSTEM: &str = "open:filesystem";
/// DriverManager responds with a FileSystemService channel.
pub const FILESYSTEM_CHANNEL: &str = "service:filesystem:channel";
