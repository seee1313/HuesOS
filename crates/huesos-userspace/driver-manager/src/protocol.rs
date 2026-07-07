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
