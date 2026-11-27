//! Ring-3 hotplug trigger syscall (Stage M.2).
//!
//! The kernel does not interpret this operation as a PCI authority grant. It
//! only validates a bounded event and writes it to a channel capability owned
//! by the caller. DriverManager creates that private channel and gives its
//! peer to `pci-manager`; a test process can therefore exercise the complete
//! userspace path without a cmdline-only shortcut or a kernel PCI rescan.

use huesos_abi::{pci_hotplug::PciHotplugTriggerArgs, ErrorCode, HandleValue};

use crate::{channel, user_memory, SyscallResult};

/// Copy and validate one ring-3 trigger argument, then enqueue its event on
/// the supplied channel endpoint.
pub(crate) fn sys_pci_hotplug_trigger(args: *const PciHotplugTriggerArgs) -> SyscallResult {
    let raw = user_memory::copy_from_user(
        args.cast::<u8>(),
        core::mem::size_of::<PciHotplugTriggerArgs>(),
    )?;
    if raw.len() != core::mem::size_of::<PciHotplugTriggerArgs>() {
        return Err(ErrorCode::InvalidArgs);
    }

    let channel_bytes = raw
        .get(0..core::mem::size_of::<HandleValue>())
        .ok_or(ErrorCode::InvalidArgs)?;
    let channel = u32::from_le_bytes(
        channel_bytes
            .try_into()
            .map_err(|_| ErrorCode::InvalidArgs)?,
    );
    let reserved = raw.get(4..8).ok_or(ErrorCode::InvalidArgs)?;
    if reserved.iter().any(|byte| *byte != 0) {
        return Err(ErrorCode::InvalidArgs);
    }
    let event = raw.get(8..).ok_or(ErrorCode::InvalidArgs)?;
    let decoded =
        huesos_abi::pci_hotplug::HotplugWireEvent::decode(event).ok_or(ErrorCode::InvalidArgs)?;
    // A trigger may use either the standard ACPI bus/device check or one of
    // the PCIe presence/eject values. The raw value must still agree with the
    // bounded classification carried by the event.
    if huesos_abi::pci_hotplug::acpi_notify_kind(decoded.notify_value) != Some(decoded.kind) {
        return Err(ErrorCode::InvalidArgs);
    }

    channel::sys_channel_write_kernel_bytes(channel, event)
}
