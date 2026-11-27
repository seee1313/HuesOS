//! Safe wrapper for the Stage M.2 ring-3 PCI hotplug trigger.

use crate::{raw, Channel, Result};
use huesos_abi::pci_hotplug::{HotplugWireEvent, PciHotplugTriggerArgs};
use huesos_abi::Syscall;

/// Submit one bounded hotplug event to the peer owned by `pci-manager`.
///
/// The channel is intentionally borrowed: the syscall only writes a copy of
/// the event and never transfers or closes the endpoint. A caller without a
/// write-capable private channel can still construct the argument in memory,
/// but the kernel rejects it before queueing anything.
pub fn trigger(channel: &Channel, event: HotplugWireEvent) -> Result<()> {
    let args = PciHotplugTriggerArgs::new(channel.handle().raw(), event);
    raw::decode(raw::syscall1(
        Syscall::PciHotplugTrigger,
        &args as *const PciHotplugTriggerArgs as u64,
    ))
    .map(|_| ())
}
