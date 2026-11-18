//! Safe wrapper for kernel `DeviceLease` syscalls (AP-20 / Stages G.2 + G.3).

use crate::handle::Handle;
use crate::port::Port;
use crate::{raw, Result};
use huesos_abi::pci_lease::{
    DeviceLeaseBindPortArgs, DeviceLeaseCreateArgs, DeviceLeaseInfo, DeviceLeaseMintResourceArgs,
};
use huesos_abi::{HandleValue, ResourceKindAbi, Syscall, INVALID_HANDLE};

/// Create one active `DeviceLease` bound to `(device_id, firmware_snapshot_id, pci_address_packed)`.
pub fn create(
    authority: &Handle,
    device_id: u64,
    firmware_snapshot_id: u64,
    pci_address_packed: u64,
) -> Result<Handle> {
    let args = DeviceLeaseCreateArgs {
        authority: authority.raw(),
        flags: 0,
        device_id,
        firmware_snapshot_id,
        pci_address_packed,
    };
    let mut out: HandleValue = INVALID_HANDLE;
    let ret = raw::syscall2(
        Syscall::DeviceLeaseCreate,
        &args as *const DeviceLeaseCreateArgs as u64,
        &mut out as *mut HandleValue as u64,
    );
    raw::decode(ret)?;
    if out == INVALID_HANDLE {
        return Err(crate::ErrorCode::Internal);
    }
    Ok(Handle::from_syscall_out(out))
}

/// Mint a lease-bound child `Resource` (`IoPort`, `Mmio`, `Irq`, or `DmaPool`)
/// for `expected_generation`.
pub fn mint_resource(
    lease: &Handle,
    kind: ResourceKindAbi,
    expected_generation: u64,
    base: u64,
    len: u64,
    exclusive: bool,
) -> Result<Handle> {
    let args = DeviceLeaseMintResourceArgs {
        lease: lease.raw(),
        kind: kind as u32,
        expected_generation,
        base,
        len,
        exclusive: u32::from(exclusive),
        reserved: 0,
    };
    let mut out: HandleValue = INVALID_HANDLE;
    let ret = raw::syscall2(
        Syscall::DeviceLeaseMintResource,
        &args as *const DeviceLeaseMintResourceArgs as u64,
        &mut out as *mut HandleValue as u64,
    );
    raw::decode(ret)?;
    if out == INVALID_HANDLE {
        return Err(crate::ErrorCode::Internal);
    }
    Ok(Handle::from_syscall_out(out))
}

/// Revoke `expected_generation` of `lease`, invalidating all child resources
/// and delivering `PORT_PACKET_DEVICE_GONE` to bound ports.
pub fn revoke(lease: &Handle, expected_generation: u64, flags: u32) -> Result<u64> {
    let ret = raw::syscall3(
        Syscall::DeviceLeaseRevoke,
        lease.raw() as u64,
        expected_generation,
        u64::from(flags),
    );
    raw::decode(ret).map(|v| v as u64)
}

/// Bind a `Port` to receive `PORT_PACKET_DEVICE_GONE` when `lease` is revoked
/// (or immediately if already revoked).
pub fn bind_gone_port(lease: &Handle, port: &Port, key: u64) -> Result<()> {
    let args = DeviceLeaseBindPortArgs {
        lease: lease.raw(),
        port: port.raw_handle(),
        key,
        flags: 0,
        reserved: 0,
    };
    let ret = raw::syscall1(
        Syscall::DeviceLeaseBindGonePort,
        &args as *const DeviceLeaseBindPortArgs as u64,
    );
    raw::decode(ret).map(|_| ())
}

/// Query current metadata and revocation status of `lease`.
pub fn query(lease: &Handle) -> Result<DeviceLeaseInfo> {
    let mut info = DeviceLeaseInfo::default();
    let ret = raw::syscall2(
        Syscall::DeviceLeaseQuery,
        lease.raw() as u64,
        &mut info as *mut DeviceLeaseInfo as u64,
    );
    raw::decode(ret)?;
    Ok(info)
}
