//! Capability-gated one-shot boot volume-key handoff.
//!
//! Only a process holding a `ResourceKind::VolumeKey` handle can move the key
//! out of the kernel. Init mints that unique binary capability and transfers it
//! to KeyBroker. The kernel slot becomes `None` after a successful copy, so an
//! application cannot retrieve the key through ambient syscall authority.

use crate::user_memory;
use crate::SyscallResult;
use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::ResourceKind;

pub(crate) fn sys_volume_key_take(
    resource_handle: HandleValue,
    out: *mut [u8; 32],
) -> SyscallResult {
    // Validate capability and output before consuming the one-shot secret.
    let authority =
        crate::resource::require_resource_of_kind(resource_handle, ResourceKind::VolumeKey)?;
    user_memory::validate_write(out)?;

    let mut key = huesos_object::boot_key::take_boot_volume_key().ok_or(ErrorCode::NotFound)?;
    let result = user_memory::copy_to_user(out.cast::<u8>(), &key);
    if let Err(error) = result {
        // A recoverable copy fault must not burn the only key. Restore before
        // clearing the local stack copy; a pre-existing value would be an
        // internal state violation and is deliberately reported as Internal.
        let restore = huesos_object::boot_key::restore_boot_volume_key(key);
        clear_secret(&mut key);
        drop(authority);
        return match restore {
            Ok(()) => Err(error),
            Err(mut duplicate) => {
                clear_secret(&mut duplicate);
                Err(ErrorCode::Internal)
            }
        };
    }

    clear_secret(&mut key);
    drop(authority);
    Ok(0)
}

fn clear_secret(secret: &mut [u8]) {
    for byte in secret {
        *byte = 0;
        let _ = core::hint::black_box(*byte);
    }
}
