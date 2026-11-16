//! Safe wrapper for `Syscall::PciConfigMint` (AP-8/AP-9).
//!
//! The kernel mints the unique `PciConfigMint` authority once per boot
//! and installs it in the initial process. `init` delegates that handle
//! to DriverManager; DriverManager then mints generation-bound,
//! read-only config capabilities (one per `huesos_abi::hmcf` record)
//! for the supervised PCI Manager. This module is the safe, typed
//! entry point; it never accepts or produces a physical address.

use crate::handle::Handle;
use crate::{raw, Result};
use huesos_abi::hmcf;
use huesos_abi::pci_config::{self, PciConfigMintRequest};

/// Upper bound on the capabilities one mint call can return.
pub const MAX_CAPABILITIES: usize = hmcf::MAX_RECORDS as usize;

/// Owning set of capabilities returned by one
/// [`mint`] call. Handles are matched to HMCF records in canonical
/// order by the receiver; only the first [`count`] slots are filled.
pub struct MintedConfigCapabilities {
    handles: [Option<Handle>; MAX_CAPABILITIES],
    count: usize,
}

impl MintedConfigCapabilities {
    /// Number of minted capabilities (`==` the HMCF record count for
    /// [`huesos_abi::pci_config::MINT_KIND_ECAM_WINDOWS`]).
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether nothing was minted.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Move the `index`-th capability out of the set (canonical HMCF
    /// record order). Returns `None` past [`len`](Self::len) or when
    /// the slot was already taken.
    pub fn take(&mut self, index: usize) -> Option<Handle> {
        if index >= self.count {
            return None;
        }
        self.handles[index].take()
    }
}

/// Invoke the snapshot-bound mint. `authority` must be the unique
/// `PciConfigMint` handle installed by the kernel at boot (delegated
/// by `init`); any other process gets `AccessDenied` from the kernel.
///
/// `request` binds the HMCF `hmcf_vmo` to the expected producer
/// generation and firmware snapshot identity; the kernel independently
/// re-decodes the image and cross-checks it against the archive-v2
/// MCFG it stashed at boot before minting anything. The call is
/// all-or-nothing: on error no capability escapes this call.
pub fn mint(
    authority: &Handle,
    request: &PciConfigMintRequest,
) -> Result<MintedConfigCapabilities> {
    // Fail closed before the syscall on an obviously stale ABI.
    if request.version != pci_config::MINT_REQUEST_VERSION {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let mut out = [0u32; MAX_CAPABILITIES];
    let ret = raw::syscall4(
        huesos_abi::Syscall::PciConfigMint,
        authority.raw() as u64,
        request as *const PciConfigMintRequest as u64,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    );
    let minted = raw::decode(ret)?;
    if minted as usize > out.len() {
        return Err(crate::ErrorCode::Internal);
    }
    let count = minted as usize;
    let mut handles: [Option<Handle>; MAX_CAPABILITIES] = [const { None }; MAX_CAPABILITIES];
    Handle::fill_kernel_batch(&mut handles, &out[..count]);
    Ok(MintedConfigCapabilities { handles, count })
}
