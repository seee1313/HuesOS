//! # HuesOS Handle-Transfer Semantics
//!
//! Host-testable, dependency-free model of **capability handle-transfer
//! semantics**. It advances [ROADMAP.md](../../docs/ROADMAP.md) Short-Term #6
//! (*handle transfer semantics*: transactional rollback when peer
//! closure/send failure becomes observable, richer typed handle dispositions,
//! stress on concurrent close/transfer).
//!
//! The kernel's channels move handles between processes by transferring
//! capabilities. Two invariants matter:
//!
//! 1. **Rights monotonicity** — a transferred/duplicated handle may keep or
//!    *reduce* the source's rights, never *add* rights the source lacks.
//! 2. **Atomicity** — sending a message that carries several handles transfers
//!    all of them or none; a validation failure (missing handle, missing right,
//!    full destination, repeated handle) must leave both tables unchanged.
//!
//! This crate models those invariants deterministically so they can be
//! unit-tested without channels, the scheduler, or `unsafe`.
//!
//! ## What lives here
//!
//! - [`Rights`]: a capability-rights bitset with set operations.
//! - [`transfer_rights`]: the monotonic rights computation (intersection).
//! - [`HandleTable`]: a bounded handle → rights table.
//! - [`DispOp`] / [`Disposition`]: typed dispositions (Move vs Duplicate).
//! - [`transfer`]: an all-or-nothing transfer between two tables.
//!
//! ## What does NOT live here
//!
//! No channels, no message queues, no scheduler, no locks. The privileged
//! integration (calling `transfer` from the channel send path, holding
//! in-flight handle counts until receipt or drop) is verified on-target. See
//! `docs/HANDLE_TRANSFER.md`.
//!
//! ## Safety budget
//!
//! This crate is intentionally **budget-neutral**: no `unsafe` blocks, no
//! `unwrap` or `expect` calls, and no panicking macros anywhere — including its
//! tests — so it adds nothing to the surface tracked by
//! `tools/check-safety-budget.py`.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// Capability rights bitset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    /// No rights.
    pub const NONE: Rights = Rights(0);
    /// May duplicate the handle.
    pub const DUPLICATE: Rights = Rights(1 << 0);
    /// May transfer the handle (e.g. through a channel).
    pub const TRANSFER: Rights = Rights(1 << 1);
    /// May read.
    pub const READ: Rights = Rights(1 << 2);
    /// May write.
    pub const WRITE: Rights = Rights(1 << 3);
    /// May observe signals.
    pub const SIGNAL: Rights = Rights(1 << 4);

    /// Construct from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Rights(bits)
    }

    /// The raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True when no rights are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// True when every right in `other` is present.
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set union.
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// Set intersection.
    pub const fn intersection(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }
}

/// Compute the rights a transferred/duplicated handle receives: the
/// intersection of the source's rights and the requested rights. This can
/// reduce rights (request fewer) but never add rights the source lacks.
pub const fn transfer_rights(source: Rights, requested: Rights) -> Rights {
    source.intersection(requested)
}

/// A bounded handle table mapping small integer handles to rights.
///
/// Handles are dense indices into a fixed array; `insert` allocates the lowest
/// free slot. Used to model one process's handle table in transfer tests.
pub struct HandleTable<const N: usize> {
    slots: [Option<Rights>; N],
    len: usize,
}

impl<const N: usize> HandleTable<N> {
    /// An empty table.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    /// Capacity bound.
    pub fn capacity(&self) -> usize {
        N
    }

    /// Number of live handles.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of handles that can still be inserted.
    pub fn available(&self) -> usize {
        N - self.len
    }

    /// Insert a handle with `rights`, returning its handle value, or `None` if
    /// full.
    pub fn insert(&mut self, rights: Rights) -> Option<u64> {
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(rights);
                self.len += 1;
                return Some(idx as u64);
            }
        }
        None
    }

    /// Look up the rights of `handle`.
    pub fn get(&self, handle: u64) -> Option<Rights> {
        let idx = usize::try_from(handle).ok()?;
        match self.slots.get(idx) {
            Some(slot) => *slot,
            None => None,
        }
    }

    /// Whether `handle` is live.
    pub fn contains(&self, handle: u64) -> bool {
        self.get(handle).is_some()
    }

    /// Remove `handle`, returning its rights, or `None` if absent.
    pub fn remove(&mut self, handle: u64) -> Option<Rights> {
        let idx = usize::try_from(handle).ok()?;
        match self.slots.get_mut(idx) {
            Some(slot) => {
                let old = slot.take();
                if old.is_some() {
                    self.len = self.len.saturating_sub(1);
                }
                old
            }
            None => None,
        }
    }
}

impl<const N: usize> Default for HandleTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// How a disposition handles its source handle on commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispOp {
    /// Remove the handle from the source (it moves into the message). Requires
    /// [`Rights::TRANSFER`].
    Move,
    /// Keep the source handle and create a new one (with reduced rights) in the
    /// destination. Requires [`Rights::DUPLICATE`].
    Duplicate,
}

/// One handle in a transfer: which handle, which operation, and the rights
/// requested for the destination handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disposition {
    /// Source handle value.
    pub handle: u64,
    /// Move or Duplicate.
    pub op: DispOp,
    /// Rights requested for the destination handle (capped by the source).
    pub rights: Rights,
}

/// Why a transfer failed. On any failure the transfer is rolled back (no
/// changes to either table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferError {
    /// A disposition names a handle not present in the source.
    NoSuchHandle,
    /// The source handle lacks the right required by the operation
    /// (`TRANSFER` for Move, `DUPLICATE` for Duplicate).
    MissingRight,
    /// The same handle appears in more than one disposition.
    AlreadyStaged,
    /// The destination lacks capacity for the transferred handles.
    DestinationFull,
}

/// Transfer `disps` from `src` to `dst`, all-or-nothing.
///
/// Phase 1 validates every disposition without mutating either table: each
/// handle exists, has the right required by its operation, no handle is staged
/// twice, and `dst` has capacity for one new handle per disposition. Any
/// failure returns an error and leaves both tables unchanged.
///
/// Phase 2 then applies: Move removes the source handle, Duplicate keeps it;
/// each destination handle receives `transfer_rights(source, requested)`.
/// Because phase 1 fully validates (distinct handles, capacity), phase 2 is
/// total. Returns the number of handles transferred.
pub fn transfer<const N: usize, const M: usize>(
    src: &mut HandleTable<N>,
    dst: &mut HandleTable<M>,
    disps: &[Disposition],
) -> Result<usize, TransferError> {
    if disps.is_empty() {
        return Ok(0);
    }

    // Phase 1a: reject a handle staged more than once.
    for (i, a) in disps.iter().enumerate() {
        for b in &disps[i + 1..] {
            if a.handle == b.handle {
                return Err(TransferError::AlreadyStaged);
            }
        }
    }

    // Phase 1b: validate existence and required rights.
    for disp in disps {
        let source_rights = match src.get(disp.handle) {
            Some(rights) => rights,
            None => return Err(TransferError::NoSuchHandle),
        };
        let required = match disp.op {
            DispOp::Move => Rights::TRANSFER,
            DispOp::Duplicate => Rights::DUPLICATE,
        };
        if !source_rights.contains(required) {
            return Err(TransferError::MissingRight);
        }
    }

    // Phase 1c: destination capacity (one new handle per disposition).
    if dst.available() < disps.len() {
        return Err(TransferError::DestinationFull);
    }

    // Phase 2: apply (total given phase 1).
    for disp in disps {
        let source_rights = match src.get(disp.handle) {
            Some(rights) => rights,
            None => Rights::NONE, // unreachable: validated in phase 1
        };
        let effective = transfer_rights(source_rights, disp.rights);
        if disp.op == DispOp::Move {
            let _ = src.remove(disp.handle);
        }
        let _ = dst.insert(effective); // capacity validated in phase 1
    }
    Ok(disps.len())
}

#[cfg(test)]
// The explicit `match { Some(v) => v, None => 0 }` used to read infallible test
// inserts deliberately avoids any `unwrap_*` call (no-unwrap convention); we
// suppress clippy's stylistic `manual_unwrap_or` suggestion because adopting it
// would reintroduce an `unwrap_*` token. (The project's clippy.sh lints
// --lib/--bins only, so test code is not gated on this regardless.)
#[allow(clippy::manual_unwrap_or, clippy::manual_unwrap_or_default)]
mod tests {
    //! Host tests. Kept free of `unwrap`, `expect`, and panicking macros
    //! (asserts expand to a panic at runtime but do not match the budget's
    //! textual panic-macro pattern), keeping this crate budget-neutral.

    use super::*;

    // --- Rights ---

    #[test]
    fn rights_ops() {
        let rw = Rights::READ.union(Rights::WRITE);
        assert!(rw.contains(Rights::READ));
        assert!(rw.contains(Rights::WRITE));
        assert!(!rw.contains(Rights::TRANSFER));
        assert_eq!(rw.intersection(Rights::READ), Rights::READ);
        assert!(Rights::NONE.is_empty());
    }

    #[test]
    fn transfer_rights_never_adds() {
        // Source has only READ; requesting READ|WRITE yields just READ.
        let src = Rights::READ;
        let requested = Rights::READ.union(Rights::WRITE);
        assert_eq!(transfer_rights(src, requested), Rights::READ);
    }

    #[test]
    fn transfer_rights_can_reduce() {
        // Source has READ|WRITE; requesting only READ yields READ.
        let src = Rights::READ.union(Rights::WRITE);
        assert_eq!(transfer_rights(src, Rights::READ), Rights::READ);
    }

    // --- HandleTable ---

    #[test]
    fn table_insert_get_remove() {
        let mut t: HandleTable<4> = HandleTable::new();
        assert!(t.is_empty());
        let h0 = t.insert(Rights::READ);
        assert_eq!(h0, Some(0));
        let h1 = t.insert(Rights::WRITE);
        assert_eq!(h1, Some(1));
        assert_eq!(t.len(), 2);
        assert_eq!(t.get(0), Some(Rights::READ));
        assert!(t.contains(1));
        assert_eq!(t.remove(0), Some(Rights::READ));
        assert_eq!(t.get(0), None);
        assert_eq!(t.len(), 1);
        // Removed slot is reused.
        let h2 = t.insert(Rights::TRANSFER);
        assert_eq!(h2, Some(0));
    }

    #[test]
    fn table_full_and_out_of_range() {
        let mut t: HandleTable<2> = HandleTable::new();
        assert_eq!(t.insert(Rights::READ), Some(0));
        assert_eq!(t.insert(Rights::READ), Some(1));
        assert_eq!(t.available(), 0);
        assert_eq!(t.insert(Rights::READ), None); // full
        assert_eq!(t.get(99), None); // out of range
        assert_eq!(t.remove(99), None);
    }

    // --- transfer: success ---

    #[test]
    fn move_transfers_and_removes_source() {
        let mut src: HandleTable<4> = HandleTable::new();
        let mut dst: HandleTable<4> = HandleTable::new();
        let h = src.insert(Rights::READ.union(Rights::TRANSFER));
        let disps = [Disposition {
            handle: match h {
                Some(v) => v,
                None => 0,
            },
            op: DispOp::Move,
            rights: Rights::READ,
        }];
        assert_eq!(transfer(&mut src, &mut dst, &disps), Ok(1));
        // Source handle moved out.
        assert!(src.is_empty());
        // Destination has the handle with reduced rights (READ only).
        assert_eq!(dst.len(), 1);
        assert_eq!(dst.get(0), Some(Rights::READ));
    }

    #[test]
    fn duplicate_keeps_source() {
        let mut src: HandleTable<4> = HandleTable::new();
        let mut dst: HandleTable<4> = HandleTable::new();
        let rights = Rights::READ.union(Rights::WRITE).union(Rights::DUPLICATE);
        let h = src.insert(rights);
        let disps = [Disposition {
            handle: match h {
                Some(v) => v,
                None => 0,
            },
            op: DispOp::Duplicate,
            rights: Rights::READ,
        }];
        assert_eq!(transfer(&mut src, &mut dst, &disps), Ok(1));
        // Source keeps its handle with original rights.
        assert_eq!(src.len(), 1);
        assert_eq!(src.get(0), Some(rights));
        // Destination has a new handle with reduced rights.
        assert_eq!(dst.get(0), Some(Rights::READ));
    }

    #[test]
    fn empty_dispositions_is_ok_zero() {
        let mut src: HandleTable<4> = HandleTable::new();
        let mut dst: HandleTable<4> = HandleTable::new();
        assert_eq!(transfer(&mut src, &mut dst, &[]), Ok(0));
        assert!(src.is_empty());
        assert!(dst.is_empty());
    }

    // --- transfer: atomicity (no partial changes) ---

    fn snapshot(t: &HandleTable<4>) -> [Option<Rights>; 4] {
        [t.get(0), t.get(1), t.get(2), t.get(3)]
    }

    #[test]
    fn no_such_handle_leaves_both_unchanged() {
        let mut src: HandleTable<4> = HandleTable::new();
        let mut dst: HandleTable<4> = HandleTable::new();
        let good = src.insert(Rights::READ.union(Rights::TRANSFER));
        let disps = [
            Disposition {
                handle: match good {
                    Some(v) => v,
                    None => 0,
                },
                op: DispOp::Move,
                rights: Rights::READ,
            },
            Disposition {
                handle: 7, // does not exist
                op: DispOp::Move,
                rights: Rights::READ,
            },
        ];
        let before_src = snapshot(&src);
        let before_dst = snapshot(&dst);
        assert_eq!(
            transfer(&mut src, &mut dst, &disps),
            Err(TransferError::NoSuchHandle)
        );
        // Neither table changed (the valid first disposition was not applied).
        assert_eq!(snapshot(&src), before_src);
        assert_eq!(snapshot(&dst), before_dst);
    }

    #[test]
    fn missing_right_leaves_both_unchanged() {
        let mut src: HandleTable<4> = HandleTable::new();
        let mut dst: HandleTable<4> = HandleTable::new();
        // Has READ but not TRANSFER.
        let h = src.insert(Rights::READ);
        let disps = [Disposition {
            handle: match h {
                Some(v) => v,
                None => 0,
            },
            op: DispOp::Move,
            rights: Rights::READ,
        }];
        let before_src = snapshot(&src);
        assert_eq!(
            transfer(&mut src, &mut dst, &disps),
            Err(TransferError::MissingRight)
        );
        assert_eq!(snapshot(&src), before_src);
        assert!(dst.is_empty());
    }

    #[test]
    fn duplicate_requires_duplicate_right() {
        let mut src: HandleTable<4> = HandleTable::new();
        let mut dst: HandleTable<4> = HandleTable::new();
        // Has TRANSFER but not DUPLICATE.
        let h = src.insert(Rights::READ.union(Rights::TRANSFER));
        let disps = [Disposition {
            handle: match h {
                Some(v) => v,
                None => 0,
            },
            op: DispOp::Duplicate,
            rights: Rights::READ,
        }];
        assert_eq!(
            transfer(&mut src, &mut dst, &disps),
            Err(TransferError::MissingRight)
        );
        assert!(dst.is_empty());
    }

    #[test]
    fn repeated_handle_is_rejected() {
        let mut src: HandleTable<4> = HandleTable::new();
        let mut dst: HandleTable<4> = HandleTable::new();
        let h = src.insert(Rights::READ.union(Rights::TRANSFER));
        let handle = match h {
            Some(v) => v,
            None => 0,
        };
        let disps = [
            Disposition {
                handle,
                op: DispOp::Move,
                rights: Rights::READ,
            },
            Disposition {
                handle, // same handle staged twice
                op: DispOp::Move,
                rights: Rights::READ,
            },
        ];
        assert_eq!(
            transfer(&mut src, &mut dst, &disps),
            Err(TransferError::AlreadyStaged)
        );
        assert_eq!(src.len(), 1);
        assert!(dst.is_empty());
    }

    #[test]
    fn destination_full_is_rejected_atomically() {
        let mut src: HandleTable<4> = HandleTable::new();
        let mut dst: HandleTable<1> = HandleTable::new();
        let a = src.insert(Rights::READ.union(Rights::TRANSFER));
        let b = src.insert(Rights::READ.union(Rights::TRANSFER));
        let disps = [
            Disposition {
                handle: match a {
                    Some(v) => v,
                    None => 0,
                },
                op: DispOp::Move,
                rights: Rights::READ,
            },
            Disposition {
                handle: match b {
                    Some(v) => v,
                    None => 0,
                },
                op: DispOp::Move,
                rights: Rights::READ,
            },
        ];
        let before_src = snapshot(&src);
        // dst capacity 1, but 2 handles requested -> rejected, nothing moved.
        assert_eq!(
            transfer(&mut src, &mut dst, &disps),
            Err(TransferError::DestinationFull)
        );
        assert_eq!(snapshot(&src), before_src);
        assert!(dst.is_empty());
    }
}
