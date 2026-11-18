//! Host-testable, fail-closed range checks for the proposed Gate B policy.
//!
//! This is policy logic only: it does not derive grants from firmware, mint
//! capabilities, access hardware, or enable any OperationRegion handler. A
//! trusted caller must build the deny set independently of AML, bind it to the
//! same firmware snapshot as the grants, and prove it is complete before using
//! this function for authorization.

/// The two mediated address spaces in the initial Gate B policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Space {
    /// Firmware memory, not ACPI table archive translation.
    Memory,
    /// x86 I/O port space.
    Io,
}

/// Requested access direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Read one value.
    Read,
    /// Write one value.
    Write,
}

/// A half-open range in one address space. Zero-length and overflowing
/// ranges are invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    /// First byte or port.
    pub base: u64,
    /// Length in bytes or ports.
    pub length: u64,
}

impl Range {
    fn end(self) -> Option<u64> {
        if self.length == 0 {
            return None;
        }
        self.base.checked_add(self.length)
    }

    fn overlaps(self, other: Self) -> Option<bool> {
        Some(self.base < other.end()? && other.base < self.end()?)
    }
}

/// Named write class for Gate B write authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteClass {
    /// Fixed FADT power-management / GPE register block.
    FadtPm,
    /// Boot memory-map `ACPI_NVS` region.
    AcpiNvs,
    /// Explicit static board-specific write policy.
    BoardSpecific,
}

/// Independently derived, snapshot-bound authority. Board-specific writes
/// additionally require class/mask enforcement outside this simple model;
/// this type must not be used on its own to grant such writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Grant {
    /// Address space.
    pub space: Space,
    /// Candidate range.
    pub range: Range,
    /// Permits reads.
    pub read: bool,
    /// Permits writes (only where the originating policy explicitly permits them).
    pub write: bool,
    /// Identity of the firmware snapshot from which the grant was derived.
    pub snapshot_id: u64,
}

/// Extended Gate B grant carrying an explicit write class and bitmask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyGrant {
    /// Base range, direction, and snapshot binding.
    pub base: Grant,
    /// Named write class when `base.write` is true.
    pub write_class: Option<WriteClass>,
    /// Allowed write bits (must be non-zero when `base.write` is true).
    pub write_mask: u64,
}

/// An independently identified forbidden range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenyRange {
    /// Address space.
    pub space: Space,
    /// Forbidden range.
    pub range: Range,
}

/// One operation against a candidate grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Access {
    /// Address space.
    pub space: Space,
    /// AML region base. This is not itself a source of authority.
    pub base: u64,
    /// Byte offset from the region base.
    pub offset: u64,
    /// Exact width in bytes.
    pub width: u8,
    /// Requested access direction.
    pub direction: Direction,
    /// Snapshot identity expected by the caller.
    pub snapshot_id: u64,
}

/// Authorize an exact access only if its entire candidate grant is disjoint
/// from every known deny range. A candidate intersecting a deny range is
/// rejected whole; callers must not silently truncate or join grants.
///
/// `deny_set_complete` must mean that *all* relevant exclusions, including
/// live and discovered resources, were independently established for the
/// matching snapshot. Passing `true` without that evidence is unsafe policy.
/// Invalid deny entries themselves fail closed, even in the other space.
pub fn authorizes(
    grant: Grant,
    deny: &[DenyRange],
    deny_set_complete: bool,
    access: Access,
) -> bool {
    if !deny_set_complete
        || grant.snapshot_id == 0
        || grant.snapshot_id != access.snapshot_id
        || grant.space != access.space
    {
        return false;
    }
    let Some(grant_end) = grant.range.end() else {
        return false;
    };
    if grant.space == Space::Io && grant_end > 0x1_0000 {
        return false;
    }
    for entry in deny {
        if entry.range.end().is_none() {
            return false;
        }
        if entry.space == grant.space && grant.range.overlaps(entry.range) != Some(false) {
            return false;
        }
    }
    let width = u64::from(access.width);
    let valid_width = match access.space {
        Space::Memory => matches!(width, 1 | 2 | 4 | 8),
        Space::Io => matches!(width, 1 | 2 | 4),
    };
    if !valid_width {
        return false;
    }
    let Some(start) = access.base.checked_add(access.offset) else {
        return false;
    };
    let Some(end) = start.checked_add(width) else {
        return false;
    };
    if start % width != 0 || start < grant.range.base || end > grant_end {
        return false;
    }
    match access.direction {
        Direction::Read => grant.read,
        Direction::Write => grant.write,
    }
}

/// Authorize an exact access against a [`PolicyGrant`], enforcing write class
/// and non-zero `write_mask` on writes.
pub fn authorizes_policy(
    grant: PolicyGrant,
    deny: &[DenyRange],
    deny_set_complete: bool,
    access: Access,
    write_value: u64,
) -> bool {
    if !authorizes(grant.base, deny, deny_set_complete, access) {
        return false;
    }
    if access.direction == Direction::Write {
        if grant.write_class.is_none() || grant.write_mask == 0 {
            return false;
        }
        if (write_value & !grant.write_mask) != 0 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> Grant {
        Grant {
            space: Space::Memory,
            range: Range {
                base: 0x1000,
                length: 0x100,
            },
            read: true,
            write: true,
            snapshot_id: 7,
        }
    }
    fn access() -> Access {
        Access {
            space: Space::Memory,
            base: 0x1000,
            offset: 8,
            width: 8,
            direction: Direction::Read,
            snapshot_id: 7,
        }
    }
    fn deny(space: Space, base: u64, length: u64) -> DenyRange {
        DenyRange {
            space,
            range: Range { base, length },
        }
    }

    #[test]
    fn allowed_widths_and_directions_are_exact() {
        assert!(authorizes(grant(), &[], true, access()));
        assert!(authorizes(
            grant(),
            &[],
            true,
            Access {
                direction: Direction::Write,
                ..access()
            }
        ));
        assert!(!authorizes(
            Grant {
                write: false,
                ..grant()
            },
            &[],
            true,
            Access {
                direction: Direction::Write,
                ..access()
            }
        ));
        assert!(!authorizes(
            grant(),
            &[],
            true,
            Access {
                width: 3,
                ..access()
            }
        ));
        assert!(!authorizes(
            grant(),
            &[],
            true,
            Access {
                offset: 1,
                width: 4,
                ..access()
            }
        ));
        let io_grant = Grant {
            space: Space::Io,
            ..grant()
        };
        let io = Access {
            space: Space::Io,
            ..access()
        };
        assert!(!authorizes(io_grant, &[], true, io));
        assert!(authorizes(io_grant, &[], true, Access { width: 4, ..io }));
    }

    #[test]
    fn sacred_deny_wins_over_whole_candidate() {
        assert!(!authorizes(
            grant(),
            &[deny(Space::Memory, 0x10ff, 1)],
            true,
            access()
        ));
        assert!(authorizes(
            grant(),
            &[deny(Space::Memory, 0x1100, 1)],
            true,
            access()
        ));
        assert!(authorizes(
            grant(),
            &[deny(Space::Io, 0x1000, 1)],
            true,
            access()
        ));
        assert!(!authorizes(
            grant(),
            &[deny(Space::Io, u64::MAX, 2)],
            true,
            access()
        ));
        assert!(!authorizes(grant(), &[], false, access()));
    }

    #[test]
    fn snapshot_mismatch_and_overflow_are_denied() {
        assert!(!authorizes(
            grant(),
            &[],
            true,
            Access {
                snapshot_id: 8,
                ..access()
            }
        ));
        assert!(!authorizes(
            Grant {
                snapshot_id: 0,
                ..grant()
            },
            &[],
            true,
            Access {
                snapshot_id: 0,
                ..access()
            }
        ));
        assert!(!authorizes(
            grant(),
            &[],
            true,
            Access {
                base: u64::MAX,
                offset: 1,
                ..access()
            }
        ));
        assert!(!authorizes(
            grant(),
            &[],
            true,
            Access {
                base: u64::MAX - 3,
                offset: 0,
                width: 4,
                ..access()
            }
        ));
        assert!(!authorizes(
            Grant {
                range: Range {
                    base: u64::MAX,
                    length: 2
                },
                ..grant()
            },
            &[],
            true,
            access()
        ));
    }

    #[test]
    fn crossing_adjacent_grants_never_combines_authority() {
        let first = Grant {
            range: Range {
                base: 0x1000,
                length: 3,
            },
            ..grant()
        };
        let second = Grant {
            range: Range {
                base: 0x1003,
                length: 5,
            },
            ..grant()
        };
        let request = Access {
            offset: 0,
            width: 4,
            ..access()
        };
        assert!(!authorizes(first, &[], true, request));
        assert!(!authorizes(second, &[], true, request));
        assert!(!authorizes(
            Grant {
                range: Range {
                    base: 0x1000,
                    length: 0
                },
                ..grant()
            },
            &[],
            true,
            request
        ));
    }
}
