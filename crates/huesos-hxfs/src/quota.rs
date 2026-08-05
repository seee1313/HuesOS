//! Hxfs per-volume quota accounting.
//!
//! Hxfs quotas are capability/volume policy, not Unix user/group policy. Stage I
//! tracks the two quotas selected in the design: physical bytes and object count.

/// Quota limits for one virtual volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeQuota {
    /// Maximum physical bytes. `0` means unlimited.
    pub max_physical_bytes: u64,
    /// Maximum object count. `0` means unlimited.
    pub max_objects: u64,
}

impl VolumeQuota {
    /// Unlimited quota.
    pub const fn unlimited() -> Self {
        Self {
            max_physical_bytes: 0,
            max_objects: 0,
        }
    }
}

/// Current volume usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VolumeUsage {
    /// Allocated physical bytes.
    pub physical_bytes: u64,
    /// Object count.
    pub objects: u64,
}

/// Quota admission error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaError {
    /// Physical byte limit would be exceeded.
    PhysicalBytes,
    /// Object-count limit would be exceeded.
    Objects,
    /// Arithmetic overflow.
    Overflow,
}

/// Check whether `delta` can be applied to `usage` under `quota`.
pub fn check_quota(
    quota: VolumeQuota,
    usage: VolumeUsage,
    delta: VolumeUsage,
) -> Result<VolumeUsage, QuotaError> {
    let physical = usage
        .physical_bytes
        .checked_add(delta.physical_bytes)
        .ok_or(QuotaError::Overflow)?;
    let objects = usage
        .objects
        .checked_add(delta.objects)
        .ok_or(QuotaError::Overflow)?;
    if quota.max_physical_bytes != 0 && physical > quota.max_physical_bytes {
        return Err(QuotaError::PhysicalBytes);
    }
    if quota.max_objects != 0 && objects > quota.max_objects {
        return Err(QuotaError::Objects);
    }
    Ok(VolumeUsage {
        physical_bytes: physical,
        objects,
    })
}

/// Release usage, saturating at zero.
pub const fn release_usage(usage: VolumeUsage, delta: VolumeUsage) -> VolumeUsage {
    VolumeUsage {
        physical_bytes: usage.physical_bytes.saturating_sub(delta.physical_bytes),
        objects: usage.objects.saturating_sub(delta.objects),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_admits_within_limits() {
        let quota = VolumeQuota {
            max_physical_bytes: 4096,
            max_objects: 2,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage {
                    physical_bytes: 1024,
                    objects: 1,
                },
                VolumeUsage {
                    physical_bytes: 1024,
                    objects: 1,
                },
            ),
            Ok(VolumeUsage {
                physical_bytes: 2048,
                objects: 2,
            })
        );
    }

    #[test]
    fn quota_rejects_physical_and_objects() {
        let quota = VolumeQuota {
            max_physical_bytes: 100,
            max_objects: 1,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage::default(),
                VolumeUsage {
                    physical_bytes: 101,
                    objects: 0,
                },
            ),
            Err(QuotaError::PhysicalBytes)
        );
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage::default(),
                VolumeUsage {
                    physical_bytes: 0,
                    objects: 2,
                },
            ),
            Err(QuotaError::Objects)
        );
    }

    #[test]
    fn release_saturates() {
        assert_eq!(
            release_usage(
                VolumeUsage {
                    physical_bytes: 1,
                    objects: 1,
                },
                VolumeUsage {
                    physical_bytes: 2,
                    objects: 2,
                },
            ),
            VolumeUsage::default()
        );
    }

    // Production-gate quota coverage: each test pins one admission
    // contract from docs/STORAGE_NVME_FS_ROADMAP.md §G (Stage O).
    //
    //   O1 feat(hxfs): persist quota tree descriptors
    //   O2 feat(hxfs): enforce physical-byte quota in allocator path
    //   O3 feat(hxfs): enforce object-count quota in object creation path
    //   O4 test(hxfs): add quota persistence and rollback tests
    //
    // The check_quota function is the only enforcement point today;
    // the tests below pin its boundary behavior so the future
    // write-path integration cannot regress them.

    #[test]
    fn unlimited_quota_accepts_any_usage() {
        // max=0 in either field means "unlimited" per the design.
        // Both the per-volume and the all-zero sentinel must admit
        // any finite usage without overflow.
        let quota = VolumeQuota::unlimited();
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage::default(),
                VolumeUsage {
                    physical_bytes: u64::MAX / 2,
                    objects: u64::MAX / 2,
                },
            ),
            Ok(VolumeUsage {
                physical_bytes: u64::MAX / 2,
                objects: u64::MAX / 2,
            })
        );
    }

    #[test]
    fn physical_quota_admits_exactly_at_limit() {
        // usage + delta == limit is the boundary case. The check is
        // `physical > limit` (strict), so exactly at the limit is
        // admitted. This matters for fixed-size allocations that
        // charge the full limit on the first call.
        let quota = VolumeQuota {
            max_physical_bytes: 100,
            max_objects: 0,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage {
                    physical_bytes: 50,
                    objects: 0,
                },
                VolumeUsage {
                    physical_bytes: 50,
                    objects: 0,
                },
            ),
            Ok(VolumeUsage {
                physical_bytes: 100,
                objects: 0,
            })
        );
    }

    #[test]
    fn physical_quota_rejects_one_byte_over_limit() {
        // Strict-greater semantics: 101 > 100, rejected.
        let quota = VolumeQuota {
            max_physical_bytes: 100,
            max_objects: 0,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage::default(),
                VolumeUsage {
                    physical_bytes: 101,
                    objects: 0,
                },
            ),
            Err(QuotaError::PhysicalBytes)
        );
    }

    #[test]
    fn object_quota_admits_exactly_at_limit() {
        // Same boundary semantics for the object counter.
        let quota = VolumeQuota {
            max_physical_bytes: 0,
            max_objects: 3,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage {
                    physical_bytes: 0,
                    objects: 2,
                },
                VolumeUsage {
                    physical_bytes: 0,
                    objects: 1,
                },
            ),
            Ok(VolumeUsage {
                physical_bytes: 0,
                objects: 3,
            })
        );
    }

    #[test]
    fn object_quota_rejects_one_object_over_limit() {
        let quota = VolumeQuota {
            max_physical_bytes: 0,
            max_objects: 3,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage::default(),
                VolumeUsage {
                    physical_bytes: 0,
                    objects: 4,
                },
            ),
            Err(QuotaError::Objects)
        );
    }

    #[test]
    fn physical_check_runs_before_object_check() {
        // When both quotas are exceeded on the same delta, the
        // physical-bytes error must win. The write-path
        // integration relies on this order so it can charge
        // physical first and back out the object increment on
        // a clean error path.
        let quota = VolumeQuota {
            max_physical_bytes: 100,
            max_objects: 1,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage::default(),
                VolumeUsage {
                    physical_bytes: 200,
                    objects: 5,
                },
            ),
            Err(QuotaError::PhysicalBytes)
        );
    }

    #[test]
    fn physical_overflow_surfaces_overflow_not_physical_bytes() {
        // An overflow on the physical counter is a different class
        // of failure from a quota breach. The write path must
        // treat it as an admission error and abort the
        // transaction, not as a quota violation that the caller
        // might try to retry.
        let quota = VolumeQuota {
            max_physical_bytes: u64::MAX,
            max_objects: 0,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage {
                    physical_bytes: u64::MAX,
                    objects: 0,
                },
                VolumeUsage {
                    physical_bytes: 1,
                    objects: 0,
                },
            ),
            Err(QuotaError::Overflow)
        );
    }

    #[test]
    fn object_overflow_surfaces_overflow_not_objects() {
        let quota = VolumeQuota {
            max_physical_bytes: 0,
            max_objects: u64::MAX,
        };
        assert_eq!(
            check_quota(
                quota,
                VolumeUsage {
                    physical_bytes: 0,
                    objects: u64::MAX,
                },
                VolumeUsage {
                    physical_bytes: 0,
                    objects: 1,
                },
            ),
            Err(QuotaError::Overflow)
        );
    }

    #[test]
    fn charge_release_charge_round_trip() {
        // Charge 50 bytes, release them, charge 50 again. The
        // second charge must succeed because usage is back to
        // zero; this is the path the write path takes on
        // allocate-then-rollback.
        let quota = VolumeQuota {
            max_physical_bytes: 100,
            max_objects: 0,
        };
        let after_first = match check_quota(
            quota,
            VolumeUsage::default(),
            VolumeUsage {
                physical_bytes: 50,
                objects: 0,
            },
        ) {
            Ok(value) => value,
            Err(error) => {
                assert!(false, "first charge failed: {error:?}");
                return;
            }
        };
        let after_release = release_usage(
            after_first,
            VolumeUsage {
                physical_bytes: 50,
                objects: 0,
            },
        );
        assert_eq!(after_release, VolumeUsage::default());
        let after_second = check_quota(
            quota,
            after_release,
            VolumeUsage {
                physical_bytes: 50,
                objects: 0,
            },
        );
        assert_eq!(
            after_second,
            Ok(VolumeUsage {
                physical_bytes: 50,
                objects: 0,
            })
        );
    }

    #[test]
    fn zero_delta_is_a_no_op() {
        // A delta of zero is admitted for any usage up to the
        // limit. This is the path a no-op write takes (e.g. an
        // idempotent retry that finds the same state).
        let quota = VolumeQuota {
            max_physical_bytes: 100,
            max_objects: 5,
        };
        assert_eq!(
            check_quota(quota, VolumeUsage::default(), VolumeUsage::default()),
            Ok(VolumeUsage::default())
        );
    }

    #[test]
    fn release_never_becomes_negative() {
        // release_usage must saturate at zero, not wrap, so the
        // post-release charge cannot see a phantom usage.
        let after = release_usage(
            VolumeUsage::default(),
            VolumeUsage {
                physical_bytes: 1,
                objects: 1,
            },
        );
        assert_eq!(after, VolumeUsage::default());
    }
}
