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
}
