//! Hxfs no-heap security and capability policy core.
//!
//! Stage X keeps security decisions host-testable before wiring them into every
//! service call site. The policy follows the HuesOS rule that paths only resolve
//! objects; all durable operations after resolution are handle-first and rights
//! checked.

use huesos_abi::hxfs::{rights, HxfsHandleKind, HxfsOp, HxfsRequest, HXFS_MAX_PATH_BYTES};

use crate::format::MAX_NAME_BYTES;

/// Maximum symlink depth accepted by path resolution policy.
pub const MAX_SYMLINK_DEPTH: u8 = 8;
/// Maximum outstanding native Hxfs requests per client in the no-heap service.
pub const MAX_OUTSTANDING_REQUESTS_PER_CLIENT: u16 = 32;

/// Security-policy decision failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityError {
    /// Request/operation does not match handle kind.
    WrongKind,
    /// Required rights are absent.
    MissingRights {
        /// Rights required by policy.
        required: u64,
        /// Rights provided by the handle/request.
        provided: u64,
    },
    /// Request attempts to use rights not defined by the ABI.
    UnknownRights,
    /// Path/name bytes are invalid for Hxfs.
    BadPath,
    /// Symlink resolution exceeded the bounded policy depth.
    SymlinkLimit,
    /// Per-client request quota would be exceeded.
    RequestQuota,
}

/// Path validation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathMode {
    /// Absolute path under the virtual volume root.
    Absolute,
    /// Single directory-entry name.
    SingleName,
}

/// Required rights for an operation on a handle kind.
pub fn required_rights(op: HxfsOp, kind: HxfsHandleKind) -> Result<u64, SecurityError> {
    match op {
        HxfsOp::GetInfo => Ok(0),
        HxfsOp::OpenRoot => match kind {
            HxfsHandleKind::None | HxfsHandleKind::Volume => Ok(rights::READ),
            _ => Err(SecurityError::WrongKind),
        },
        HxfsOp::OpenPath | HxfsOp::ReadAt | HxfsOp::ListDirectory => Ok(rights::READ),
        HxfsOp::CreateFile | HxfsOp::Mkdir | HxfsOp::Symlink => match kind {
            HxfsHandleKind::Directory | HxfsHandleKind::Volume | HxfsHandleKind::None => {
                Ok(rights::CREATE)
            }
            _ => Err(SecurityError::WrongKind),
        },
        HxfsOp::Rename | HxfsOp::Unlink => match kind {
            HxfsHandleKind::Directory | HxfsHandleKind::Volume | HxfsHandleKind::None => {
                Ok(rights::MODIFY_DIRECTORY)
            }
            _ => Err(SecurityError::WrongKind),
        },
        HxfsOp::Truncate | HxfsOp::WriteAt => match kind {
            HxfsHandleKind::File => Ok(rights::WRITE),
            _ => Err(SecurityError::WrongKind),
        },
        HxfsOp::Fsync | HxfsOp::Checkpoint => Ok(rights::SYNC),
        HxfsOp::CreateSnapshot | HxfsOp::DeleteSnapshot => match kind {
            HxfsHandleKind::Volume | HxfsHandleKind::Snapshot => Ok(rights::SNAPSHOT),
            _ => Err(SecurityError::WrongKind),
        },
    }
}

/// Validate request rights against the policy table.
pub fn validate_request_rights(request: HxfsRequest) -> Result<(), SecurityError> {
    if request.rights & !rights::ALL != 0 {
        return Err(SecurityError::UnknownRights);
    }
    let required = required_rights(request.op, request.handle_kind)?;
    if required != 0 && request.rights & required != required {
        return Err(SecurityError::MissingRights {
            required,
            provided: request.rights,
        });
    }
    Ok(())
}

/// Validate absolute path or single-name bytes.
pub fn validate_path(bytes: &[u8], mode: PathMode) -> Result<(), SecurityError> {
    if bytes.is_empty() || bytes.len() > HXFS_MAX_PATH_BYTES {
        return Err(SecurityError::BadPath);
    }
    let Ok(text) = core::str::from_utf8(bytes) else {
        return Err(SecurityError::BadPath);
    };
    match mode {
        PathMode::Absolute => validate_absolute(text),
        PathMode::SingleName => validate_component(bytes),
    }
}

/// Validate symlink traversal depth.
pub const fn validate_symlink_depth(depth: u8) -> Result<(), SecurityError> {
    if depth > MAX_SYMLINK_DEPTH {
        Err(SecurityError::SymlinkLimit)
    } else {
        Ok(())
    }
}

/// Validate per-client outstanding request quota.
pub const fn admit_request(current_outstanding: u16) -> Result<(), SecurityError> {
    if current_outstanding >= MAX_OUTSTANDING_REQUESTS_PER_CLIENT {
        Err(SecurityError::RequestQuota)
    } else {
        Ok(())
    }
}

fn validate_absolute(path: &str) -> Result<(), SecurityError> {
    let bytes = path.as_bytes();
    if !bytes.starts_with(b"/") {
        return Err(SecurityError::BadPath);
    }
    if path == "/" {
        return Ok(());
    }
    let mut rest = &bytes[1..];
    loop {
        let slash = rest.iter().position(|&byte| byte == b'/');
        let (component, tail) = match slash {
            Some(pos) => (&rest[..pos], &rest[pos + 1..]),
            None => (rest, &[][..]),
        };
        validate_component(component)?;
        if tail.is_empty() {
            return Ok(());
        }
        rest = tail;
    }
}

fn validate_component(component: &[u8]) -> Result<(), SecurityError> {
    if component.is_empty()
        || component.len() > MAX_NAME_BYTES
        || component == b"."
        || component == b".."
        || component.contains(&0)
        || component.contains(&b'/')
        || core::str::from_utf8(component).is_err()
    {
        return Err(SecurityError::BadPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_abi::hxfs::{HxfsRequest, HXFS_PROTOCOL_VERSION};

    fn request(op: HxfsOp, kind: HxfsHandleKind, request_rights: u64) -> HxfsRequest {
        HxfsRequest {
            version: HXFS_PROTOCOL_VERSION,
            reserved0: 0,
            op,
            flags: 0,
            request_id: 1,
            handle_id: 1,
            handle_kind: kind,
            rights: request_rights,
            arg0: 0,
            arg1: 0,
            payload_len: 0,
            reserved1: 0,
        }
    }

    #[test]
    fn rights_are_operation_specific() {
        assert_eq!(
            validate_request_rights(request(
                HxfsOp::WriteAt,
                HxfsHandleKind::File,
                rights::WRITE
            )),
            Ok(())
        );
        assert_eq!(
            validate_request_rights(request(HxfsOp::WriteAt, HxfsHandleKind::File, rights::READ)),
            Err(SecurityError::MissingRights {
                required: rights::WRITE,
                provided: rights::READ,
            })
        );
        assert_eq!(
            validate_request_rights(request(
                HxfsOp::WriteAt,
                HxfsHandleKind::Directory,
                rights::WRITE
            )),
            Err(SecurityError::WrongKind)
        );
    }

    #[test]
    fn paths_reject_escape_and_bad_names() {
        assert_eq!(
            validate_path(b"/home/user/file", PathMode::Absolute),
            Ok(())
        );
        assert_eq!(
            validate_path(b"relative", PathMode::Absolute),
            Err(SecurityError::BadPath)
        );
        assert_eq!(
            validate_path(b"/home/../secret", PathMode::Absolute),
            Err(SecurityError::BadPath)
        );
        assert_eq!(validate_path(b"child", PathMode::SingleName), Ok(()));
        assert_eq!(
            validate_path(b"bad/name", PathMode::SingleName),
            Err(SecurityError::BadPath)
        );
    }

    #[test]
    fn symlink_depth_and_request_quota_are_bounded() {
        assert_eq!(validate_symlink_depth(MAX_SYMLINK_DEPTH), Ok(()));
        assert_eq!(
            validate_symlink_depth(MAX_SYMLINK_DEPTH + 1),
            Err(SecurityError::SymlinkLimit)
        );
        assert_eq!(admit_request(0), Ok(()));
        assert_eq!(
            admit_request(MAX_OUTSTANDING_REQUESTS_PER_CLIENT),
            Err(SecurityError::RequestQuota)
        );
    }

    // Production-gate security hardening coverage: each test
    // pins one invariant from the rights/path/quota contract in
    // docs/STORAGE_NVME_FS_ROADMAP.md §O (Stage X).
    //
    //   X1 feat(abi): define Hxfs handle rights
    //   X2 feat(hxfs-service): enforce rights and request quotas
    //   X3 feat(hxfs): harden path/symlink/name validation
    //   X4 fuzz(hxfs): add ABI/path resolver fuzz targets
    //   X5 docs(audit): record Hxfs service security boundary

    #[test]
    fn unknown_right_bits_are_rejected() {
        // A request that carries rights bits outside the
        // known rights::ALL mask must surface UnknownRights,
        // not silently accept. The validate_request_rights
        // contract guarantees this so a future rights-bit
        // addition cannot accidentally pass an unrelated bit.
        let mut req = request(HxfsOp::GetInfo, HxfsHandleKind::Volume, rights::READ);
        // A bit well above the highest known rights bit.
        req.rights = rights::ALL | (1u64 << 60);
        assert_eq!(
            validate_request_rights(req),
            Err(SecurityError::UnknownRights)
        );
    }

    #[test]
    fn getinfo_requires_no_specific_rights() {
        // GetInfo is a metadata read; any non-zero rights bit
        // set is accepted (the caller may have full rights on
        // the volume handle), and missing rights are not a
        // failure. The strict-required check only fires for
        // ops that have a non-zero required mask.
        let req = request(HxfsOp::GetInfo, HxfsHandleKind::Volume, 0);
        assert_eq!(validate_request_rights(req), Ok(()));
    }

    #[test]
    fn rename_against_a_file_handle_is_wrong_kind() {
        // Rename must operate on a directory or volume; a
        // file handle is the wrong kind.
        let req = request(
            HxfsOp::Rename,
            HxfsHandleKind::File,
            rights::MODIFY_DIRECTORY,
        );
        assert_eq!(validate_request_rights(req), Err(SecurityError::WrongKind));
    }

    #[test]
    fn truncate_against_a_directory_handle_is_wrong_kind() {
        let req = request(
            HxfsOp::Truncate,
            HxfsHandleKind::Directory,
            rights::WRITE,
        );
        assert_eq!(validate_request_rights(req), Err(SecurityError::WrongKind));
    }

    #[test]
    fn snapshot_op_against_file_handle_is_wrong_kind() {
        let req = request(
            HxfsOp::CreateSnapshot,
            HxfsHandleKind::File,
            rights::SNAPSHOT,
        );
        assert_eq!(validate_request_rights(req), Err(SecurityError::WrongKind));
    }

    #[test]
    fn path_rejects_empty_and_overlong_inputs() {
        assert_eq!(validate_path(b"", PathMode::Absolute), Err(SecurityError::BadPath));
        let overlong = [b'a'; HXFS_MAX_PATH_BYTES + 1];
        assert_eq!(validate_path(&overlong, PathMode::Absolute), Err(SecurityError::BadPath));
    }

    #[test]
    fn single_name_path_rejects_absolute_prefix() {
        // A SingleName is a single directory entry; it must
        // not contain a path separator. The "/" prefix is
        // therefore rejected.
        assert_eq!(
            validate_path(b"/etc", PathMode::SingleName),
            Err(SecurityError::BadPath)
        );
    }

    #[test]
    fn symlink_depth_at_max_is_admitted_at_max_plus_one_is_rejected() {
        // The exact boundary: MAX_SYMLINK_DEPTH must succeed
        // and one more must fail. This is the policy table
        // contract that the resolver walks; the boundary
        // cannot be off-by-one without breaking production
        // mounts.
        assert_eq!(validate_symlink_depth(0), Ok(()));
        assert_eq!(validate_symlink_depth(MAX_SYMLINK_DEPTH), Ok(()));
        assert_eq!(
            validate_symlink_depth(MAX_SYMLINK_DEPTH + 1),
            Err(SecurityError::SymlinkLimit)
        );
    }

    #[test]
    fn request_quota_at_limit_admits_one_more_is_over() {
        // admit_request counts outstanding requests per
        // client; the contract admits up to
        // MAX_OUTSTANDING_REQUESTS_PER_CLIENT outstanding,
        // and the next one is rejected.
        let max = MAX_OUTSTANDING_REQUESTS_PER_CLIENT;
        assert_eq!(admit_request(max - 1), Ok(()));
        assert_eq!(admit_request(max), Err(SecurityError::RequestQuota));
    }
}
