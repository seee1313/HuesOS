//! One error type for the whole library.
//!
//! Every [`libcanvas`] call returns [`huesos_abi::ErrorCode`]; this module
//! turns those codes into an [`Error`] that carries a coarse [`ErrorKind`] a
//! program can branch on plus the raw code it can print. The mapping is
//! deliberately lossy in one direction only: `Error` never invents a code it
//! was not given.

use core::fmt;

/// The raw ABI codes, re-exported so a program can match on one without
/// depending on `huesos-abi` itself.
pub use huesos_abi::ErrorCode;

/// Coarse failure classes, stable enough to match on in a program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// A capability was withheld: the service channel was never granted.
    AccessDenied,
    /// The handle is stale or names the wrong object kind.
    BadHandle,
    /// The resource is busy; the caller may retry.
    Busy,
    /// The caller passed a malformed argument.
    InvalidInput,
    /// The service or device reported an I/O failure.
    Io,
    /// Out of memory.
    NoMemory,
    /// The path or object does not exist.
    NotFound,
    /// The operation is not supported by this build.
    Unsupported,
    /// The peer end of the channel is gone.
    PeerClosed,
    /// A bounded wait expired.
    TimedOut,
    /// The call would block; the caller should wait and try again.
    ShouldWait,
    /// Anything the code table does not name.
    Other,
}

impl ErrorKind {
    /// Human-readable name, allocation free.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessDenied => "access denied",
            Self::BadHandle => "bad handle",
            Self::Busy => "resource busy",
            Self::InvalidInput => "invalid input",
            Self::Io => "I/O error",
            Self::NoMemory => "out of memory",
            Self::NotFound => "not found",
            Self::Unsupported => "unsupported",
            Self::PeerClosed => "peer closed",
            Self::TimedOut => "timed out",
            Self::ShouldWait => "would block",
            Self::Other => "error",
        }
    }
}

/// Map a kernel/service code onto a coarse class.
pub const fn kind_of(code: ErrorCode) -> ErrorKind {
    match code {
        ErrorCode::AccessDenied => ErrorKind::AccessDenied,
        ErrorCode::BadHandle | ErrorCode::WrongType => ErrorKind::BadHandle,
        ErrorCode::Busy => ErrorKind::Busy,
        ErrorCode::InvalidArgs => ErrorKind::InvalidInput,
        ErrorCode::NoMemory => ErrorKind::NoMemory,
        ErrorCode::NotFound => ErrorKind::NotFound,
        ErrorCode::NotSupported | ErrorCode::NoFramebuffer => ErrorKind::Unsupported,
        ErrorCode::PeerClosed => ErrorKind::PeerClosed,
        ErrorCode::TimedOut => ErrorKind::TimedOut,
        ErrorCode::ShouldWait => ErrorKind::ShouldWait,
        ErrorCode::Internal => ErrorKind::Io,
    }
}

/// A failure with a coarse kind and, when it came from a syscall, its code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    code: Option<ErrorCode>,
}

impl Error {
    /// An error of `kind` that did not come from a syscall.
    pub const fn new(kind: ErrorKind) -> Self {
        Self { kind, code: None }
    }

    /// Wrap a syscall code.
    pub const fn from_code(code: ErrorCode) -> Self {
        Self {
            kind: kind_of(code),
            code: Some(code),
        }
    }

    /// The capability this program was not given.
    pub const fn capability() -> Self {
        Self::new(ErrorKind::AccessDenied)
    }

    /// A malformed argument built by this library rather than by the kernel.
    pub const fn invalid(message: &'static str) -> Invalid<'static> {
        Invalid {
            message,
            kind: ErrorKind::InvalidInput,
            code: None,
        }
    }

    /// The coarse class.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The original syscall code, if there was one.
    pub const fn code(&self) -> Option<ErrorCode> {
        self.code
    }

    /// True when the caller may usefully retry the same call.
    pub const fn is_retryable(&self) -> bool {
        matches!(self.kind, ErrorKind::Busy | ErrorKind::ShouldWait | ErrorKind::TimedOut)
    }
}

/// An [`Error`] that also carries a caller-supplied explanation.
///
/// Kept separate so the common case stays a plain `Copy` struct; convert it
/// with [`Into::into`] when the explanation is worth printing.
#[derive(Clone, Copy, Debug)]
pub struct Invalid<'a> {
    message: &'a str,
    kind: ErrorKind,
    code: Option<ErrorCode>,
}

impl fmt::Display for Invalid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.as_str())?;
        f.write_str(": ")?;
        f.write_str(self.message)
    }
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Self::from_code(code)
    }
}

impl From<Invalid<'_>> for Error {
    fn from(invalid: Invalid<'_>) -> Self {
        Self {
            kind: invalid.kind,
            code: invalid.code,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.as_str())?;
        match self.code {
            Some(code) => {
                f.write_str(" (")?;
                f.write_str(code.as_str())?;
                f.write_str(")")
            }
            None => Ok(()),
        }
    }
}

/// The result type used throughout `huesos-std`.
pub type Result<T> = core::result::Result<T, Error>;
