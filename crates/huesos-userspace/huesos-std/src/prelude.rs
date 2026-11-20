//! What almost every program wants, in one `use`.

pub use alloc::format;
pub use alloc::string::{String, ToString};
pub use alloc::vec;
pub use alloc::vec::Vec;

pub use crate::env::{args, argv, caps, has_caps};
pub use crate::error::{Error, ErrorKind, Result};
pub use crate::fs::{self, Entry, EntryKind, File};
pub use crate::io::{self, Read, Seek, SeekFrom, Write};
pub use crate::path;
pub use crate::process;
pub use crate::{eprint, eprintln, print, println};
