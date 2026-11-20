//! Lexical path handling.
//!
//! HuesOS has one namespace per service, so paths are plain strings: either
//! absolute (`/home/user/a.txt`) or relative to a directory handle. Nothing
//! here touches the file system — these are pure string operations, which is
//! what makes them testable inside the smoke binary with no volume mounted.
//!
//! `..` never climbs above `/`: a path that tries becomes `/`, matching what
//! the services accept, and keeping a scoped directory handle from being
//! escaped by a relative path.

use alloc::string::String;
use alloc::vec::Vec;

/// The separator between path components.
pub const SEPARATOR: char = '/';

/// True when `path` starts at the namespace root.
pub fn is_absolute(path: &str) -> bool {
    path.starts_with(SEPARATOR)
}

/// Iterate the meaningful components of `path`, dropping empty ones (so `//`
/// and a trailing `/` disappear).
pub struct Components<'a> {
    rest: &'a str,
}

impl<'a> Components<'a> {
    /// Components of `path`.
    pub fn new(path: &'a str) -> Self {
        Self { rest: path }
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        loop {
            let rest = self.rest.trim_start_matches(SEPARATOR);
            if rest.is_empty() {
                self.rest = "";
                return None;
            }
            match rest.find(SEPARATOR) {
                Some(index) => {
                    self.rest = &rest[index..];
                    let component = &rest[..index];
                    if !component.is_empty() {
                        return Some(component);
                    }
                }
                None => {
                    self.rest = "";
                    return Some(rest);
                }
            }
        }
    }
}

/// The components of `path`, in order.
pub fn components(path: &str) -> Vec<&str> {
    Components::new(path).collect()
}

/// The last component of `path`, ignoring a trailing separator.
pub fn file_name(path: &str) -> Option<&str> {
    components(path).pop()
}

/// Everything before the last component; `/` for a top-level entry and `None`
/// for the root itself.
pub fn parent(path: &str) -> Option<String> {
    let parts = components(path);
    if parts.is_empty() {
        return None;
    }
    let absolute = is_absolute(path);
    if parts.len() == 1 {
        return if absolute {
            Some(String::from("/"))
        } else {
            None
        };
    }
    let mut out = String::new();
    if absolute {
        out.push(SEPARATOR);
    }
    out.push_str(&parts[..parts.len() - 1].join("/"));
    Some(out)
}

/// Join `name` onto `base`, keeping a single separator.
pub fn join(base: &str, name: &str) -> String {
    if is_absolute(name) {
        return String::from(name);
    }
    if base.is_empty() || base == "/" {
        let mut out = String::from(SEPARATOR);
        out.push_str(name);
        return out;
    }
    let mut out = String::from(base.trim_end_matches(SEPARATOR));
    out.push(SEPARATOR);
    out.push_str(name.trim_start_matches(SEPARATOR));
    out
}

/// Collapse `.`, `..` and repeated separators in `path`.
///
/// `..` on an already-empty prefix is dropped rather than reported: a caller
/// that walks above the root gets the root, which is the only thing a service
/// could resolve anyway.
pub fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in Components::new(path) {
        match component {
            "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = String::new();
    if is_absolute(path) || path.is_empty() {
        out.push(SEPARATOR);
    }
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(SEPARATOR);
        }
        out.push_str(part);
    }
    if out.is_empty() {
        out.push(SEPARATOR);
    }
    out
}

/// `path` relative to the root, which is what a scoped directory handle wants.
pub fn relative(path: &str) -> &str {
    path.trim_start_matches(SEPARATOR)
}
