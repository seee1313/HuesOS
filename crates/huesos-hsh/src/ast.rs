//! Abstract syntax tree for `hsh`.

use alloc::string::String;
use alloc::vec::Vec;
use huesos_abi::auxv::caps_mask;

/// HxFS capability access level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HxfsAccess {
    None,
    ReadOnly,
    ReadWrite,
}

/// BOOTFS capability access level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootfsAccess {
    None,
    ReadOnly,
}

/// Framebuffer capability access level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FbAccess {
    None,
    ReadOnly,
}

/// Scoped HxFS directory grant (`@caps(dir=/subpath:ro)`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirGrant {
    pub path: String,
    pub read_only: bool,
}

/// Capability attenuation specification parsed from `@caps(...)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsSpec {
    pub hxfs: HxfsAccess,
    pub bootfs: BootfsAccess,
    pub fb: FbAccess,
    pub block_rw: bool,
    pub dir: Option<DirGrant>,
}

impl Default for CapsSpec {
    fn default() -> Self {
        Self {
            hxfs: HxfsAccess::ReadWrite,
            bootfs: BootfsAccess::ReadOnly,
            fb: FbAccess::ReadOnly,
            block_rw: true,
            dir: None,
        }
    }
}

impl CapsSpec {
    /// Convert this specification into the kernel/rtld `AT_HUESOS_CAPS_MASK` bitmask.
    pub fn to_caps_mask(&self) -> u64 {
        let mut mask = 0u64;
        match self.hxfs {
            HxfsAccess::None => {}
            HxfsAccess::ReadOnly => mask |= caps_mask::HXFS_RO,
            HxfsAccess::ReadWrite => mask |= caps_mask::HXFS_RO | caps_mask::HXFS_RW,
        }
        if matches!(self.bootfs, BootfsAccess::ReadOnly) {
            mask |= caps_mask::BOOTFS_RO;
        }
        if matches!(self.fb, FbAccess::ReadOnly) {
            mask |= caps_mask::FB_RO;
        }
        if self.block_rw && !matches!(self.hxfs, HxfsAccess::None) {
            // Note: block writes follow hxfs=ro/none attenuation unless explicitly kept.
            mask |= caps_mask::BLOCK_RW;
        }
        if matches!(self.hxfs, HxfsAccess::ReadOnly) {
            mask &= !caps_mask::BLOCK_RW;
        }
        if let Some(dir) = &self.dir {
            mask |= caps_mask::HXFS_RO;
            if dir.read_only {
                mask &= !caps_mask::HXFS_RW;
            }
        }
        mask
    }

    /// Parse the inner text of `@caps(...)` (e.g. `hxfs=ro, bootfs=none, dir=/tmp:ro`).
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut out = Self::default();
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Ok(out);
        }
        for part in trimmed.split(',') {
            let item = part.trim();
            if item.is_empty() {
                continue;
            }
            let Some((key, val)) = item.split_once('=') else {
                return Err(alloc::format!("@caps expected key=value, got '{item}'"));
            };
            let key = key.trim();
            let val = val.trim();
            match key {
                "hxfs" => {
                    out.hxfs = match val {
                        "none" => {
                            out.block_rw = false;
                            HxfsAccess::None
                        }
                        "ro" => {
                            out.block_rw = false;
                            HxfsAccess::ReadOnly
                        }
                        "rw" => {
                            out.block_rw = true;
                            HxfsAccess::ReadWrite
                        }
                        _ => return Err(alloc::format!("invalid hxfs cap '{val}'")),
                    };
                }
                "bootfs" => {
                    out.bootfs = match val {
                        "none" => BootfsAccess::None,
                        "ro" => BootfsAccess::ReadOnly,
                        _ => return Err(alloc::format!("invalid bootfs cap '{val}'")),
                    };
                }
                "fb" => {
                    out.fb = match val {
                        "none" => FbAccess::None,
                        "ro" => FbAccess::ReadOnly,
                        _ => return Err(alloc::format!("invalid fb cap '{val}'")),
                    };
                }
                "dir" => {
                    let (path, ro) = if let Some((p, mode)) = val.rsplit_once(':') {
                        match mode {
                            "ro" => (p, true),
                            "rw" => (p, false),
                            _ => return Err(alloc::format!("invalid dir mode '{mode}'")),
                        }
                    } else {
                        (val, true)
                    };
                    if !path.starts_with('/') {
                        return Err(alloc::format!("dir path must be absolute: '{path}'"));
                    }
                    out.dir = Some(DirGrant {
                        path: String::from(path),
                        read_only: ro,
                    });
                    if ro {
                        out.hxfs = HxfsAccess::ReadOnly;
                        out.block_rw = false;
                    }
                }
                _ => return Err(alloc::format!("unknown @caps key '{key}'")),
            }
        }
        Ok(out)
    }
}

/// Piece inside an argument expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WordPart {
    Literal(String),
    Var(String),
    CmdSubst(Vec<Stmt>),
}

/// Argument expression (preserves exact boundaries; no POSIX word splitting).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgExpr {
    pub parts: Vec<WordPart>,
    pub raw_var_only: Option<String>,
}

/// Expression evaluated in `let`, `for`, or `return`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    Scalar(ArgExpr),
    List(Vec<Expr>),
}

/// Comparison operator for `if` conditions and `where` predicates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Contains,
}

/// Conditional expression in `if ... { ... }`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Cond {
    Compare {
        left: ArgExpr,
        op: CmpOp,
        right: ArgExpr,
    },
    Truthy(ArgExpr),
}

/// Output redirection to an HxFS file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Redirect {
    Truncate(ArgExpr),
    Append(ArgExpr),
}

/// Single command invocation in a pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandCall {
    pub caps: Option<CapsSpec>,
    pub name: ArgExpr,
    pub args: Vec<ArgExpr>,
    pub redirect: Option<Redirect>,
}

/// Pipeline `cmd1 | cmd2 | ...`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pipeline {
    pub stages: Vec<CommandCall>,
}

/// Logical/sequential chain operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainOp {
    Seq,
    And,
    Or,
}

/// Chained pipelines (`p1 && p2 ; p3 || p4`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chain {
    pub first: Pipeline,
    pub rest: Vec<(ChainOp, Pipeline)>,
}

/// Top-level or block statement in `hsh`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Stmt {
    Let {
        name: String,
        value: Expr,
    },
    Alias {
        name: String,
        value: String,
    },
    FnDef {
        name: String,
        params: Vec<String>,
        body: Vec<Stmt>,
    },
    If {
        cond: Cond,
        then_body: Vec<Stmt>,
        else_body: Option<Vec<Stmt>>,
    },
    For {
        var: String,
        iter: Expr,
        body: Vec<Stmt>,
    },
    Return(Option<Expr>),
    Chain(Chain),
}
