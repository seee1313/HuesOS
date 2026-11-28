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

/// Network service capability access level (`@caps(net=none|ro|rw)`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetAccess {
    None,
    ReadOnly,
    ReadWrite,
}

/// WLAN service capability access level (`@caps(wlan=none|ro|admin)`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WlanAccess {
    None,
    ReadOnly,
    Admin,
}

/// `/net/btl` Bluetooth transport capability access level (`@caps(btl=none|ro|rw|admin)`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BtlAccess {
    None,
    ReadOnly,
    ReadWrite,
    Admin,
}

/// `/dev/audio` service capability access level (`@caps(audio=none|ro|rw|admin)`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioAccess {
    None,
    ReadOnly,
    ReadWrite,
    Admin,
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
    pub net: NetAccess,
    pub wlan: WlanAccess,
    pub btl: BtlAccess,
    pub audio: AudioAccess,
}

impl Default for CapsSpec {
    fn default() -> Self {
        Self {
            hxfs: HxfsAccess::ReadWrite,
            bootfs: BootfsAccess::ReadOnly,
            fb: FbAccess::ReadOnly,
            block_rw: true,
            dir: None,
            net: NetAccess::ReadWrite,
            wlan: WlanAccess::Admin,
            btl: BtlAccess::Admin,
            audio: AudioAccess::Admin,
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
        match self.net {
            NetAccess::None => {}
            NetAccess::ReadOnly => mask |= caps_mask::NET_RO,
            NetAccess::ReadWrite => mask |= caps_mask::NET_RO | caps_mask::NET_RW,
        }
        match self.wlan {
            WlanAccess::None => {}
            WlanAccess::ReadOnly => mask |= caps_mask::WLAN_RO,
            WlanAccess::Admin => mask |= caps_mask::WLAN_RO | caps_mask::WLAN_ADMIN,
        }
        match self.btl {
            BtlAccess::None => {}
            BtlAccess::ReadOnly => mask |= caps_mask::BTL_RO,
            BtlAccess::ReadWrite => mask |= caps_mask::BTL_RO | caps_mask::BTL_RW,
            BtlAccess::Admin => {
                mask |= caps_mask::BTL_RO | caps_mask::BTL_RW | caps_mask::BTL_ADMIN
            }
        }
        match self.audio {
            AudioAccess::None => {}
            AudioAccess::ReadOnly => mask |= caps_mask::AUDIO_RO,
            AudioAccess::ReadWrite => mask |= caps_mask::AUDIO_RO | caps_mask::AUDIO_RW,
            AudioAccess::Admin => {
                mask |= caps_mask::AUDIO_RO | caps_mask::AUDIO_RW | caps_mask::AUDIO_ADMIN
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
                "net" => {
                    out.net = match val {
                        "none" => NetAccess::None,
                        "ro" => NetAccess::ReadOnly,
                        "rw" => NetAccess::ReadWrite,
                        _ => return Err(alloc::format!("invalid net cap '{val}'")),
                    };
                }
                "wlan" => {
                    out.wlan = match val {
                        "none" => WlanAccess::None,
                        "ro" => WlanAccess::ReadOnly,
                        "admin" | "rw" => WlanAccess::Admin,
                        _ => return Err(alloc::format!("invalid wlan cap '{val}'")),
                    };
                }
                "btl" => {
                    out.btl = match val {
                        "none" => BtlAccess::None,
                        "ro" => BtlAccess::ReadOnly,
                        "rw" => BtlAccess::ReadWrite,
                        "admin" => BtlAccess::Admin,
                        _ => return Err(alloc::format!("invalid btl cap '{val}'")),
                    };
                }
                "audio" => {
                    out.audio = match val {
                        "none" => AudioAccess::None,
                        "ro" => AudioAccess::ReadOnly,
                        "rw" => AudioAccess::ReadWrite,
                        "admin" => AudioAccess::Admin,
                        _ => return Err(alloc::format!("invalid audio cap '{val}'")),
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
                        (val, false)
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
    ArithSubst(String),
}

/// Argument expression (preserves exact boundaries; no POSIX word splitting).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgExpr {
    pub parts: Vec<WordPart>,
    pub raw_var_only: Option<String>,
    /// True if any part was quoted (`'...'` or `"..."`), suppressing `*`/`?` globbing.
    pub quoted: bool,
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

/// Conditional expression in `if ... { ... }` or `while ... { ... }`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Cond {
    Compare {
        left: ArgExpr,
        op: CmpOp,
        right: ArgExpr,
    },
    Truthy(ArgExpr),
    Test(Vec<ArgExpr>),
    Not(alloc::boxed::Box<Cond>),
    And(alloc::boxed::Box<Cond>, alloc::boxed::Box<Cond>),
    Or(alloc::boxed::Box<Cond>, alloc::boxed::Box<Cond>),
}

/// Output redirection to an HxFS file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Redirect {
    Truncate(ArgExpr),
    Append(ArgExpr),
}

/// Stderr redirection on a command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrRedirect {
    ToStdout,
    Truncate(ArgExpr),
    Append(ArgExpr),
}

/// Single command invocation in a pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandCall {
    pub caps: Option<CapsSpec>,
    pub negated: bool,
    pub name: ArgExpr,
    pub args: Vec<ArgExpr>,
    pub stdin_redirect: Option<ArgExpr>,
    pub redirect: Option<Redirect>,
    pub err_redirect: Option<ErrRedirect>,
}

/// Pipeline `cmd1 | cmd2 | ...`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pipeline {
    pub stages: Vec<CommandCall>,
    /// Run the external pipeline in the background (`command &`).
    pub background: bool,
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
    Assign {
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
    While {
        cond: Cond,
        body: Vec<Stmt>,
    },
    For {
        var: String,
        iter: Expr,
        body: Vec<Stmt>,
    },
    Break,
    Continue,
    Return(Option<Expr>),
    Chain(Chain),
}
