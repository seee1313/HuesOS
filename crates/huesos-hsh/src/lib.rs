//! `hsh` — HuesOS's capability-first, structured-pipeline shell engine.
//!
//! Combines Plan 9 `rc` predictability (no POSIX word splitting), Rust-style
//! control flow (`if ... { ... } else { ... }`, `for ... in ...`, `fn`),
//! Nushell-inspired structured `Table` pipes (`where`, `select`, `sort`,
//! `head`, `tail`, `count`, `grep`), and `@caps(...)` capability attenuation.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ast;
pub mod eval;
pub mod lexer;
pub mod parser;
pub mod value;

pub use ast::{BootfsAccess, CapsSpec, ChainOp, CmpOp, DirGrant, FbAccess, HxfsAccess, Stmt};
pub use eval::{EvalAction, EvalResult, ExecOutcome, ShellEnv, ShellHost};
pub use lexer::{highlight_line, HighlightKind, HighlightSpan};
pub use parser::{parse_script, ParseError};
pub use value::{Table, Value};

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::*;

    struct MockHost {
        files: BTreeMap<String, Vec<u8>>,
        last_caps: Option<CapsSpec>,
        exec_log: Vec<(String, Vec<String>)>,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                files: BTreeMap::new(),
                last_caps: None,
                exec_log: Vec::new(),
            }
        }
    }

    impl ShellHost for MockHost {
        fn exec_command(
            &mut self,
            caps: Option<&CapsSpec>,
            name: &str,
            args: &[String],
            stdin: Option<&Value>,
        ) -> ExecOutcome {
            self.last_caps = caps.cloned();
            self.exec_log.push((String::from(name), args.to_vec()));
            match name {
                "cls" => ExecOutcome {
                    status: 0,
                    output: Value::Empty,
                    clear_screen: true,
                    exit_requested: false,
                    child_pid: None,
                },
                "help" => ExecOutcome::ok_text("help-text"),
                "ok" => ExecOutcome::ok_text("ok"),
                "fail" => ExecOutcome::err(7, "boom"),
                "fdisk" => {
                    if let Some(c) = caps {
                        if matches!(c.hxfs, HxfsAccess::ReadOnly | HxfsAccess::None)
                            && args.first().map(String::as_str) == Some("add")
                        {
                            return ExecOutcome::err(1, "AccessDenied");
                        }
                    }
                    let tsv = "part\ttype\tsize_mib\n1\tefi\t64\n2\thxfs\t512\n3\tswap\t128\n";
                    let tbl = Table::from_tsv(tsv)
                        .map(Value::Table)
                        .unwrap_or(Value::Empty);
                    ExecOutcome {
                        status: 0,
                        output: tbl,
                        clear_screen: false,
                        exit_requested: false,
                        child_pid: Some(42),
                    }
                }
                "argcheck" => ExecOutcome::ok_text(format!("argc={}", args.len())),
                "cat_stdin" => {
                    ExecOutcome::ok_text(stdin.map(Value::into_text).unwrap_or_default())
                }
                _ => ExecOutcome::err(127, format!("unknown command: {name}")),
            }
        }

        fn write_file(&mut self, path: &str, data: &[u8], append: bool) -> Result<(), String> {
            let entry = self.files.entry(String::from(path)).or_default();
            if !append {
                entry.clear();
            }
            entry.extend_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn test_chains_and_cls_ordering() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();

        let Ok(res) = env.eval_script("cls ; help", &mut host) else {
            assert!(false, "eval cls ; help");
            return;
        };
        assert_eq!(res.status, 0);
        assert_eq!(
            res.actions,
            alloc::vec![
                EvalAction::ClearScreen,
                EvalAction::Output(Value::Text(String::from("help-text")))
            ]
        );

        let Ok(res2) = env.eval_script("fail && ok || help", &mut host) else {
            assert!(false, "eval chain");
            return;
        };
        assert_eq!(res2.status, 0);
        assert_eq!(res2.render_text(), "boom\nhelp-text");
    }

    #[test]
    fn test_no_posix_word_splitting_and_cmd_subst() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();
        let Ok(res) = env.eval_script(
            "let msg = \"hello   world\"\nargcheck $msg\nlet cap = $(echo \"$msg\")\necho $cap",
            &mut host,
        ) else {
            assert!(false, "eval word splitting");
            return;
        };
        assert_eq!(res.render_text(), "argc=1\nhello   world");
    }

    #[test]
    fn test_functions_if_for_and_aliases() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();
        let script = r#"
            alias hi = "echo greeting"
            fn check(x) {
                if $x contains "hx" {
                    echo "yes:$x"
                } else {
                    echo "no:$x"
                }
            }
            hi world
            for item in [efi, hxfs, swap] {
                check $item
            }
        "#;
        let Ok(res) = env.eval_script(script, &mut host) else {
            assert!(false, "eval fn/for/if");
            return;
        };
        assert_eq!(
            res.render_text(),
            "greeting world\nno:efi\nyes:hxfs\nno:swap"
        );
    }

    #[test]
    fn test_structured_table_pipeline_and_redirects() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();
        let Ok(res) = env.eval_script(
            "fdisk list | where type == hxfs | select part size_mib > /out.txt",
            &mut host,
        ) else {
            assert!(false, "eval pipe");
            return;
        };
        assert_eq!(res.status, 0);
        assert_eq!(env.last_pid, 42);
        let Some(bytes) = host.files.get("/out.txt") else {
            assert!(false, "missing redirected file");
            return;
        };
        let Ok(written) = core::str::from_utf8(bytes) else {
            assert!(false, "utf8");
            return;
        };
        assert!(written.contains("part"));
        assert!(written.contains("512"));
        assert!(!written.contains("efi"));

        let Ok(res2) = env.eval_script(
            "fdisk list | sort --desc size_mib | head 1 | count",
            &mut host,
        ) else {
            assert!(false, "eval sort/head/count");
            return;
        };
        assert_eq!(res2.render_text(), "1");
    }

    #[test]
    fn test_caps_parsing_and_enforcement() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();
        let Ok(res) = env.eval_script(
            "@caps(hxfs=ro, bootfs=none, fb=none, dir=/sub:ro) fdisk add",
            &mut host,
        ) else {
            assert!(false, "eval caps");
            return;
        };
        assert_eq!(res.status, 1);
        assert_eq!(res.render_text(), "AccessDenied");
        let Some(caps) = host.last_caps else {
            assert!(false, "caps recorded");
            return;
        };
        assert_eq!(caps.hxfs, HxfsAccess::ReadOnly);
        assert_eq!(caps.bootfs, BootfsAccess::None);
        assert_eq!(caps.fb, FbAccess::None);
        assert_eq!(
            caps.dir,
            Some(DirGrant {
                path: String::from("/sub"),
                read_only: true
            })
        );
        assert_eq!(caps.to_caps_mask(), huesos_abi::auxv::caps_mask::HXFS_RO);
    }
}
