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

pub use ast::{
    AudioAccess, BootfsAccess, BtlAccess, CapsSpec, ChainOp, CmpOp, DirGrant, FbAccess, HxfsAccess,
    NetAccess, Stmt, WlanAccess,
};
pub use eval::{
    EvalAction, EvalResult, ExecOutcome, HostPathKind, PipelineCommand, ShellEnv, ShellHost,
};
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
        pipeline_log: Vec<(Vec<eval::PipelineCommand>, bool, bool)>,
        handle_pipelines: bool,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                files: BTreeMap::new(),
                last_caps: None,
                exec_log: Vec::new(),
                pipeline_log: Vec::new(),
                handle_pipelines: false,
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
                    stderr: String::new(),
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
                        stderr: String::new(),
                        clear_screen: false,
                        exit_requested: false,
                        child_pid: Some(42),
                    }
                }
                "argcheck" => ExecOutcome::ok_text(format!("argc={}", args.len())),
                "cat_stdin" => ExecOutcome::ok_text(
                    stdin
                        .map(Value::into_text)
                        .unwrap_or_default()
                        .trim_end_matches('\n'),
                ),
                "warn_cmd" => ExecOutcome {
                    status: 0,
                    output: Value::Text(String::from("out-line")),
                    stderr: String::from("err-line"),
                    clear_screen: false,
                    exit_requested: false,
                    child_pid: None,
                },
                _ => ExecOutcome::err(127, format!("unknown command: {name}")),
            }
        }

        fn exec_pipeline(
            &mut self,
            stages: &[eval::PipelineCommand],
            background: bool,
            capture_output: bool,
        ) -> Option<ExecOutcome> {
            self.pipeline_log
                .push((stages.to_vec(), background, capture_output));
            self.handle_pipelines.then(|| ExecOutcome {
                status: 0,
                output: Value::Text(String::from("pipeline-started")),
                stderr: String::new(),
                clear_screen: false,
                exit_requested: false,
                child_pid: Some(77),
            })
        }

        fn write_file(&mut self, path: &str, data: &[u8], append: bool) -> Result<(), String> {
            let entry = self.files.entry(String::from(path)).or_default();
            if !append {
                entry.clear();
            }
            entry.extend_from_slice(data);
            Ok(())
        }

        fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| format!("not found: {path}"))
        }

        fn stat_path(&mut self, path: &str, _follow: bool) -> Option<(HostPathKind, u64)> {
            if let Some(bytes) = self.files.get(path) {
                return Some((HostPathKind::File, bytes.len() as u64));
            }
            let prefix = if path == "/" {
                String::from("/")
            } else {
                format!("{path}/")
            };
            if self.files.keys().any(|k| k.starts_with(&prefix)) {
                return Some((HostPathKind::Dir, 0));
            }
            None
        }

        fn list_dir(&mut self, dir: &str) -> Vec<String> {
            let prefix = if dir == "/" || dir == "." {
                String::from("/")
            } else {
                format!("{}/", dir.trim_end_matches('/'))
            };
            let mut out = Vec::new();
            for k in self.files.keys() {
                if let Some(rest) = k.strip_prefix(&prefix) {
                    let leaf = rest.split('/').next().unwrap_or("");
                    if !leaf.is_empty() && !out.iter().any(|x| x == leaf) {
                        out.push(String::from(leaf));
                    }
                }
            }
            out
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
        assert_eq!(
            caps.to_caps_mask(),
            huesos_abi::auxv::caps_mask::HXFS_RO
                | huesos_abi::auxv::caps_mask::NET_RO
                | huesos_abi::auxv::caps_mask::NET_RW
                | huesos_abi::auxv::caps_mask::WLAN_RO
                | huesos_abi::auxv::caps_mask::WLAN_ADMIN
                | huesos_abi::auxv::caps_mask::BTL_RO
                | huesos_abi::auxv::caps_mask::BTL_RW
                | huesos_abi::auxv::caps_mask::BTL_ADMIN
                | huesos_abi::auxv::caps_mask::AUDIO_RO
                | huesos_abi::auxv::caps_mask::AUDIO_RW
                | huesos_abi::auxv::caps_mask::AUDIO_ADMIN
        );
    }

    #[test]
    fn test_caps_net_and_wlan_attenuation() {
        let Ok(ro) =
            CapsSpec::parse("hxfs=none, bootfs=none, fb=none, net=ro, wlan=ro, btl=ro, audio=ro")
        else {
            assert!(false, "parse net=ro, wlan=ro, btl=ro, audio=ro");
            return;
        };
        assert_eq!(ro.net, NetAccess::ReadOnly);
        assert_eq!(ro.wlan, WlanAccess::ReadOnly);
        assert_eq!(ro.btl, BtlAccess::ReadOnly);
        assert_eq!(ro.audio, AudioAccess::ReadOnly);
        assert_eq!(
            ro.to_caps_mask(),
            huesos_abi::auxv::caps_mask::NET_RO
                | huesos_abi::auxv::caps_mask::WLAN_RO
                | huesos_abi::auxv::caps_mask::BTL_RO
                | huesos_abi::auxv::caps_mask::AUDIO_RO
        );

        let Ok(rw) = CapsSpec::parse(
            "hxfs=none, bootfs=none, fb=none, net=none, wlan=none, btl=rw, audio=rw",
        ) else {
            assert!(false, "parse btl=rw, audio=rw");
            return;
        };
        assert_eq!(rw.btl, BtlAccess::ReadWrite);
        assert_eq!(rw.audio, AudioAccess::ReadWrite);
        assert_eq!(
            rw.to_caps_mask(),
            huesos_abi::auxv::caps_mask::BTL_RO
                | huesos_abi::auxv::caps_mask::BTL_RW
                | huesos_abi::auxv::caps_mask::AUDIO_RO
                | huesos_abi::auxv::caps_mask::AUDIO_RW
        );

        let Ok(none) = CapsSpec::parse(
            "hxfs=none, bootfs=none, fb=none, net=none, wlan=none, btl=none, audio=none",
        ) else {
            assert!(false, "parse net=none, wlan=none, btl=none, audio=none");
            return;
        };
        assert_eq!(none.net, NetAccess::None);
        assert_eq!(none.wlan, WlanAccess::None);
        assert_eq!(none.btl, BtlAccess::None);
        assert_eq!(none.audio, AudioAccess::None);
        assert_eq!(none.to_caps_mask(), 0);
    }

    #[test]
    fn test_while_break_continue_arith_and_elif() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();
        let script = r#"
            let i = 0
            let sum = 0
            while $i < 10 {
                i = $((i + 1))
                if $((i % 2)) == 0 {
                    continue
                } elif $i > 7 {
                    break
                } else {
                    sum = $((sum + i))
                }
            }
            echo "sum=$sum i=$i"
        "#;
        let Ok(res) = env.eval_script(script, &mut host) else {
            assert!(false, "eval while/arith/elif");
            return;
        };
        assert_eq!(res.render_text(), "sum=16 i=9");
    }

    #[test]
    fn test_fn_local_scoping_and_positional_args() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();
        let script = r#"
            let x = "outer"
            fn demo(a) {
                let x = "inner"
                echo "argc=$# arg1=$1 arg2=$2 x=$x"
            }
            demo alpha beta
            echo "after=$x"
        "#;
        let Ok(res) = env.eval_script(script, &mut host) else {
            assert!(false, "eval fn scope");
            return;
        };
        assert_eq!(
            res.render_text(),
            "argc=2 arg1=alpha arg2=beta x=inner\nafter=outer"
        );
    }

    #[test]
    fn test_test_builtin_negation_globs_and_io_redirects() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();
        let script = r#"
            echo "alpha" > /sub/a.txt
            echo "beta" > /sub/b.txt
            echo "skip" > /sub/c.log
            if [ -f /sub/a.txt ] && [ ! -d /sub/a.txt ] {
                echo "stat-ok"
            }
            echo /sub/*.txt
            cat_stdin < /sub/b.txt
            ! false
            echo "neg_status=$?"
            warn_cmd 2> /sub/err.log > /sub/out.log
            cat_stdin < /sub/err.log
        "#;
        let Ok(res) = env.eval_script(script, &mut host) else {
            assert!(false, "eval test/globs/redirects");
            return;
        };
        assert_eq!(
            res.render_text(),
            "stat-ok\n/sub/a.txt /sub/b.txt\nbeta\nneg_status=0\nerr-line"
        );
    }

    #[test]
    fn test_background_external_pipeline_is_delegated_as_one_job() {
        let mut env = ShellEnv::new();
        let mut host = MockHost::new();
        host.handle_pipelines = true;

        let Ok(foreground) = env.eval_script("seq 1 4 | grep 2", &mut host) else {
            assert!(false, "eval foreground external pipeline");
            return;
        };
        assert_eq!(foreground.render_text(), "pipeline-started");
        assert_eq!(host.pipeline_log.len(), 1);
        assert!(!host.pipeline_log[0].1);

        let Ok(result) = env.eval_script(
            "alias list = \"seq 1 4\"\nlist | grep 2 &\nlet foreground = \"foreground\"\necho $foreground",
            &mut host,
        ) else {
            assert!(false, "eval background pipeline");
            return;
        };

        assert_eq!(result.status, 0);
        assert_eq!(result.render_text(), "pipeline-started\nforeground");
        assert_eq!(env.last_pid, 77);
        assert_eq!(host.pipeline_log.len(), 2);
        let (stages, background, capture_output) = &host.pipeline_log[1];
        assert!(*background);
        assert!(!capture_output);
        assert_eq!(stages.len(), 2);
        assert_eq!(stages[0].name, "seq");
        assert_eq!(stages[0].args, alloc::vec!["1", "4"]);
        assert_eq!(stages[1].name, "grep");
        assert_eq!(stages[1].args, alloc::vec!["2"]);
    }

    #[test]
    fn test_top_level_script_positional_args_and_zero() {
        let mut env = ShellEnv::new();
        env.set_var("0", Value::Text(String::from("/e2e/run.hsh")));
        env.set_positional_args(alloc::vec![String::from("first"), String::from("second")]);
        let mut host = MockHost::new();
        let script = r#"
            echo "0=$0 argc=$# 1=$1 2=$2"
            echo $0:$#:$1:$2:$(echo ok)
            for item in $@ {
                echo "arg=$item"
            }
        "#;
        let Ok(res) = env.eval_script(script, &mut host) else {
            assert!(false, "eval script args");
            return;
        };
        assert_eq!(
            res.render_text(),
            "0=/e2e/run.hsh argc=2 1=first 2=second\n/e2e/run.hsh:2:first:second:ok\narg=first\narg=second"
        );
    }
}
