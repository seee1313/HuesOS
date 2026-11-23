//! AST evaluator for `hsh`.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::ast::{
    ArgExpr, CapsSpec, Chain, ChainOp, CommandCall, Cond, ErrRedirect, Expr, Pipeline, Redirect,
    Stmt, WordPart,
};
use crate::parser::parse_script;
use crate::value::{compare_cells, try_apply_pipe_builtin, Value};

const MAX_CALL_DEPTH: usize = 32;
const MAX_WHILE_ITERATIONS: usize = 100_000;

/// Kind of filesystem entry inspected by `test`/`[` or globbing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPathKind {
    File,
    Dir,
    Symlink,
}

/// Single command execution result returned by [`ShellHost::exec_command`].
#[derive(Clone, Debug)]
pub struct ExecOutcome {
    pub status: i32,
    pub output: Value,
    pub stderr: String,
    pub clear_screen: bool,
    pub exit_requested: bool,
    pub child_pid: Option<u64>,
}

impl ExecOutcome {
    pub fn ok(output: Value) -> Self {
        Self {
            status: 0,
            output,
            stderr: String::new(),
            clear_screen: false,
            exit_requested: false,
            child_pid: None,
        }
    }

    pub fn ok_text(s: impl Into<String>) -> Self {
        Self::ok(Value::Text(s.into()))
    }

    pub fn err(status: i32, msg: impl Into<String>) -> Self {
        let m = msg.into();
        Self {
            status,
            output: Value::Text(m.clone()),
            stderr: m,
            clear_screen: false,
            exit_requested: false,
            child_pid: None,
        }
    }
}

/// One fully expanded command in a pipeline that the host can run as a
/// concurrently connected stream of external processes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineCommand {
    pub caps: Option<CapsSpec>,
    pub name: String,
    pub args: Vec<String>,
}

/// Host environment callbacks implemented by `terminal` (or a mock in tests).
pub trait ShellHost {
    fn exec_command(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
    ) -> ExecOutcome;

    /// Execute a command stage with explicit `capture_output` intent.
    fn exec_command_mode(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
        _capture_output: bool,
    ) -> ExecOutcome {
        self.exec_command(caps, name, args, stdin)
    }

    /// Execute a command stage with explicit `separate_stderr` control (used for `2>` / `2>>`).
    fn exec_command_ex(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
        capture_output: bool,
        _separate_stderr: bool,
    ) -> ExecOutcome {
        self.exec_command_mode(caps, name, args, stdin, capture_output)
    }

    /// Start or execute a pipeline using directly connected stream channels.
    /// `None` asks the evaluator to use its in-memory/builtin path instead.
    /// Hosts must retain process capabilities for background jobs and must not
    /// treat a displayed PID/KOID as authority.
    fn exec_pipeline(
        &mut self,
        _stages: &[PipelineCommand],
        _background: bool,
        _capture_output: bool,
    ) -> Option<ExecOutcome> {
        None
    }

    /// Poll and reap completed background jobs without blocking.
    fn poll_background_jobs(&mut self) {}

    /// Terminate jobs still owned by the shell before it exits.
    fn shutdown_background_jobs(&mut self) {}

    fn write_file(&mut self, path: &str, data: &[u8], append: bool) -> Result<(), String>;

    fn read_file(&mut self, _path: &str) -> Result<Vec<u8>, String> {
        Err(String::from("read_file unsupported by host"))
    }

    /// Stat a path (`follow = true` for `-e/-f/-d/-s`, `false` for `-L`).
    fn stat_path(&mut self, _path: &str, _follow: bool) -> Option<(HostPathKind, u64)> {
        None
    }

    /// List child entry names of `dir` for glob expansion.
    fn list_dir(&mut self, _dir: &str) -> Vec<String> {
        Vec::new()
    }
}

/// Ordered side-effect produced by evaluating an `hsh` script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvalAction {
    ClearScreen,
    Output(Value),
    Exit,
}

/// Aggregate result of evaluating a script or interactive line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalResult {
    pub status: i32,
    pub actions: Vec<EvalAction>,
}

impl EvalResult {
    /// Collect all non-empty textual outputs joined cleanly.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for act in &self.actions {
            if let EvalAction::Output(val) = act {
                let txt = val.into_text();
                if !txt.is_empty() {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&txt);
                }
            }
        }
        out
    }
}

/// Persistent `hsh` interpreter state (variables, aliases, functions, `$status`, `$pid`).
pub struct ShellEnv {
    vars: BTreeMap<String, Value>,
    aliases: BTreeMap<String, String>,
    functions: BTreeMap<String, (Vec<String>, Vec<Stmt>)>,
    local_frames: Vec<BTreeMap<String, Option<Value>>>,
    positional_stack: Vec<Vec<String>>,
    pub last_status: i32,
    pub last_pid: u64,
    depth: usize,
    capture_depth: usize,
}

impl Default for ShellEnv {
    fn default() -> Self {
        Self::new()
    }
}

enum BlockSignal {
    Return(Value),
    Break,
    Continue,
}

impl ShellEnv {
    pub fn new() -> Self {
        Self {
            vars: BTreeMap::new(),
            aliases: BTreeMap::new(),
            functions: BTreeMap::new(),
            local_frames: Vec::new(),
            positional_stack: Vec::new(),
            last_status: 0,
            last_pid: 0,
            depth: 0,
            capture_depth: 0,
        }
    }

    pub fn vars(&self) -> &BTreeMap<String, Value> {
        &self.vars
    }

    pub fn aliases(&self) -> &BTreeMap<String, String> {
        &self.aliases
    }

    pub fn functions(&self) -> &BTreeMap<String, (Vec<String>, Vec<Stmt>)> {
        &self.functions
    }

    pub fn set_var(&mut self, name: impl Into<String>, value: Value) {
        self.vars.insert(name.into(), value);
    }

    pub fn set_positional_args(&mut self, args: Vec<String>) {
        if let Some(top) = self.positional_stack.last_mut() {
            *top = args;
        } else {
            self.positional_stack.push(args);
        }
    }

    fn record_local(&mut self, name: &str) {
        if let Some(frame) = self.local_frames.last_mut() {
            if !frame.contains_key(name) {
                let prev = self.vars.get(name).cloned();
                frame.insert(String::from(name), prev);
            }
        }
    }

    pub fn get_var(&self, name: &str) -> Value {
        match name {
            "status" | "?" => Value::Int(i64::from(self.last_status)),
            "pid" => Value::Int(self.last_pid as i64),
            "#" => {
                let count = self.positional_stack.last().map_or(0, Vec::len);
                Value::Int(count as i64)
            }
            "@" => {
                if let Some(pos) = self.positional_stack.last() {
                    Value::List(pos.iter().cloned().map(Value::Text).collect())
                } else {
                    Value::Empty
                }
            }
            _ => {
                if name == "0" {
                    return self.vars.get("0").cloned().unwrap_or(Value::Empty);
                }
                if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
                    if let Ok(idx) = name.parse::<usize>() {
                        if idx >= 1 {
                            if let Some(pos) = self.positional_stack.last() {
                                return pos
                                    .get(idx - 1)
                                    .cloned()
                                    .map(Value::Text)
                                    .unwrap_or(Value::Empty);
                            }
                        }
                    }
                }
                self.vars.get(name).cloned().unwrap_or(Value::Empty)
            }
        }
    }

    /// Parse and execute an `hsh` script string against `host`.
    pub fn eval_script(
        &mut self,
        input: &str,
        host: &mut dyn ShellHost,
    ) -> Result<EvalResult, String> {
        host.poll_background_jobs();
        let stmts =
            parse_script(input).map_err(|e| format!("parse error @{}: {}", e.offset, e.message))?;
        let mut actions = Vec::new();
        let _sig = self.exec_stmts(&stmts, host, &mut actions)?;
        Ok(EvalResult {
            status: self.last_status,
            actions,
        })
    }

    fn exec_stmts(
        &mut self,
        stmts: &[Stmt],
        host: &mut dyn ShellHost,
        actions: &mut Vec<EvalAction>,
    ) -> Result<Option<BlockSignal>, String> {
        for stmt in stmts {
            host.poll_background_jobs();
            match stmt {
                Stmt::Let { name, value } => {
                    let val = self.eval_expr(value, host)?;
                    self.record_local(name);
                    self.vars.insert(name.clone(), val);
                    self.last_status = 0;
                }
                Stmt::Assign { name, value } => {
                    let val = self.eval_expr(value, host)?;
                    self.vars.insert(name.clone(), val);
                    self.last_status = 0;
                }
                Stmt::Alias { name, value } => {
                    self.aliases.insert(name.clone(), value.clone());
                    self.last_status = 0;
                }
                Stmt::FnDef { name, params, body } => {
                    self.functions
                        .insert(name.clone(), (params.clone(), body.clone()));
                    self.last_status = 0;
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    let matched = self.eval_cond(cond, host)?;
                    if matched {
                        if let Some(sig) = self.exec_stmts(then_body, host, actions)? {
                            return Ok(Some(sig));
                        }
                    } else if let Some(eb) = else_body {
                        if let Some(sig) = self.exec_stmts(eb, host, actions)? {
                            return Ok(Some(sig));
                        }
                    }
                }
                Stmt::While { cond, body } => {
                    let mut iters = 0usize;
                    while self.eval_cond(cond, host)? {
                        iters += 1;
                        if iters > MAX_WHILE_ITERATIONS {
                            return Err(String::from("while loop iteration limit exceeded"));
                        }
                        if let Some(sig) = self.exec_stmts(body, host, actions)? {
                            match sig {
                                BlockSignal::Break => break,
                                BlockSignal::Continue => continue,
                                ret @ BlockSignal::Return(_) => return Ok(Some(ret)),
                            }
                        }
                    }
                }
                Stmt::For { var, iter, body } => {
                    let list_val = self.eval_expr(iter, host)?;
                    let items: Vec<Value> = match list_val {
                        Value::List(items) => items,
                        Value::Table(tbl) => tbl
                            .rows
                            .into_iter()
                            .map(|r| Value::Text(r.join("\t")))
                            .collect(),
                        Value::Text(s) => s
                            .lines()
                            .filter(|l| !l.is_empty())
                            .map(|l| Value::Text(String::from(l)))
                            .collect(),
                        Value::Empty => Vec::new(),
                        other => vec![other],
                    };
                    let saved = self.vars.get(var).cloned();
                    for item in items {
                        self.vars.insert(var.clone(), item);
                        if let Some(sig) = self.exec_stmts(body, host, actions)? {
                            match sig {
                                BlockSignal::Break => break,
                                BlockSignal::Continue => continue,
                                ret @ BlockSignal::Return(_) => {
                                    match saved {
                                        Some(v) => {
                                            self.vars.insert(var.clone(), v);
                                        }
                                        None => {
                                            self.vars.remove(var);
                                        }
                                    }
                                    return Ok(Some(ret));
                                }
                            }
                        }
                    }
                    match saved {
                        Some(v) => {
                            self.vars.insert(var.clone(), v);
                        }
                        None => {
                            self.vars.remove(var);
                        }
                    }
                }
                Stmt::Break => return Ok(Some(BlockSignal::Break)),
                Stmt::Continue => return Ok(Some(BlockSignal::Continue)),
                Stmt::Return(expr) => {
                    let val = match expr {
                        Some(e) => self.eval_expr(e, host)?,
                        None => Value::Empty,
                    };
                    return Ok(Some(BlockSignal::Return(val)));
                }
                Stmt::Chain(chain) => {
                    self.exec_chain(chain, host, actions)?;
                }
            }
        }
        Ok(None)
    }

    fn eval_cond(&mut self, cond: &Cond, host: &mut dyn ShellHost) -> Result<bool, String> {
        match cond {
            Cond::Compare { left, op, right } => {
                let l = self.eval_arg_text(left, host)?;
                let r = self.eval_arg_text(right, host)?;
                Ok(compare_cells(&l, *op, &r))
            }
            Cond::Truthy(arg) => {
                let val = self.eval_arg_value(arg, host)?;
                Ok(val.is_truthy())
            }
            Cond::Test(args) => {
                let mut evaluated = Vec::with_capacity(args.len());
                for a in args {
                    evaluated.push(self.eval_arg_text(a, host)?);
                }
                Ok(eval_test_slice(&evaluated, host))
            }
            Cond::Not(inner) => Ok(!self.eval_cond(inner, host)?),
            Cond::And(lhs, rhs) => {
                if !self.eval_cond(lhs, host)? {
                    Ok(false)
                } else {
                    self.eval_cond(rhs, host)
                }
            }
            Cond::Or(lhs, rhs) => {
                if self.eval_cond(lhs, host)? {
                    Ok(true)
                } else {
                    self.eval_cond(rhs, host)
                }
            }
        }
    }

    fn eval_expr(&mut self, expr: &Expr, host: &mut dyn ShellHost) -> Result<Value, String> {
        match expr {
            Expr::Scalar(arg) => self.eval_arg_value(arg, host),
            Expr::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.eval_expr(item, host)?);
                }
                Ok(Value::List(out))
            }
        }
    }

    fn eval_arg_value(&mut self, arg: &ArgExpr, host: &mut dyn ShellHost) -> Result<Value, String> {
        if let Some(var_name) = &arg.raw_var_only {
            return Ok(self.get_var(var_name));
        }
        if arg.parts.len() == 1 && !arg.quoted {
            if let WordPart::ArithSubst(expr) = &arg.parts[0] {
                let n = self.eval_arith_expr(expr)?;
                return Ok(Value::Int(n));
            }
        }
        Ok(Value::Text(self.eval_arg_text(arg, host)?))
    }

    fn eval_arg_text(&mut self, arg: &ArgExpr, host: &mut dyn ShellHost) -> Result<String, String> {
        let mut out = String::new();
        for part in &arg.parts {
            match part {
                WordPart::Literal(s) => out.push_str(s),
                WordPart::Var(name) => {
                    if name == "@" {
                        if let Some(pos) = self.positional_stack.last() {
                            out.push_str(&pos.join(" "));
                        }
                    } else {
                        out.push_str(&self.get_var(name).into_text());
                    }
                }
                WordPart::ArithSubst(expr) => {
                    let n = self.eval_arith_expr(expr)?;
                    out.push_str(&format!("{n}"));
                }
                WordPart::CmdSubst(stmts) => {
                    let mut sub_actions = Vec::new();
                    self.capture_depth += 1;
                    let sub_exec = self.exec_stmts(stmts, host, &mut sub_actions);
                    self.capture_depth -= 1;
                    let _ = sub_exec?;
                    let sub_res = EvalResult {
                        status: self.last_status,
                        actions: sub_actions,
                    };
                    let txt = sub_res.render_text();
                    out.push_str(txt.trim_end_matches(&['\r', '\n'][..]));
                }
            }
        }
        Ok(out)
    }

    fn eval_arith_expr(&self, expr: &str) -> Result<i64, String> {
        let mut p = ArithParser {
            bytes: expr.as_bytes(),
            pos: 0,
            env: self,
        };
        let val = p.parse_or()?;
        p.skip_ws();
        if p.pos < p.bytes.len() {
            return Err(format!(
                "unexpected token in arithmetic expression '{expr}'"
            ));
        }
        Ok(val)
    }

    fn expand_arg_with_globs(
        &mut self,
        arg: &ArgExpr,
        host: &mut dyn ShellHost,
    ) -> Result<Vec<String>, String> {
        if !arg.quoted && arg.parts.len() == 1 {
            if let WordPart::Var(v) = &arg.parts[0] {
                if v == "@" {
                    return Ok(self.positional_stack.last().cloned().unwrap_or_default());
                }
            }
        }
        let text = self.eval_arg_text(arg, host)?;
        if arg.quoted || (!text.contains('*') && !text.contains('?')) {
            return Ok(vec![text]);
        }
        let (dir_prefix, dir_query, pat) = match text.rsplit_once('/') {
            Some(("", p)) => (String::from("/"), String::from("/"), p),
            Some((d, p)) => (format!("{d}/"), String::from(d), p),
            None => (String::new(), String::from("."), text.as_str()),
        };
        if dir_prefix.contains('*') || dir_prefix.contains('?') {
            return Ok(vec![text]);
        }
        let entries = host.list_dir(&dir_query);
        let mut matched: Vec<String> = entries
            .into_iter()
            .filter(|name| {
                if name.starts_with('.') && !pat.starts_with('.') {
                    return false;
                }
                glob_match_bytes(pat.as_bytes(), name.as_bytes())
            })
            .map(|name| format!("{dir_prefix}{name}"))
            .collect();
        matched.sort();
        matched.dedup();
        if matched.is_empty() {
            Ok(vec![text])
        } else {
            Ok(matched)
        }
    }

    fn exec_chain(
        &mut self,
        chain: &Chain,
        host: &mut dyn ShellHost,
        actions: &mut Vec<EvalAction>,
    ) -> Result<(), String> {
        self.exec_pipeline(&chain.first, host, actions)?;
        for (op, pipe) in &chain.rest {
            let should_run = match op {
                ChainOp::Seq => true,
                ChainOp::And => self.last_status == 0,
                ChainOp::Or => self.last_status != 0,
            };
            if should_run {
                self.exec_pipeline(pipe, host, actions)?;
            }
        }
        Ok(())
    }

    fn prepare_external_pipeline(
        &mut self,
        pipe: &Pipeline,
        host: &mut dyn ShellHost,
    ) -> Result<Option<Vec<PipelineCommand>>, String> {
        let mut prepared = Vec::with_capacity(pipe.stages.len());
        for stage in &pipe.stages {
            if stage.stdin_redirect.is_some()
                || stage.redirect.is_some()
                || stage.err_redirect.is_some()
            {
                if pipe.background {
                    return Err(String::from(
                        "background pipelines do not support redirection yet",
                    ));
                }
                return Ok(None);
            }
            let raw_name = self.eval_arg_text(&stage.name, host)?;
            let no_glob_cmd = raw_name == "where" || raw_name == "find";
            let mut args = Vec::with_capacity(stage.args.len());
            let mut skip_glob_next = false;
            for arg in &stage.args {
                if no_glob_cmd || skip_glob_next {
                    skip_glob_next = false;
                    args.push(self.eval_arg_text(arg, host)?);
                } else {
                    let expanded = self.expand_arg_with_globs(arg, host)?;
                    if expanded.len() == 1
                        && raw_name == "grep"
                        && matches!(expanded[0].as_str(), "-e" | "--regexp")
                    {
                        skip_glob_next = true;
                    }
                    args.extend(expanded);
                }
            }
            let (name, args) = if let Some(alias) = self.aliases.get(&raw_name) {
                let mut parts = alias.split_whitespace();
                if let Some(target) = parts.next() {
                    let mut expanded: Vec<String> = parts.map(String::from).collect();
                    expanded.extend(args);
                    (String::from(target), expanded)
                } else {
                    (raw_name, args)
                }
            } else {
                (raw_name, args)
            };

            let is_shell_command = self.functions.contains_key(&name)
                || (stage.caps.is_none()
                    && matches!(
                        name.as_str(),
                        "cls"
                            | "clear"
                            | "true"
                            | ":"
                            | "false"
                            | "echo"
                            | "printf"
                            | "test"
                            | "["
                            | "export"
                            | "env"
                            | "exit"
                            | "help"
                            | "pwd"
                            | "cd"
                            | "history"
                            | "jobs"
                            | "fg"
                            | "wait"
                            | "kill"
                            | "caps"
                            | "font"
                            | "doom"
                            | "snake"
                            | "shutdown"
                            | "where"
                            | "select"
                            | "count"
                    ));
            if is_shell_command {
                if pipe.background {
                    return Err(String::from(
                        "background mode supports external commands only",
                    ));
                }
                return Ok(None);
            }
            prepared.push(PipelineCommand {
                caps: stage.caps.clone(),
                name,
                args,
            });
        }
        Ok(Some(prepared))
    }

    fn exec_pipeline(
        &mut self,
        pipe: &Pipeline,
        host: &mut dyn ShellHost,
        actions: &mut Vec<EvalAction>,
    ) -> Result<(), String> {
        if pipe.stages.len() > 1 || pipe.background {
            if let Some(stages) = self.prepare_external_pipeline(pipe, host)? {
                let capture_output = self.capture_depth > 0 || self.depth > 0;
                if let Some(mut outcome) =
                    host.exec_pipeline(&stages, pipe.background, capture_output)
                {
                    if pipe.stages.last().is_some_and(|stage| stage.negated) {
                        outcome.status = if outcome.status == 0 { 1 } else { 0 };
                    }
                    self.last_status = outcome.status;
                    if let Some(pid) = outcome.child_pid {
                        self.last_pid = pid;
                    }
                    if outcome.clear_screen {
                        actions.push(EvalAction::ClearScreen);
                    }
                    if outcome.exit_requested {
                        actions.push(EvalAction::Exit);
                    }
                    if !matches!(outcome.output, Value::Empty) {
                        actions.push(EvalAction::Output(outcome.output));
                    }
                    return Ok(());
                }
            }
        }

        let mut current_val: Option<Value> = None;
        let mut final_redirect: Option<&Redirect> = None;

        for (idx, stage) in pipe.stages.iter().enumerate() {
            let is_last = idx + 1 == pipe.stages.len();
            if is_last {
                final_redirect = stage.redirect.as_ref();
            }

            let stage_stdin_owned = if let Some(in_expr) = &stage.stdin_redirect {
                let in_path = self.eval_arg_text(in_expr, host)?;
                match host.read_file(&in_path) {
                    Ok(bytes) => Some(Value::Text(String::from_utf8_lossy(&bytes).into_owned())),
                    Err(err) => {
                        self.last_status = if stage.negated { 0 } else { 1 };
                        actions.push(EvalAction::Output(Value::Text(err)));
                        return Ok(());
                    }
                }
            } else {
                None
            };

            let effective_stdin = stage_stdin_owned.as_ref().or(current_val.as_ref());
            let separate_stderr = matches!(
                stage.err_redirect,
                Some(ErrRedirect::Truncate(_) | ErrRedirect::Append(_))
            );
            let capture_output = self.capture_depth > 0
                || self.depth > 0
                || !is_last
                || stage.redirect.is_some()
                || stage.err_redirect.is_some();

            let mut outcome = self.exec_stage(
                stage,
                effective_stdin,
                capture_output,
                separate_stderr,
                host,
            )?;

            if let Some(err_redir) = &stage.err_redirect {
                match err_redir {
                    ErrRedirect::ToStdout => {}
                    ErrRedirect::Truncate(p) | ErrRedirect::Append(p) => {
                        let append = matches!(err_redir, ErrRedirect::Append(_));
                        let path = self.eval_arg_text(p, host)?;
                        let mut err_txt = outcome.stderr.clone();
                        if !err_txt.is_empty() && !err_txt.ends_with('\n') {
                            err_txt.push('\n');
                        }
                        if let Err(err) = host.write_file(&path, err_txt.as_bytes(), append) {
                            outcome.status = 1;
                            actions.push(EvalAction::Output(Value::Text(err)));
                        }
                    }
                }
            }

            if stage.negated {
                outcome.status = if outcome.status == 0 { 1 } else { 0 };
            }
            self.last_status = outcome.status;
            if let Some(pid) = outcome.child_pid {
                self.last_pid = pid;
            }
            if outcome.clear_screen {
                actions.push(EvalAction::ClearScreen);
            }
            if outcome.exit_requested {
                actions.push(EvalAction::Exit);
            }

            if !is_last {
                if let Some(mid_redir) = &stage.redirect {
                    let (p, append) = match mid_redir {
                        Redirect::Truncate(p) => (p, false),
                        Redirect::Append(p) => (p, true),
                    };
                    let path = self.eval_arg_text(p, host)?;
                    let mut txt = outcome.output.into_text();
                    if !txt.is_empty() && !txt.ends_with('\n') {
                        txt.push('\n');
                    }
                    let _ = host.write_file(&path, txt.as_bytes(), append);
                    current_val = Some(Value::Empty);
                } else {
                    current_val = Some(outcome.output);
                }
            } else {
                current_val = Some(outcome.output);
            }
        }

        if let Some(val) = current_val {
            if let Some(redir) = final_redirect {
                let (path_expr, append) = match redir {
                    Redirect::Truncate(p) => (p, false),
                    Redirect::Append(p) => (p, true),
                };
                let path = self.eval_arg_text(path_expr, host)?;
                let mut text = val.into_text();
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                match host.write_file(&path, text.as_bytes(), append) {
                    Ok(()) => {}
                    Err(err) => {
                        self.last_status = 1;
                        actions.push(EvalAction::Output(Value::Text(err)));
                    }
                }
            } else if !matches!(val, Value::Empty) {
                actions.push(EvalAction::Output(val));
            }
        }
        Ok(())
    }

    fn exec_stage(
        &mut self,
        stage: &CommandCall,
        stdin: Option<&Value>,
        capture_output: bool,
        separate_stderr: bool,
        host: &mut dyn ShellHost,
    ) -> Result<ExecOutcome, String> {
        let raw_name = self.eval_arg_text(&stage.name, host)?;
        let no_glob_cmd = raw_name == "where" || raw_name == "find";
        let mut args = Vec::with_capacity(stage.args.len());
        let mut skip_glob_next = false;
        for a in &stage.args {
            if no_glob_cmd || skip_glob_next {
                skip_glob_next = false;
                let s = self.eval_arg_text(a, host)?;
                args.push(s);
            } else {
                let expanded = self.expand_arg_with_globs(a, host)?;
                if expanded.len() == 1
                    && (raw_name == "grep" && matches!(expanded[0].as_str(), "-e" | "--regexp"))
                {
                    skip_glob_next = true;
                }
                args.extend(expanded);
            }
        }

        // Single-level alias expansion (only when no @caps overrides or preserves @caps).
        let (cmd_name, final_args) = if let Some(alias_val) = self.aliases.get(&raw_name) {
            let mut parts = alias_val.split_whitespace();
            if let Some(target_cmd) = parts.next() {
                let mut expanded: Vec<String> = parts.map(String::from).collect();
                expanded.extend(args);
                (String::from(target_cmd), expanded)
            } else {
                (raw_name, args)
            }
        } else {
            (raw_name, args)
        };

        // First-class `cls` / `clear`
        if cmd_name == "cls" || cmd_name == "clear" {
            let mut outcome = host.exec_command(stage.caps.as_ref(), "cls", &final_args, stdin);
            outcome.clear_screen = true;
            outcome.status = 0;
            return Ok(outcome);
        }

        // Pure table/stream pipeline filters
        if let Some(pipe_in) = stdin {
            match try_apply_pipe_builtin(&cmd_name, &final_args, pipe_in) {
                Ok(Some(v)) => return Ok(ExecOutcome::ok(v)),
                Ok(None) => {}
                Err(msg) => return Ok(ExecOutcome::err(1, msg)),
            }
        }

        // User-defined functions
        if let Some((params, body)) = self.functions.get(&cmd_name).cloned() {
            if self.depth >= MAX_CALL_DEPTH {
                return Err(String::from("function recursion limit exceeded"));
            }
            self.depth += 1;
            self.local_frames.push(BTreeMap::new());
            self.positional_stack.push(final_args.clone());
            for (idx, param) in params.iter().enumerate() {
                self.record_local(param);
                let val = final_args
                    .get(idx)
                    .cloned()
                    .map(Value::Text)
                    .unwrap_or(Value::Empty);
                self.vars.insert(param.clone(), val);
            }
            let mut fn_actions = Vec::new();
            let exec_res = self.exec_stmts(&body, host, &mut fn_actions);
            self.positional_stack.pop();
            if let Some(frame) = self.local_frames.pop() {
                for (name, old) in frame {
                    match old {
                        Some(v) => {
                            self.vars.insert(name, v);
                        }
                        None => {
                            self.vars.remove(&name);
                        }
                    }
                }
            }
            self.depth -= 1;

            let sig = exec_res?;
            let mut clear_screen = false;
            let mut exit_requested = false;
            let mut rendered = String::new();
            for act in fn_actions {
                match act {
                    EvalAction::ClearScreen => clear_screen = true,
                    EvalAction::Exit => exit_requested = true,
                    EvalAction::Output(v) => {
                        let s = v.into_text();
                        if !s.is_empty() {
                            if !rendered.is_empty() && !rendered.ends_with('\n') {
                                rendered.push('\n');
                            }
                            rendered.push_str(&s);
                        }
                    }
                }
            }
            let output = if let Some(BlockSignal::Return(ret_val)) = sig {
                if let Value::Int(code) = &ret_val {
                    self.last_status = *code as i32;
                }
                ret_val
            } else if rendered.is_empty() {
                Value::Empty
            } else {
                Value::Text(rendered)
            };
            return Ok(ExecOutcome {
                status: self.last_status,
                output,
                stderr: String::new(),
                clear_screen,
                exit_requested,
                child_pid: None,
            });
        }

        // Built-in commands (`true`, `false`, `echo`, `printf`, `test`/`[`, `export`, `env`)
        if stage.caps.is_none() {
            match cmd_name.as_str() {
                "true" | ":" => return Ok(ExecOutcome::ok(Value::Empty)),
                "false" => {
                    return Ok(ExecOutcome {
                        status: 1,
                        output: Value::Empty,
                        stderr: String::new(),
                        clear_screen: false,
                        exit_requested: false,
                        child_pid: None,
                    });
                }
                "echo" => {
                    if final_args.first().map(String::as_str) == Some("-n") {
                        return Ok(ExecOutcome::ok_text(final_args[1..].join(" ")));
                    }
                    return Ok(ExecOutcome::ok_text(final_args.join(" ")));
                }
                "printf" => return Ok(eval_printf(&final_args)),
                "test" | "[" => {
                    return Ok(eval_test_builtin(&cmd_name, &final_args, host));
                }
                "export" => {
                    for item in &final_args {
                        if let Some((k, v)) = item.split_once('=') {
                            self.vars
                                .insert(String::from(k), Value::Text(String::from(v)));
                        }
                    }
                    return Ok(ExecOutcome::ok(Value::Empty));
                }
                "env" => {
                    let mut out = String::new();
                    for (k, v) in &self.vars {
                        out.push_str(&format!("{k}={}\n", v.into_text()));
                    }
                    return Ok(ExecOutcome::ok_text(out.trim_end_matches('\n')));
                }
                _ => {}
            }
        }

        Ok(host.exec_command_ex(
            stage.caps.as_ref(),
            &cmd_name,
            &final_args,
            stdin,
            capture_output,
            separate_stderr,
        ))
    }
}

struct ArithParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    env: &'a ShellEnv,
}

impl<'a> ArithParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn parse_or(&mut self) -> Result<i64, String> {
        let mut lhs = self.parse_and()?;
        loop {
            self.skip_ws();
            if self.bytes[self.pos..].starts_with(b"||") {
                self.pos += 2;
                let rhs = self.parse_and()?;
                lhs = i64::from(lhs != 0 || rhs != 0);
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<i64, String> {
        let mut lhs = self.parse_eq()?;
        loop {
            self.skip_ws();
            if self.bytes[self.pos..].starts_with(b"&&") {
                self.pos += 2;
                let rhs = self.parse_eq()?;
                lhs = i64::from(lhs != 0 && rhs != 0);
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_eq(&mut self) -> Result<i64, String> {
        let mut lhs = self.parse_rel()?;
        loop {
            self.skip_ws();
            if self.bytes[self.pos..].starts_with(b"==") {
                self.pos += 2;
                let rhs = self.parse_rel()?;
                lhs = i64::from(lhs == rhs);
            } else if self.bytes[self.pos..].starts_with(b"!=") {
                self.pos += 2;
                let rhs = self.parse_rel()?;
                lhs = i64::from(lhs != rhs);
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_rel(&mut self) -> Result<i64, String> {
        let mut lhs = self.parse_add()?;
        loop {
            self.skip_ws();
            if self.bytes[self.pos..].starts_with(b"<=") {
                self.pos += 2;
                let rhs = self.parse_add()?;
                lhs = i64::from(lhs <= rhs);
            } else if self.bytes[self.pos..].starts_with(b">=") {
                self.pos += 2;
                let rhs = self.parse_add()?;
                lhs = i64::from(lhs >= rhs);
            } else if self.pos < self.bytes.len() && self.bytes[self.pos] == b'<' {
                self.pos += 1;
                let rhs = self.parse_add()?;
                lhs = i64::from(lhs < rhs);
            } else if self.pos < self.bytes.len() && self.bytes[self.pos] == b'>' {
                self.pos += 1;
                let rhs = self.parse_add()?;
                lhs = i64::from(lhs > rhs);
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> Result<i64, String> {
        let mut lhs = self.parse_mul()?;
        loop {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                break;
            }
            match self.bytes[self.pos] {
                b'+' => {
                    self.pos += 1;
                    let rhs = self.parse_mul()?;
                    lhs = lhs.wrapping_add(rhs);
                }
                b'-' => {
                    self.pos += 1;
                    let rhs = self.parse_mul()?;
                    lhs = lhs.wrapping_sub(rhs);
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<i64, String> {
        let mut lhs = self.parse_unary()?;
        loop {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                break;
            }
            match self.bytes[self.pos] {
                b'*' => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    lhs = lhs.wrapping_mul(rhs);
                }
                b'/' => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    if rhs == 0 {
                        return Err(String::from("division by zero in $((...))"));
                    }
                    lhs = lhs.wrapping_div(rhs);
                }
                b'%' => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    if rhs == 0 {
                        return Err(String::from("remainder by zero in $((...))"));
                    }
                    lhs = lhs.wrapping_rem(rhs);
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<i64, String> {
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return Err(String::from("unexpected end of arithmetic expression"));
        }
        match self.bytes[self.pos] {
            b'+' => {
                self.pos += 1;
                self.parse_unary()
            }
            b'-' => {
                self.pos += 1;
                Ok(self.parse_unary()?.wrapping_neg())
            }
            b'!' => {
                self.pos += 1;
                Ok(i64::from(self.parse_unary()? == 0))
            }
            b'(' => {
                self.pos += 1;
                let inner = self.parse_or()?;
                self.skip_ws();
                if self.pos >= self.bytes.len() || self.bytes[self.pos] != b')' {
                    return Err(String::from("expected ')' in $((...))"));
                }
                self.pos += 1;
                Ok(inner)
            }
            _ => self.parse_atom(),
        }
    }

    fn parse_atom(&mut self) -> Result<i64, String> {
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return Err(String::from("expected number or variable in $((...))"));
        }
        if self.bytes[self.pos] == b'$' {
            self.pos += 1;
        }
        let start = self.pos;
        if self.bytes[start].is_ascii_digit() {
            if self.bytes[start..].starts_with(b"0x") || self.bytes[start..].starts_with(b"0X") {
                self.pos += 2;
                let hstart = self.pos;
                while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_hexdigit() {
                    self.pos += 1;
                }
                let s = core::str::from_utf8(&self.bytes[hstart..self.pos])
                    .map_err(|_| String::from("invalid hex in $((...))"))?;
                return i64::from_str_radix(s, 16)
                    .map_err(|_| format!("invalid hex literal '0x{s}'"));
            }
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            let s = core::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| String::from("invalid number in $((...))"))?;
            return s
                .parse::<i64>()
                .map_err(|_| format!("invalid integer '{s}'"));
        }
        if self.bytes[start].is_ascii_alphabetic()
            || self.bytes[start] == b'_'
            || matches!(self.bytes[start], b'?' | b'#')
        {
            if matches!(self.bytes[start], b'?' | b'#') {
                self.pos += 1;
            } else {
                while self.pos < self.bytes.len()
                    && (self.bytes[self.pos].is_ascii_alphanumeric()
                        || self.bytes[self.pos] == b'_')
                {
                    self.pos += 1;
                }
            }
            let name = core::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| String::from("invalid identifier in $((...))"))?;
            let val = self.env.get_var(name);
            return match val {
                Value::Int(n) => Ok(n),
                Value::Bool(b) => Ok(i64::from(b)),
                Value::Empty => Ok(0),
                other => Ok(other.into_text().trim().parse::<i64>().unwrap_or(0)),
            };
        }
        Err(String::from("unexpected character in $((...))"))
    }
}

fn glob_match_bytes(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    let (mut star, mut resume) = (None::<usize>, 0usize);
    while n < name.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some(p);
                resume = n;
                p += 1;
            }
            Some(b'?') => {
                p += 1;
                n += 1;
            }
            Some(b) if *b == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                Some(pos) => {
                    p = pos + 1;
                    resume += 1;
                    n = resume;
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

fn eval_printf(args: &[String]) -> ExecOutcome {
    let Some(fmt) = args.first() else {
        return ExecOutcome::ok(Value::Empty);
    };
    let mut arg_idx = 1usize;
    let mut out = String::new();
    let bytes = fmt.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => out.push('\n'),
                b't' => out.push('\t'),
                b'r' => out.push('\r'),
                b'\\' => out.push('\\'),
                b'0' => out.push('\0'),
                other => {
                    out.push('\\');
                    out.push(other as char);
                }
            }
            i += 2;
            continue;
        }
        if bytes[i] == b'%' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'%' {
                out.push('%');
                i += 2;
                continue;
            }
            let spec_start = i + 1;
            let mut j = spec_start;
            while j < bytes.len() && matches!(bytes[j], b'-' | b'+' | b'0'..=b'9' | b'.') {
                j += 1;
            }
            if j < bytes.len() {
                let conv = bytes[j];
                let raw_arg = args.get(arg_idx).map(String::as_str).unwrap_or("");
                arg_idx += 1;
                match conv {
                    b's' => out.push_str(raw_arg),
                    b'd' | b'i' => {
                        let n = raw_arg.trim().parse::<i64>().unwrap_or(0);
                        out.push_str(&format!("{n}"));
                    }
                    b'x' => {
                        let n = raw_arg.trim().parse::<u64>().unwrap_or(0);
                        out.push_str(&format!("{n:x}"));
                    }
                    b'X' => {
                        let n = raw_arg.trim().parse::<u64>().unwrap_or(0);
                        out.push_str(&format!("{n:X}"));
                    }
                    b'o' => {
                        let n = raw_arg.trim().parse::<u64>().unwrap_or(0);
                        out.push_str(&format!("{n:o}"));
                    }
                    other => {
                        out.push('%');
                        out.push(other as char);
                    }
                }
                i = j + 1;
                continue;
            }
        }
        if let Some(ch) = fmt[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    ExecOutcome::ok_text(out)
}

fn eval_test_builtin(cmd_name: &str, args: &[String], host: &mut dyn ShellHost) -> ExecOutcome {
    let slice = if cmd_name == "[" {
        let Some(last) = args.last() else {
            return ExecOutcome::err(2, "[: missing ']'");
        };
        if last != "]" {
            return ExecOutcome::err(2, "[: missing ']'");
        }
        &args[..args.len() - 1]
    } else {
        args
    };

    let ok = eval_test_slice(slice, host);
    ExecOutcome {
        status: if ok { 0 } else { 1 },
        output: Value::Empty,
        stderr: String::new(),
        clear_screen: false,
        exit_requested: false,
        child_pid: None,
    }
}

fn eval_test_slice(tokens: &[String], host: &mut dyn ShellHost) -> bool {
    if tokens.is_empty() {
        return false;
    }
    if tokens[0] == "!" {
        return !eval_test_slice(&tokens[1..], host);
    }
    if tokens.len() == 1 {
        return !tokens[0].is_empty();
    }
    if tokens.len() == 2 {
        let op = tokens[0].as_str();
        let val = tokens[1].as_str();
        return match op {
            "-z" => val.is_empty(),
            "-n" => !val.is_empty(),
            "-e" => host.stat_path(val, true).is_some() || host.stat_path(val, false).is_some(),
            "-f" => matches!(host.stat_path(val, true), Some((HostPathKind::File, _))),
            "-d" => matches!(host.stat_path(val, true), Some((HostPathKind::Dir, _))),
            "-L" | "-h" => matches!(host.stat_path(val, false), Some((HostPathKind::Symlink, _))),
            "-s" => host.stat_path(val, true).is_some_and(|(_, sz)| sz > 0),
            _ => false,
        };
    }
    if tokens.len() == 3 {
        let lhs = tokens[0].as_str();
        let op = tokens[1].as_str();
        let rhs = tokens[2].as_str();
        return match op {
            "=" | "==" => lhs == rhs,
            "!=" => lhs != rhs,
            "-eq" => lhs.parse::<i64>().unwrap_or(0) == rhs.parse::<i64>().unwrap_or(0),
            "-ne" => lhs.parse::<i64>().unwrap_or(0) != rhs.parse::<i64>().unwrap_or(0),
            "-lt" => lhs.parse::<i64>().unwrap_or(0) < rhs.parse::<i64>().unwrap_or(0),
            "-le" => lhs.parse::<i64>().unwrap_or(0) <= rhs.parse::<i64>().unwrap_or(0),
            "-gt" => lhs.parse::<i64>().unwrap_or(0) > rhs.parse::<i64>().unwrap_or(0),
            "-ge" => lhs.parse::<i64>().unwrap_or(0) >= rhs.parse::<i64>().unwrap_or(0),
            _ => false,
        };
    }
    for (idx, tok) in tokens.iter().enumerate() {
        if tok == "-o" {
            return eval_test_slice(&tokens[..idx], host)
                || eval_test_slice(&tokens[idx + 1..], host);
        }
    }
    for (idx, tok) in tokens.iter().enumerate() {
        if tok == "-a" {
            return eval_test_slice(&tokens[..idx], host)
                && eval_test_slice(&tokens[idx + 1..], host);
        }
    }
    false
}
