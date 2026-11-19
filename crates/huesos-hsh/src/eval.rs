//! AST evaluator for `hsh`.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::ast::{
    ArgExpr, CapsSpec, Chain, ChainOp, CommandCall, Cond, Expr, Pipeline, Redirect, Stmt, WordPart,
};
use crate::parser::parse_script;
use crate::value::{compare_cells, try_apply_pipe_builtin, Value};

const MAX_CALL_DEPTH: usize = 32;

/// Single command execution result returned by [`ShellHost::exec_command`].
#[derive(Clone, Debug)]
pub struct ExecOutcome {
    pub status: i32,
    pub output: Value,
    pub clear_screen: bool,
    pub exit_requested: bool,
    pub child_pid: Option<u64>,
}

impl ExecOutcome {
    pub fn ok(output: Value) -> Self {
        Self {
            status: 0,
            output,
            clear_screen: false,
            exit_requested: false,
            child_pid: None,
        }
    }

    pub fn ok_text(s: impl Into<String>) -> Self {
        Self::ok(Value::Text(s.into()))
    }

    pub fn err(status: i32, msg: impl Into<String>) -> Self {
        Self {
            status,
            output: Value::Text(msg.into()),
            clear_screen: false,
            exit_requested: false,
            child_pid: None,
        }
    }
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

    fn write_file(&mut self, path: &str, data: &[u8], append: bool) -> Result<(), String>;
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
    pub last_status: i32,
    pub last_pid: u64,
    depth: usize,
}

impl Default for ShellEnv {
    fn default() -> Self {
        Self::new()
    }
}

struct BlockSignal {
    returned: Option<Value>,
}

impl ShellEnv {
    pub fn new() -> Self {
        Self {
            vars: BTreeMap::new(),
            aliases: BTreeMap::new(),
            functions: BTreeMap::new(),
            last_status: 0,
            last_pid: 0,
            depth: 0,
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

    pub fn get_var(&self, name: &str) -> Value {
        match name {
            "status" => Value::Int(i64::from(self.last_status)),
            "pid" => Value::Int(self.last_pid as i64),
            _ => self.vars.get(name).cloned().unwrap_or(Value::Empty),
        }
    }

    /// Parse and execute an `hsh` script string against `host`.
    pub fn eval_script(
        &mut self,
        input: &str,
        host: &mut dyn ShellHost,
    ) -> Result<EvalResult, String> {
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
            match stmt {
                Stmt::Let { name, value } => {
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
                            match saved {
                                Some(v) => {
                                    self.vars.insert(var.clone(), v);
                                }
                                None => {
                                    self.vars.remove(var);
                                }
                            }
                            return Ok(Some(sig));
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
                Stmt::Return(expr) => {
                    let val = match expr {
                        Some(e) => self.eval_expr(e, host)?,
                        None => Value::Empty,
                    };
                    return Ok(Some(BlockSignal {
                        returned: Some(val),
                    }));
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
        Ok(Value::Text(self.eval_arg_text(arg, host)?))
    }

    fn eval_arg_text(&mut self, arg: &ArgExpr, host: &mut dyn ShellHost) -> Result<String, String> {
        let mut out = String::new();
        for part in &arg.parts {
            match part {
                WordPart::Literal(s) => out.push_str(s),
                WordPart::Var(name) => out.push_str(&self.get_var(name).into_text()),
                WordPart::CmdSubst(stmts) => {
                    let mut sub_actions = Vec::new();
                    let _ = self.exec_stmts(stmts, host, &mut sub_actions)?;
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

    fn exec_pipeline(
        &mut self,
        pipe: &Pipeline,
        host: &mut dyn ShellHost,
        actions: &mut Vec<EvalAction>,
    ) -> Result<(), String> {
        let mut current_val: Option<Value> = None;
        let mut final_redirect: Option<&Redirect> = None;

        for (idx, stage) in pipe.stages.iter().enumerate() {
            let is_last = idx + 1 == pipe.stages.len();
            if is_last {
                final_redirect = stage.redirect.as_ref();
            }

            let outcome = self.exec_stage(stage, current_val.as_ref(), host)?;
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
            current_val = Some(outcome.output);
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
                    Ok(()) => self.last_status = 0,
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
        host: &mut dyn ShellHost,
    ) -> Result<ExecOutcome, String> {
        let raw_name = self.eval_arg_text(&stage.name, host)?;
        let mut args = Vec::with_capacity(stage.args.len());
        for a in &stage.args {
            args.push(self.eval_arg_text(a, host)?);
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
            let mut saved_vars = Vec::with_capacity(params.len());
            for (idx, param) in params.iter().enumerate() {
                saved_vars.push((param.clone(), self.vars.get(param).cloned()));
                let val = final_args
                    .get(idx)
                    .cloned()
                    .map(Value::Text)
                    .unwrap_or(Value::Empty);
                self.vars.insert(param.clone(), val);
            }
            let mut fn_actions = Vec::new();
            let exec_res = self.exec_stmts(&body, host, &mut fn_actions);
            for (param, old) in saved_vars {
                match old {
                    Some(v) => {
                        self.vars.insert(param, v);
                    }
                    None => {
                        self.vars.remove(&param);
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
            let output = if let Some(BlockSignal {
                returned: Some(ret_val),
            }) = sig
            {
                ret_val
            } else if rendered.is_empty() {
                Value::Empty
            } else {
                Value::Text(rendered)
            };
            return Ok(ExecOutcome {
                status: self.last_status,
                output,
                clear_screen,
                exit_requested,
                child_pid: None,
            });
        }

        // Built-in `echo` (preserves exact non-split arguments)
        if cmd_name == "echo" && stage.caps.is_none() {
            return Ok(ExecOutcome::ok_text(final_args.join(" ")));
        }

        Ok(host.exec_command(stage.caps.as_ref(), &cmd_name, &final_args, stdin))
    }
}
