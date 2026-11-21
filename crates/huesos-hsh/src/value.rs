//! Structured values and Nushell-inspired table pipeline operators.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt::Write;

use crate::ast::CmpOp;

/// Tabular value with named columns and string cells.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// Dynamically-typed shell value flowing through variables and pipes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Empty,
    Text(String),
    Int(i64),
    Bool(bool),
    List(Vec<Value>),
    Table(Table),
}

impl Value {
    /// Convert any value into a plain display string (tables render cleanly).
    pub fn into_text(&self) -> String {
        match self {
            Value::Empty => String::new(),
            Value::Text(s) => s.clone(),
            Value::Int(n) => format!("{n}"),
            Value::Bool(b) => String::from(if *b { "true" } else { "false" }),
            Value::List(items) => {
                let mut out = String::new();
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push('\n');
                    }
                    out.push_str(&item.into_text());
                }
                out
            }
            Value::Table(tbl) => tbl.render(),
        }
    }

    /// Convert to TSV/wire text when piping into an external ELF `stdin`.
    pub fn to_pipe_bytes(&self) -> Vec<u8> {
        let mut bytes = match self {
            Value::Empty => return Vec::new(),
            Value::Table(tbl) => tbl.to_tsv().into_bytes(),
            other => other.into_text().into_bytes(),
        };
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        bytes
    }

    /// Evaluate truthiness (`false`, `0`, empty text/list/table -> false).
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Empty => false,
            Value::Bool(b) => *b,
            Value::Int(n) => *n != 0,
            Value::Text(s) => !s.is_empty() && s != "false" && s != "0",
            Value::List(items) => !items.is_empty(),
            Value::Table(tbl) => !tbl.rows.is_empty(),
        }
    }
}

impl Table {
    /// Construct an empty table with the given column headers.
    pub fn new(columns: Vec<String>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
        }
    }

    /// Parse tab-separated text (`col1\tcol2\n...`) into a [`Table`].
    pub fn from_tsv(input: &str) -> Option<Self> {
        let mut lines = input.lines().filter(|l| !l.trim().is_empty());
        let header = lines.next()?;
        if !header.contains('\t') {
            return None;
        }
        let columns: Vec<String> = header.split('\t').map(|s| String::from(s.trim())).collect();
        let ncols = columns.len();
        if ncols == 0 {
            return None;
        }
        let mut rows = Vec::new();
        for line in lines {
            let mut row: Vec<String> = line.split('\t').map(|s| String::from(s.trim())).collect();
            row.resize(ncols, String::new());
            rows.push(row);
        }
        Some(Self { columns, rows })
    }

    /// Serialize back to TSV text.
    pub fn to_tsv(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.columns.join("\t"));
        out.push('\n');
        for row in &self.rows {
            out.push_str(&row.join("\t"));
            out.push('\n');
        }
        out
    }

    /// Render as a neat column-aligned ASCII table.
    pub fn render(&self) -> String {
        if self.columns.is_empty() {
            return String::new();
        }
        let mut widths: Vec<usize> = self.columns.iter().map(|c| c.len()).collect();
        for row in &self.rows {
            for (idx, cell) in row.iter().enumerate() {
                if idx < widths.len() {
                    widths[idx] = widths[idx].max(cell.len());
                }
            }
        }
        let mut out = String::new();
        for (i, col) in self.columns.iter().enumerate() {
            if i > 0 {
                out.push_str("  ");
            }
            let _ = write!(out, "{:<width$}", col, width = widths[i]);
        }
        out.push('\n');
        for (i, w) in widths.iter().enumerate() {
            if i > 0 {
                out.push_str("  ");
            }
            for _ in 0..*w {
                out.push('-');
            }
        }
        out.push('\n');
        for row in &self.rows {
            for (i, w) in widths.iter().enumerate() {
                if i > 0 {
                    out.push_str("  ");
                }
                let cell = row.get(i).map(String::as_str).unwrap_or("");
                let _ = write!(out, "{:<width$}", cell, width = *w);
            }
            out.push('\n');
        }
        out
    }

    fn col_index(&self, name: &str) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.eq_ignore_ascii_case(name))
    }

    /// Filter rows with `where <col> <op> <val>`.
    pub fn filter_where(&self, col: &str, op: CmpOp, rhs: &str) -> Result<Self, String> {
        let idx = self
            .col_index(col)
            .ok_or_else(|| format!("unknown column '{col}'"))?;
        let mut rows = Vec::new();
        for row in &self.rows {
            let lhs = row.get(idx).map(String::as_str).unwrap_or("");
            if compare_cells(lhs, op, rhs) {
                rows.push(row.clone());
            }
        }
        Ok(Self {
            columns: self.columns.clone(),
            rows,
        })
    }

    /// Project columns `select <col1> [<col2> ...]`.
    pub fn select_cols(&self, cols: &[String]) -> Result<Self, String> {
        let mut indices = Vec::with_capacity(cols.len());
        let mut new_cols = Vec::with_capacity(cols.len());
        for col in cols {
            let idx = self
                .col_index(col)
                .ok_or_else(|| format!("unknown column '{col}'"))?;
            indices.push(idx);
            new_cols.push(self.columns[idx].clone());
        }
        let mut rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let projected = indices
                .iter()
                .map(|&idx| row.get(idx).cloned().unwrap_or_default())
                .collect();
            rows.push(projected);
        }
        Ok(Self {
            columns: new_cols,
            rows,
        })
    }

    /// Sort rows by `col` (default first column), ascending or descending.
    pub fn sort_by(&self, col: Option<&str>, desc: bool) -> Result<Self, String> {
        let idx = match col {
            Some(c) => self
                .col_index(c)
                .ok_or_else(|| format!("unknown column '{c}'"))?,
            None => 0,
        };
        let mut rows = self.rows.clone();
        rows.sort_by(|a, b| {
            let sa = a.get(idx).map(String::as_str).unwrap_or("");
            let sb = b.get(idx).map(String::as_str).unwrap_or("");
            let ord = cmp_scalar(sa, sb);
            if desc {
                ord.reverse()
            } else {
                ord
            }
        });
        Ok(Self {
            columns: self.columns.clone(),
            rows,
        })
    }

    /// Keep first `n` rows.
    pub fn head(&self, n: usize) -> Self {
        Self {
            columns: self.columns.clone(),
            rows: self.rows.iter().take(n).cloned().collect(),
        }
    }

    /// Keep last `n` rows.
    pub fn tail(&self, n: usize) -> Self {
        let skip = self.rows.len().saturating_sub(n);
        Self {
            columns: self.columns.clone(),
            rows: self.rows.iter().skip(skip).cloned().collect(),
        }
    }

    /// Filter rows containing `pattern` (case-insensitive) in any column.
    pub fn grep(&self, pattern: &str) -> Self {
        let pat_lower = pattern.to_ascii_lowercase();
        let rows = self
            .rows
            .iter()
            .filter(|row| {
                row.iter()
                    .any(|cell| cell.to_ascii_lowercase().contains(&pat_lower))
            })
            .cloned()
            .collect();
        Self {
            columns: self.columns.clone(),
            rows,
        }
    }
}

/// Compare two cell/scalar strings numerically if both parse as integers/hex, else lexicographically.
pub fn cmp_scalar(lhs: &str, rhs: &str) -> Ordering {
    if let (Some(a), Some(b)) = (parse_num(lhs), parse_num(rhs)) {
        return a.cmp(&b);
    }
    lhs.to_ascii_lowercase().cmp(&rhs.to_ascii_lowercase())
}

fn parse_num(s: &str) -> Option<i128> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i128::from_str_radix(hex, 16).ok();
    }
    t.parse::<i128>().ok()
}

/// Evaluate a binary comparison `lhs <op> rhs`.
pub fn compare_cells(lhs: &str, op: CmpOp, rhs: &str) -> bool {
    match op {
        CmpOp::Eq => {
            if let (Some(a), Some(b)) = (parse_num(lhs), parse_num(rhs)) {
                a == b
            } else {
                lhs.eq_ignore_ascii_case(rhs)
            }
        }
        CmpOp::Ne => !compare_cells(lhs, CmpOp::Eq, rhs),
        CmpOp::Lt => cmp_scalar(lhs, rhs) == Ordering::Less,
        CmpOp::Gt => cmp_scalar(lhs, rhs) == Ordering::Greater,
        CmpOp::Le => cmp_scalar(lhs, rhs) != Ordering::Greater,
        CmpOp::Ge => cmp_scalar(lhs, rhs) != Ordering::Less,
        CmpOp::Contains => lhs.to_ascii_lowercase().contains(&rhs.to_ascii_lowercase()),
    }
}

/// Run a built-in table/text transform (`where`, `select`, `sort`, `head`, `tail`, `count`, `grep`).
/// Returns `Ok(Some(value))` if `cmd` is a stream/table filter, or `Ok(None)` if not.
pub fn try_apply_pipe_builtin(
    cmd: &str,
    args: &[String],
    input: &Value,
) -> Result<Option<Value>, String> {
    match cmd {
        "where" => {
            if args.len() < 3 {
                return Err(String::from("usage: where <col> <op> <value>"));
            }
            let op = match args[1].as_str() {
                "==" => CmpOp::Eq,
                "!=" => CmpOp::Ne,
                "<" => CmpOp::Lt,
                ">" => CmpOp::Gt,
                "<=" => CmpOp::Le,
                ">=" => CmpOp::Ge,
                "contains" => CmpOp::Contains,
                other => return Err(alloc::format!("invalid where operator '{other}'")),
            };
            let tbl = match input {
                Value::Table(t) => t.clone(),
                Value::Text(s) => {
                    Table::from_tsv(s).ok_or_else(|| String::from("where requires table input"))?
                }
                _ => return Err(String::from("where requires table input")),
            };
            Ok(Some(Value::Table(
                tbl.filter_where(&args[0], op, &args[2])?,
            )))
        }
        "select" => {
            if args.is_empty() {
                return Err(String::from("usage: select <col1> [<col2> ...]"));
            }
            let tbl = match input {
                Value::Table(t) => t.clone(),
                Value::Text(s) => {
                    Table::from_tsv(s).ok_or_else(|| String::from("select requires table input"))?
                }
                _ => return Err(String::from("select requires table input")),
            };
            Ok(Some(Value::Table(tbl.select_cols(args)?)))
        }
        "sort" => {
            let mut desc = false;
            let mut col: Option<&str> = None;
            for arg in args {
                if arg == "--desc" || arg == "-r" {
                    desc = true;
                } else {
                    col = Some(arg.as_str());
                }
            }
            match input {
                Value::Table(t) => Ok(Some(Value::Table(t.sort_by(col, desc)?))),
                Value::Text(s) => {
                    if let Some(t) = Table::from_tsv(s) {
                        Ok(Some(Value::Table(t.sort_by(col, desc)?)))
                    } else {
                        let mut lines: Vec<&str> = s.lines().collect();
                        lines.sort_by(|a, b| if desc { b.cmp(a) } else { a.cmp(b) });
                        Ok(Some(Value::Text(lines.join("\n"))))
                    }
                }
                Value::List(items) => {
                    let mut strs: Vec<String> = items.iter().map(Value::into_text).collect();
                    strs.sort_by(|a, b| {
                        let o = cmp_scalar(a, b);
                        if desc {
                            o.reverse()
                        } else {
                            o
                        }
                    });
                    Ok(Some(Value::List(
                        strs.into_iter().map(Value::Text).collect(),
                    )))
                }
                _ => Ok(Some(input.clone())),
            }
        }
        "head" => {
            let n = args
                .first()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(10);
            match input {
                Value::Table(t) => Ok(Some(Value::Table(t.head(n)))),
                Value::List(items) => {
                    Ok(Some(Value::List(items.iter().take(n).cloned().collect())))
                }
                other => {
                    let txt = other.into_text();
                    let out: Vec<&str> = txt.lines().take(n).collect();
                    Ok(Some(Value::Text(out.join("\n"))))
                }
            }
        }
        "tail" => {
            let n = args
                .first()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(10);
            match input {
                Value::Table(t) => Ok(Some(Value::Table(t.tail(n)))),
                Value::List(items) => {
                    let skip = items.len().saturating_sub(n);
                    Ok(Some(Value::List(
                        items.iter().skip(skip).cloned().collect(),
                    )))
                }
                other => {
                    let txt = other.into_text();
                    let lines: Vec<&str> = txt.lines().collect();
                    let skip = lines.len().saturating_sub(n);
                    Ok(Some(Value::Text(lines[skip..].join("\n"))))
                }
            }
        }
        "count" => {
            let n = match input {
                Value::Empty => 0,
                Value::Table(t) => t.rows.len() as i64,
                Value::List(items) => items.len() as i64,
                Value::Text(s) => s.lines().filter(|l| !l.is_empty()).count() as i64,
                _ => 1,
            };
            Ok(Some(Value::Text(n.to_string())))
        }
        "grep" => {
            let pat = args
                .first()
                .ok_or_else(|| String::from("usage: grep <pattern>"))?;
            match input {
                Value::Table(t) => Ok(Some(Value::Table(t.grep(pat)))),
                other => {
                    let pat_l = pat.to_ascii_lowercase();
                    let txt = other.into_text();
                    let matched: Vec<&str> = txt
                        .lines()
                        .filter(|l| l.to_ascii_lowercase().contains(&pat_l))
                        .collect();
                    Ok(Some(Value::Text(matched.join("\n"))))
                }
            }
        }
        _ => Ok(None),
    }
}
