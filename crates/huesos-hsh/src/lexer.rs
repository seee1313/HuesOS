//! Lexer and syntax-highlighting tokenizer for `hsh`.

use alloc::string::String;
use alloc::vec::Vec;

/// Byte range in the source input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Token kind produced by [`tokenize`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Word(String),
    SingleQuoted(String),
    DoubleQuoted(Vec<QuotePart>),
    Var(String),
    CmdSubst(String),
    ArithSubst(String),
    CapsAnnot(String),
    Keyword(Keyword),
    Bang,
    Semi,
    AndAnd,
    OrOr,
    Pipe,
    Gt,
    GtGt,
    ErrGt,
    ErrGtGt,
    ErrToOut,
    Eq,
    EqEq,
    NotEq,
    Lt,
    Le,
    Ge,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Newline,
}

/// Segment inside a double-quoted string `"..."`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotePart {
    Literal(String),
    Var(String),
    CmdSubst(String),
    ArithSubst(String),
}

/// Reserved `hsh` keywords.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Keyword {
    Let,
    If,
    Elif,
    Else,
    While,
    For,
    In,
    Fn,
    Alias,
    Break,
    Continue,
    Return,
    Contains,
}

/// Token with source byte span.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// Syntax-highlighting category for live terminal rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HighlightKind {
    Keyword,
    Command,
    Builtin,
    Caps,
    StringLit,
    Variable,
    Operator,
    Comment,
    Number,
    Default,
}

/// Highlight span for terminal rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HighlightSpan {
    pub span: Span,
    pub kind: HighlightKind,
}

/// Lexer error with source offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexError {
    pub message: String,
    pub offset: usize,
}

fn is_word_break(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t'
            | b'\r'
            | b'\n'
            | b';'
            | b'|'
            | b'&'
            | b'>'
            | b'<'
            | b'='
            | b'{'
            | b'}'
            | b'['
            | b']'
            | b'('
            | b')'
            | b','
            | b'"'
            | b'\''
            | b'#'
    )
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_special_var_char(b: u8) -> bool {
    matches!(b, b'?' | b'#' | b'@')
}

fn keyword_from_str(s: &str) -> Option<Keyword> {
    match s {
        "let" => Some(Keyword::Let),
        "if" => Some(Keyword::If),
        "elif" => Some(Keyword::Elif),
        "else" => Some(Keyword::Else),
        "while" => Some(Keyword::While),
        "for" => Some(Keyword::For),
        "in" => Some(Keyword::In),
        "fn" => Some(Keyword::Fn),
        "alias" => Some(Keyword::Alias),
        "break" => Some(Keyword::Break),
        "continue" => Some(Keyword::Continue),
        "return" => Some(Keyword::Return),
        "contains" => Some(Keyword::Contains),
        _ => None,
    }
}

fn parse_arith_subst(
    bytes: &[u8],
    start_after_dollar_lparen2: usize,
) -> Result<(String, usize), LexError> {
    let mut i = start_after_dollar_lparen2;
    let mut depth = 1usize;
    while i < bytes.len() {
        if bytes[i] == b'(' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i] == b')' && i + 1 < bytes.len() && bytes[i + 1] == b')' {
            depth -= 1;
            if depth == 0 {
                let inner =
                    core::str::from_utf8(&bytes[start_after_dollar_lparen2..i]).map_err(|_| {
                        LexError {
                            message: String::from("invalid UTF-8 in $((...))"),
                            offset: start_after_dollar_lparen2,
                        }
                    })?;
                return Ok((String::from(inner), i + 2));
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    Err(LexError {
        message: String::from("unterminated $((...))"),
        offset: start_after_dollar_lparen2.saturating_sub(3),
    })
}

fn parse_cmd_subst(
    bytes: &[u8],
    start_after_dollar_paren: usize,
) -> Result<(String, usize), LexError> {
    let mut i = start_after_dollar_paren;
    let mut depth = 1usize;
    let mut in_sq = false;
    let mut in_dq = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_sq {
            if b == b'\'' {
                in_sq = false;
            }
            i += 1;
            continue;
        }
        if in_dq {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_dq = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_sq = true,
            b'"' => in_dq = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    let inner = core::str::from_utf8(&bytes[start_after_dollar_paren..i]).map_err(
                        |_| LexError {
                            message: String::from("invalid UTF-8 in $(...)"),
                            offset: start_after_dollar_paren,
                        },
                    )?;
                    return Ok((String::from(inner), i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err(LexError {
        message: String::from("unterminated $(...)"),
        offset: start_after_dollar_paren.saturating_sub(2),
    })
}

/// Tokenize an `hsh` script into [`Token`]s.
pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' || b == b'\t' || b == b'\r' {
            i += 1;
            continue;
        }
        if b == b'\n' {
            tokens.push(Token {
                kind: TokenKind::Newline,
                span: Span {
                    start: i,
                    end: i + 1,
                },
            });
            i += 1;
            continue;
        }
        if b == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // `@caps(...)`
        if bytes[i..].starts_with(b"@caps(") {
            let start = i;
            let body_start = i + b"@caps(".len();
            let mut j = body_start;
            while j < bytes.len() && bytes[j] != b')' {
                j += 1;
            }
            if j >= bytes.len() {
                return Err(LexError {
                    message: String::from("unterminated @caps(...)"),
                    offset: start,
                });
            }
            let body = core::str::from_utf8(&bytes[body_start..j]).map_err(|_| LexError {
                message: String::from("invalid UTF-8 in @caps(...)"),
                offset: start,
            })?;
            tokens.push(Token {
                kind: TokenKind::CapsAnnot(String::from(body)),
                span: Span { start, end: j + 1 },
            });
            i = j + 1;
            continue;
        }

        // Multi-char stderr redirection operators (`2>&1`, `2>>`, `2>`) when at token start
        if bytes[i..].starts_with(b"2>&1") && (i + 4 == bytes.len() || is_word_break(bytes[i + 4]))
        {
            tokens.push(Token {
                kind: TokenKind::ErrToOut,
                span: Span {
                    start: i,
                    end: i + 4,
                },
            });
            i += 4;
            continue;
        }
        if bytes[i..].starts_with(b"2>>") {
            tokens.push(Token {
                kind: TokenKind::ErrGtGt,
                span: Span {
                    start: i,
                    end: i + 3,
                },
            });
            i += 3;
            continue;
        }
        if bytes[i..].starts_with(b"2>") {
            tokens.push(Token {
                kind: TokenKind::ErrGt,
                span: Span {
                    start: i,
                    end: i + 2,
                },
            });
            i += 2;
            continue;
        }

        // Two-char operators
        if i + 1 < bytes.len() {
            let two = &bytes[i..i + 2];
            let op = match two {
                b"&&" => Some(TokenKind::AndAnd),
                b"||" => Some(TokenKind::OrOr),
                b">>" => Some(TokenKind::GtGt),
                b"==" => Some(TokenKind::EqEq),
                b"!=" => Some(TokenKind::NotEq),
                b"<=" => Some(TokenKind::Le),
                b">=" => Some(TokenKind::Ge),
                _ => None,
            };
            if let Some(kind) = op {
                tokens.push(Token {
                    kind,
                    span: Span {
                        start: i,
                        end: i + 2,
                    },
                });
                i += 2;
                continue;
            }
        }

        // Standalone `!` negation operator (followed by whitespace or paren)
        if b == b'!' && (i + 1 == bytes.len() || matches!(bytes[i + 1], b' ' | b'\t' | b'(')) {
            tokens.push(Token {
                kind: TokenKind::Bang,
                span: Span {
                    start: i,
                    end: i + 1,
                },
            });
            i += 1;
            continue;
        }

        // Single-char punctuation
        let single = match b {
            b';' => Some(TokenKind::Semi),
            b'|' => Some(TokenKind::Pipe),
            b'>' => Some(TokenKind::Gt),
            b'<' => Some(TokenKind::Lt),
            b'=' => Some(TokenKind::Eq),
            b'{' => Some(TokenKind::LBrace),
            b'}' => Some(TokenKind::RBrace),
            b'[' => Some(TokenKind::LBracket),
            b']' => Some(TokenKind::RBracket),
            b'(' => Some(TokenKind::LParen),
            b')' => Some(TokenKind::RParen),
            b',' => Some(TokenKind::Comma),
            _ => None,
        };
        if let Some(kind) = single {
            tokens.push(Token {
                kind,
                span: Span {
                    start: i,
                    end: i + 1,
                },
            });
            i += 1;
            continue;
        }

        // Single-quoted literal
        if b == b'\'' {
            let start = i;
            i += 1;
            let body_start = i;
            while i < bytes.len() && bytes[i] != b'\'' {
                i += 1;
            }
            if i >= bytes.len() {
                return Err(LexError {
                    message: String::from("unterminated single-quoted string"),
                    offset: start,
                });
            }
            let inner = core::str::from_utf8(&bytes[body_start..i]).map_err(|_| LexError {
                message: String::from("invalid UTF-8 in string"),
                offset: start,
            })?;
            tokens.push(Token {
                kind: TokenKind::SingleQuoted(String::from(inner)),
                span: Span { start, end: i + 1 },
            });
            i += 1;
            continue;
        }

        // Double-quoted string with `$var` and `$(cmd)` interpolation
        if b == b'"' {
            let start = i;
            i += 1;
            let mut parts: Vec<QuotePart> = Vec::new();
            let mut lit = String::new();
            let mut closed = false;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => {
                        closed = true;
                        i += 1;
                        break;
                    }
                    b'\\' if i + 1 < bytes.len() => {
                        let esc = match bytes[i + 1] {
                            b'n' => '\n',
                            b't' => '\t',
                            b'r' => '\r',
                            b'"' => '"',
                            b'\\' => '\\',
                            b'$' => '$',
                            other => {
                                lit.push('\\');
                                other as char
                            }
                        };
                        lit.push(esc);
                        i += 2;
                    }
                    b'$' if i + 2 < bytes.len() && bytes[i + 1] == b'(' && bytes[i + 2] == b'(' => {
                        if !lit.is_empty() {
                            parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                        }
                        let (expr, next_i) = parse_arith_subst(bytes, i + 3)?;
                        parts.push(QuotePart::ArithSubst(expr));
                        i = next_i;
                    }
                    b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'(' => {
                        if !lit.is_empty() {
                            parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                        }
                        let (cmd, next_i) = parse_cmd_subst(bytes, i + 2)?;
                        parts.push(QuotePart::CmdSubst(cmd));
                        i = next_i;
                    }
                    b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'{' => {
                        if !lit.is_empty() {
                            parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                        }
                        let vstart = i + 2;
                        let mut vend = vstart;
                        while vend < bytes.len() && bytes[vend] != b'}' {
                            vend += 1;
                        }
                        if vend >= bytes.len() {
                            return Err(LexError {
                                message: String::from("unterminated ${...}"),
                                offset: i,
                            });
                        }
                        let name = &input[vstart..vend];
                        parts.push(QuotePart::Var(String::from(name)));
                        i = vend + 1;
                    }
                    b'$' if i + 1 < bytes.len() && is_special_var_char(bytes[i + 1]) => {
                        if !lit.is_empty() {
                            parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                        }
                        let name = &input[i + 1..i + 2];
                        parts.push(QuotePart::Var(String::from(name)));
                        i += 2;
                    }
                    b'$' if i + 1 < bytes.len() && is_ident_char(bytes[i + 1]) => {
                        if !lit.is_empty() {
                            parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                        }
                        let vstart = i + 1;
                        let mut vend = vstart;
                        while vend < bytes.len() && is_ident_char(bytes[vend]) {
                            vend += 1;
                        }
                        let name = &input[vstart..vend];
                        parts.push(QuotePart::Var(String::from(name)));
                        i = vend;
                    }
                    _ => {
                        let ch = input[i..].chars().next().ok_or(LexError {
                            message: String::from("invalid UTF-8"),
                            offset: i,
                        })?;
                        lit.push(ch);
                        i += ch.len_utf8();
                    }
                }
            }
            if !closed {
                return Err(LexError {
                    message: String::from("unterminated double-quoted string"),
                    offset: start,
                });
            }
            if !lit.is_empty() || parts.is_empty() {
                parts.push(QuotePart::Literal(lit));
            }
            tokens.push(Token {
                kind: TokenKind::DoubleQuoted(parts),
                span: Span { start, end: i },
            });
            continue;
        }

        // Standalone `$((arith))`, `$(cmd)`, `${var}`, `$?`, `$#`, `$@`, or `$var`
        // (only when followed by a word break; otherwise composite word handling
        // below keeps `$0:$1:$(cmd)` together as a single argument).
        if b == b'$' {
            let start = i;
            if i + 2 < bytes.len() && bytes[i + 1] == b'(' && bytes[i + 2] == b'(' {
                let (expr, next_i) = parse_arith_subst(bytes, i + 3)?;
                if next_i == bytes.len() || is_word_break(bytes[next_i]) {
                    tokens.push(Token {
                        kind: TokenKind::ArithSubst(expr),
                        span: Span { start, end: next_i },
                    });
                    i = next_i;
                    continue;
                }
            } else if i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                let (cmd, next_i) = parse_cmd_subst(bytes, i + 2)?;
                if next_i == bytes.len() || is_word_break(bytes[next_i]) {
                    tokens.push(Token {
                        kind: TokenKind::CmdSubst(cmd),
                        span: Span { start, end: next_i },
                    });
                    i = next_i;
                    continue;
                }
            } else if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                let vstart = i + 2;
                let mut vend = vstart;
                while vend < bytes.len() && bytes[vend] != b'}' {
                    vend += 1;
                }
                if vend >= bytes.len() {
                    return Err(LexError {
                        message: String::from("unterminated ${...}"),
                        offset: start,
                    });
                }
                if vend + 1 == bytes.len() || is_word_break(bytes[vend + 1]) {
                    let name = &input[vstart..vend];
                    tokens.push(Token {
                        kind: TokenKind::Var(String::from(name)),
                        span: Span {
                            start,
                            end: vend + 1,
                        },
                    });
                    i = vend + 1;
                    continue;
                }
            } else if i + 1 < bytes.len() && is_special_var_char(bytes[i + 1]) {
                if i + 2 == bytes.len() || is_word_break(bytes[i + 2]) {
                    let name = &input[i + 1..i + 2];
                    tokens.push(Token {
                        kind: TokenKind::Var(String::from(name)),
                        span: Span { start, end: i + 2 },
                    });
                    i += 2;
                    continue;
                }
            } else if i + 1 < bytes.len() && is_ident_char(bytes[i + 1]) {
                let vstart = i + 1;
                let mut vend = vstart;
                while vend < bytes.len() && is_ident_char(bytes[vend]) {
                    vend += 1;
                }
                if vend == bytes.len() || is_word_break(bytes[vend]) {
                    let name = &input[vstart..vend];
                    tokens.push(Token {
                        kind: TokenKind::Var(String::from(name)),
                        span: Span { start, end: vend },
                    });
                    i = vend;
                    continue;
                }
            }
        }

        // Bare word / keyword (supports composite words like `$0:$1:$(cmd)` or `foo"bar"`)
        let start = i;
        let mut parts: Vec<QuotePart> = Vec::new();
        let mut lit = String::new();
        let mut saw_dynamic_or_quote = false;
        while i < bytes.len() && !is_word_break(bytes[i]) {
            if bytes[i] == b'\'' {
                saw_dynamic_or_quote = true;
                let sq_start = i;
                i += 1;
                let body_start = i;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
                if i >= bytes.len() {
                    return Err(LexError {
                        message: String::from("unterminated single-quoted string"),
                        offset: sq_start,
                    });
                }
                let inner = core::str::from_utf8(&bytes[body_start..i]).map_err(|_| LexError {
                    message: String::from("invalid UTF-8 in string"),
                    offset: sq_start,
                })?;
                lit.push_str(inner);
                i += 1;
                continue;
            }
            if bytes[i] == b'$' {
                if i + 2 < bytes.len() && bytes[i + 1] == b'(' && bytes[i + 2] == b'(' {
                    saw_dynamic_or_quote = true;
                    if !lit.is_empty() {
                        parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                    }
                    let (expr, next_i) = parse_arith_subst(bytes, i + 3)?;
                    parts.push(QuotePart::ArithSubst(expr));
                    i = next_i;
                    continue;
                }
                if i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                    saw_dynamic_or_quote = true;
                    if !lit.is_empty() {
                        parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                    }
                    let (cmd, next_i) = parse_cmd_subst(bytes, i + 2)?;
                    parts.push(QuotePart::CmdSubst(cmd));
                    i = next_i;
                    continue;
                }
                if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    saw_dynamic_or_quote = true;
                    if !lit.is_empty() {
                        parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                    }
                    let vstart = i + 2;
                    let mut vend = vstart;
                    while vend < bytes.len() && bytes[vend] != b'}' {
                        vend += 1;
                    }
                    if vend >= bytes.len() {
                        return Err(LexError {
                            message: String::from("unterminated ${...}"),
                            offset: i,
                        });
                    }
                    parts.push(QuotePart::Var(String::from(&input[vstart..vend])));
                    i = vend + 1;
                    continue;
                }
                if i + 1 < bytes.len() && is_special_var_char(bytes[i + 1]) {
                    saw_dynamic_or_quote = true;
                    if !lit.is_empty() {
                        parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                    }
                    parts.push(QuotePart::Var(String::from(&input[i + 1..i + 2])));
                    i += 2;
                    continue;
                }
                if i + 1 < bytes.len() && is_ident_char(bytes[i + 1]) {
                    saw_dynamic_or_quote = true;
                    if !lit.is_empty() {
                        parts.push(QuotePart::Literal(core::mem::take(&mut lit)));
                    }
                    let vstart = i + 1;
                    let mut vend = vstart;
                    while vend < bytes.len() && is_ident_char(bytes[vend]) {
                        vend += 1;
                    }
                    parts.push(QuotePart::Var(String::from(&input[vstart..vend])));
                    i = vend;
                    continue;
                }
            }
            let ch = input[i..].chars().next().ok_or(LexError {
                message: String::from("invalid UTF-8 in word"),
                offset: i,
            })?;
            lit.push(ch);
            i += ch.len_utf8();
        }
        let kind = if saw_dynamic_or_quote {
            if !lit.is_empty() || parts.is_empty() {
                parts.push(QuotePart::Literal(lit));
            }
            TokenKind::DoubleQuoted(parts)
        } else if let Some(kw) = keyword_from_str(&lit) {
            TokenKind::Keyword(kw)
        } else {
            TokenKind::Word(lit)
        };
        tokens.push(Token {
            kind,
            span: Span { start, end: i },
        });
    }

    Ok(tokens)
}

/// Produce best-effort syntax-highlighting spans even on incomplete lines
/// (used live as the user types in the terminal).
pub fn highlight_line(input: &str, builtins: &[&str]) -> Vec<HighlightSpan> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut expect_cmd = true;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' || b == b'\t' || b == b'\r' {
            i += 1;
            continue;
        }
        if b == b'#' {
            out.push(HighlightSpan {
                span: Span {
                    start: i,
                    end: bytes.len(),
                },
                kind: HighlightKind::Comment,
            });
            break;
        }
        if bytes[i..].starts_with(b"@caps(") {
            let start = i;
            i += 6;
            while i < bytes.len() && bytes[i] != b')' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            out.push(HighlightSpan {
                span: Span { start, end: i },
                kind: HighlightKind::Caps,
            });
            continue;
        }
        if b == b'\'' || b == b'"' {
            let start = i;
            let q = b;
            i += 1;
            while i < bytes.len() {
                if q == b'"' && bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push(HighlightSpan {
                span: Span { start, end: i },
                kind: HighlightKind::StringLit,
            });
            expect_cmd = false;
            continue;
        }
        if b == b'$' {
            let start = i;
            i += 1;
            if i < bytes.len() && bytes[i] == b'(' {
                let mut depth = 1usize;
                i += 1;
                while i < bytes.len() && depth > 0 {
                    if bytes[i] == b'(' {
                        depth += 1;
                    } else if bytes[i] == b')' {
                        depth -= 1;
                    }
                    i += 1;
                }
            } else {
                while i < bytes.len() && is_ident_char(bytes[i]) {
                    i += 1;
                }
            }
            out.push(HighlightSpan {
                span: Span { start, end: i },
                kind: HighlightKind::Variable,
            });
            expect_cmd = false;
            continue;
        }
        if matches!(
            b,
            b';' | b'|'
                | b'&'
                | b'>'
                | b'<'
                | b'='
                | b'{'
                | b'}'
                | b'['
                | b']'
                | b'('
                | b')'
                | b','
        ) {
            let start = i;
            i += 1;
            if i < bytes.len() && matches!(bytes[i], b'&' | b'|' | b'>' | b'=') {
                i += 1;
            }
            out.push(HighlightSpan {
                span: Span { start, end: i },
                kind: HighlightKind::Operator,
            });
            if matches!(b, b';' | b'|' | b'&' | b'{') {
                expect_cmd = true;
            }
            continue;
        }
        let start = i;
        while i < bytes.len() && !is_word_break(bytes[i]) {
            i += 1;
        }
        let word = &input[start..i];
        let kind = if keyword_from_str(word).is_some() {
            if word == "else" {
                expect_cmd = false;
            }
            HighlightKind::Keyword
        } else if expect_cmd {
            expect_cmd = false;
            if builtins.contains(&word) {
                HighlightKind::Builtin
            } else {
                HighlightKind::Command
            }
        } else if word.bytes().all(|c| c.is_ascii_digit()) {
            HighlightKind::Number
        } else {
            HighlightKind::Default
        };
        out.push(HighlightSpan {
            span: Span { start, end: i },
            kind,
        });
    }
    out
}
