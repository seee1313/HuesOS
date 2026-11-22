//! Recursive-descent parser for `hsh`.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::ast::{
    ArgExpr, CapsSpec, Chain, ChainOp, CmpOp, CommandCall, Cond, ErrRedirect, Expr, Pipeline,
    Redirect, Stmt, WordPart,
};
use crate::lexer::{tokenize, Keyword, QuotePart, Span, Token, TokenKind};

/// Parse failure with byte offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub offset: usize,
}

/// Parse an `hsh` script into a list of [`Stmt`]s.
pub fn parse_script(input: &str) -> Result<Vec<Stmt>, ParseError> {
    let tokens = tokenize(input).map_err(|e| ParseError {
        message: e.message,
        offset: e.offset,
    })?;
    let mut parser = Parser { tokens, pos: 0 };
    parser.parse_block(false)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_offset(&self) -> usize {
        self.peek().map_or(0, |t| t.span.start)
    }

    fn bump(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn skip_separators(&mut self) {
        while let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Newline | TokenKind::Semi) {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn skip_newlines(&mut self) {
        while let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Newline) {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_block(&mut self, stop_at_rbrace: bool) -> Result<Vec<Stmt>, ParseError> {
        let mut stmts = Vec::new();
        loop {
            self.skip_separators();
            let Some(tok) = self.peek() else {
                if stop_at_rbrace {
                    return Err(ParseError {
                        message: String::from("expected '}'"),
                        offset: self.peek_offset(),
                    });
                }
                break;
            };
            if stop_at_rbrace && matches!(tok.kind, TokenKind::RBrace) {
                self.bump();
                break;
            }
            stmts.push(self.parse_stmt()?);
        }
        Ok(stmts)
    }

    fn peek_next(&self) -> Option<&Token> {
        self.tokens.get(self.pos + 1)
    }

    fn starts_standalone_stmt(&self) -> bool {
        match self.peek().map(|token| &token.kind) {
            Some(TokenKind::Keyword(
                Keyword::Let
                | Keyword::If
                | Keyword::While
                | Keyword::For
                | Keyword::Fn
                | Keyword::Alias
                | Keyword::Break
                | Keyword::Continue
                | Keyword::Return,
            )) => true,
            Some(TokenKind::Word(name)) => {
                is_valid_var_ident(name)
                    && matches!(
                        self.peek_next().map(|token| &token.kind),
                        Some(TokenKind::Eq)
                    )
            }
            _ => false,
        }
    }

    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        let Some(tok) = self.peek() else {
            return Err(ParseError {
                message: String::from("unexpected end of input"),
                offset: 0,
            });
        };
        match &tok.kind {
            TokenKind::Keyword(Keyword::Let) => self.parse_let(),
            TokenKind::Keyword(Keyword::Alias) => self.parse_alias(),
            TokenKind::Keyword(Keyword::Fn) => self.parse_fn(),
            TokenKind::Keyword(Keyword::If) => self.parse_if(),
            TokenKind::Keyword(Keyword::While) => self.parse_while(),
            TokenKind::Keyword(Keyword::For) => self.parse_for(),
            TokenKind::Keyword(Keyword::Break) => {
                self.bump();
                Ok(Stmt::Break)
            }
            TokenKind::Keyword(Keyword::Continue) => {
                self.bump();
                Ok(Stmt::Continue)
            }
            TokenKind::Keyword(Keyword::Return) => self.parse_return(),
            TokenKind::Word(w)
                if is_valid_var_ident(w)
                    && matches!(self.peek_next().map(|t| &t.kind), Some(TokenKind::Eq)) =>
            {
                self.parse_assign()
            }
            _ => Ok(Stmt::Chain(self.parse_chain()?)),
        }
    }

    fn expect_ident_word(&mut self, ctx: &str) -> Result<String, ParseError> {
        let off = self.peek_offset();
        let Some(tok) = self.bump() else {
            return Err(ParseError {
                message: format!("expected {ctx}"),
                offset: off,
            });
        };
        match tok.kind {
            TokenKind::Word(w) => Ok(w),
            _ => Err(ParseError {
                message: format!("expected {ctx}"),
                offset: tok.span.start,
            }),
        }
    }

    fn parse_let(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // `let`
        let name = self.expect_ident_word("variable name")?;
        let off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::Eq,
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected '=' in let statement"),
                    offset: off,
                })
            }
        }
        let value = self.parse_expr()?;
        Ok(Stmt::Let { name, value })
    }

    fn parse_assign(&mut self) -> Result<Stmt, ParseError> {
        let name = self.expect_ident_word("variable name")?;
        let off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::Eq,
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected '=' in assignment"),
                    offset: off,
                })
            }
        }
        let value = self.parse_expr()?;
        Ok(Stmt::Assign { name, value })
    }

    fn parse_alias(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // `alias`
        let name = self.expect_ident_word("alias name")?;
        let off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::Eq,
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected '=' in alias statement"),
                    offset: off,
                })
            }
        }
        let val_off = self.peek_offset();
        let Some(tok) = self.bump() else {
            return Err(ParseError {
                message: String::from("expected alias target string"),
                offset: val_off,
            });
        };
        let value = match tok.kind {
            TokenKind::SingleQuoted(s) | TokenKind::Word(s) => s,
            TokenKind::DoubleQuoted(parts) => {
                let mut s = String::new();
                for p in parts {
                    if let QuotePart::Literal(l) = p {
                        s.push_str(&l);
                    } else {
                        return Err(ParseError {
                            message: String::from("alias value must be static text"),
                            offset: tok.span.start,
                        });
                    }
                }
                s
            }
            _ => {
                return Err(ParseError {
                    message: String::from("expected string or word for alias"),
                    offset: tok.span.start,
                })
            }
        };
        Ok(Stmt::Alias { name, value })
    }

    fn parse_fn(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // `fn`
        let name = self.expect_ident_word("function name")?;
        let off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::LParen,
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected '(' after function name"),
                    offset: off,
                })
            }
        }
        let mut params = Vec::new();
        loop {
            match self.peek() {
                Some(Token {
                    kind: TokenKind::RParen,
                    ..
                }) => {
                    self.bump();
                    break;
                }
                Some(Token {
                    kind: TokenKind::Comma,
                    ..
                }) => {
                    self.bump();
                }
                Some(Token {
                    kind: TokenKind::Word(_),
                    ..
                }) => {
                    params.push(self.expect_ident_word("parameter name")?);
                }
                _ => {
                    return Err(ParseError {
                        message: String::from("expected parameter or ')'"),
                        offset: self.peek_offset(),
                    })
                }
            }
        }
        let brace_off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::LBrace,
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected '{' before function body"),
                    offset: brace_off,
                })
            }
        }
        let body = self.parse_block(true)?;
        Ok(Stmt::FnDef { name, params, body })
    }

    fn parse_cond(&mut self) -> Result<Cond, ParseError> {
        let mut left = self.parse_cond_and()?;
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::OrOr)) {
            self.bump();
            self.skip_newlines();
            let right = self.parse_cond_and()?;
            left = Cond::Or(alloc::boxed::Box::new(left), alloc::boxed::Box::new(right));
        }
        Ok(left)
    }

    fn parse_cond_and(&mut self) -> Result<Cond, ParseError> {
        let mut left = self.parse_cond_unary()?;
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::AndAnd)) {
            self.bump();
            self.skip_newlines();
            let right = self.parse_cond_unary()?;
            left = Cond::And(alloc::boxed::Box::new(left), alloc::boxed::Box::new(right));
        }
        Ok(left)
    }

    fn parse_cond_unary(&mut self) -> Result<Cond, ParseError> {
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LBracket)) {
            self.bump();
            let mut bracket_args = Vec::new();
            loop {
                let off = self.peek_offset();
                match self.peek().map(|t| &t.kind) {
                    Some(TokenKind::RBracket) => {
                        self.bump();
                        break;
                    }
                    None | Some(TokenKind::Newline | TokenKind::LBrace) => {
                        return Err(ParseError {
                            message: String::from("expected ']' in condition"),
                            offset: off,
                        });
                    }
                    _ => {
                        let tok = self.bump().ok_or(ParseError {
                            message: String::from("unexpected EOF"),
                            offset: off,
                        })?;
                        bracket_args.push(token_to_arg_expr(tok)?);
                    }
                }
            }
            return Ok(Cond::Test(bracket_args));
        }
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Bang)) {
            self.bump();
            let inner = self.parse_cond_unary()?;
            return Ok(Cond::Not(alloc::boxed::Box::new(inner)));
        }
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LParen)) {
            self.bump();
            let inner = self.parse_cond()?;
            let off = self.peek_offset();
            match self.bump() {
                Some(Token {
                    kind: TokenKind::RParen,
                    ..
                }) => return Ok(inner),
                _ => {
                    return Err(ParseError {
                        message: String::from("expected ')' in condition"),
                        offset: off,
                    })
                }
            }
        }
        let left = self.parse_arg_expr()?;
        let op = match self.peek().map(|t| &t.kind) {
            Some(TokenKind::EqEq) => Some(CmpOp::Eq),
            Some(TokenKind::NotEq) => Some(CmpOp::Ne),
            Some(TokenKind::Lt) => Some(CmpOp::Lt),
            Some(TokenKind::Gt) => Some(CmpOp::Gt),
            Some(TokenKind::Le) => Some(CmpOp::Le),
            Some(TokenKind::Ge) => Some(CmpOp::Ge),
            Some(TokenKind::Keyword(Keyword::Contains)) => Some(CmpOp::Contains),
            _ => None,
        };
        if let Some(cmp) = op {
            self.bump();
            let right = self.parse_arg_expr()?;
            Ok(Cond::Compare {
                left,
                op: cmp,
                right,
            })
        } else {
            Ok(Cond::Truthy(left))
        }
    }

    fn parse_if(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // `if` or `elif`
        let cond = self.parse_cond()?;
        let brace_off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::LBrace,
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected '{' after if condition"),
                    offset: brace_off,
                })
            }
        }
        let then_body = self.parse_block(true)?;
        self.skip_newlines();
        let else_body = if matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::Elif))
        ) {
            Some(vec![self.parse_if()?])
        } else if matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::Else))
        ) {
            self.bump();
            self.skip_newlines();
            if matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::If))
            ) {
                Some(vec![self.parse_if()?])
            } else {
                let eb_off = self.peek_offset();
                match self.bump() {
                    Some(Token {
                        kind: TokenKind::LBrace,
                        ..
                    }) => {}
                    _ => {
                        return Err(ParseError {
                            message: String::from("expected '{' after else"),
                            offset: eb_off,
                        })
                    }
                }
                Some(self.parse_block(true)?)
            }
        } else {
            None
        };
        Ok(Stmt::If {
            cond,
            then_body,
            else_body,
        })
    }

    fn parse_while(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // `while`
        let cond = self.parse_cond()?;
        let brace_off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::LBrace,
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected '{' before while body"),
                    offset: brace_off,
                })
            }
        }
        let body = self.parse_block(true)?;
        Ok(Stmt::While { cond, body })
    }

    fn parse_for(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // `for`
        let var = self.expect_ident_word("loop variable")?;
        let in_off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::Keyword(Keyword::In),
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected 'in' in for loop"),
                    offset: in_off,
                })
            }
        }
        let iter = self.parse_expr()?;
        let brace_off = self.peek_offset();
        match self.bump() {
            Some(Token {
                kind: TokenKind::LBrace,
                ..
            }) => {}
            _ => {
                return Err(ParseError {
                    message: String::from("expected '{' before for body"),
                    offset: brace_off,
                })
            }
        }
        let body = self.parse_block(true)?;
        Ok(Stmt::For { var, iter, body })
    }

    fn parse_return(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // `return`
        let has_val = !matches!(
            self.peek().map(|t| &t.kind),
            None | Some(TokenKind::Newline | TokenKind::Semi | TokenKind::RBrace)
        );
        let val = if has_val {
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Stmt::Return(val))
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LBracket)) {
            self.bump();
            let mut items = Vec::new();
            loop {
                self.skip_newlines();
                match self.peek().map(|t| &t.kind) {
                    Some(TokenKind::RBracket) => {
                        self.bump();
                        break;
                    }
                    Some(TokenKind::Comma) => {
                        self.bump();
                    }
                    None => {
                        return Err(ParseError {
                            message: String::from("unterminated list '['"),
                            offset: self.peek_offset(),
                        })
                    }
                    _ => items.push(self.parse_expr()?),
                }
            }
            Ok(Expr::List(items))
        } else {
            Ok(Expr::Scalar(self.parse_arg_expr()?))
        }
    }

    fn parse_arg_expr(&mut self) -> Result<ArgExpr, ParseError> {
        let off = self.peek_offset();
        let Some(tok) = self.bump() else {
            return Err(ParseError {
                message: String::from("expected argument"),
                offset: off,
            });
        };
        token_to_arg_expr(tok)
    }

    fn parse_chain(&mut self) -> Result<Chain, ParseError> {
        let mut first = self.parse_pipeline()?;
        let mut rest = Vec::new();
        loop {
            match self.peek().map(|token| &token.kind) {
                Some(TokenKind::AndAnd) | Some(TokenKind::OrOr) => {
                    let op = if matches!(
                        self.peek().map(|token| &token.kind),
                        Some(TokenKind::AndAnd)
                    ) {
                        ChainOp::And
                    } else {
                        ChainOp::Or
                    };
                    self.bump();
                    self.skip_newlines();
                    rest.push((op, self.parse_pipeline()?));
                }
                Some(TokenKind::Amp) => {
                    self.bump();
                    if let Some((_, pipeline)) = rest.last_mut() {
                        pipeline.background = true;
                    } else {
                        first.background = true;
                    }
                    self.skip_newlines();
                    if matches!(
                        self.peek().map(|token| &token.kind),
                        None | Some(TokenKind::RBrace)
                    ) || self.starts_standalone_stmt()
                    {
                        break;
                    }
                    if matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Semi)) {
                        self.bump();
                        self.skip_newlines();
                        if matches!(
                            self.peek().map(|token| &token.kind),
                            None | Some(TokenKind::RBrace)
                        ) || self.starts_standalone_stmt()
                        {
                            break;
                        }
                    }
                    rest.push((ChainOp::Seq, self.parse_pipeline()?));
                }
                Some(TokenKind::Semi) => {
                    // A semicolon may trail the chain or separate a simple
                    // command from a following control-flow statement.
                    self.bump();
                    self.skip_newlines();
                    if matches!(
                        self.peek().map(|token| &token.kind),
                        None | Some(TokenKind::RBrace)
                    ) {
                        break;
                    }
                    if self.starts_standalone_stmt() {
                        break;
                    }
                    rest.push((ChainOp::Seq, self.parse_pipeline()?));
                }
                _ => break,
            }
        }
        Ok(Chain { first, rest })
    }

    fn parse_pipeline(&mut self) -> Result<Pipeline, ParseError> {
        let mut stages = vec![self.parse_command()?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Pipe)) {
            self.bump();
            self.skip_newlines();
            stages.push(self.parse_command()?);
        }
        Ok(Pipeline {
            stages,
            background: false,
        })
    }

    fn parse_command(&mut self) -> Result<CommandCall, ParseError> {
        let mut negated = false;
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Bang)) {
            self.bump();
            negated = !negated;
        }

        let caps = if let Some(Token {
            kind: TokenKind::CapsAnnot(spec),
            span,
        }) = self.peek().cloned()
        {
            self.bump();
            Some(CapsSpec::parse(&spec).map_err(|msg| ParseError {
                message: msg,
                offset: span.start,
            })?)
        } else {
            None
        };

        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Bang)) {
            self.bump();
            negated = !negated;
        }

        let name = if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LBracket)) {
            self.bump();
            ArgExpr {
                parts: vec![WordPart::Literal(String::from("["))],
                raw_var_only: None,
                quoted: false,
            }
        } else {
            self.parse_arg_expr()?
        };

        let mut args = Vec::new();
        let mut stdin_redirect = None;
        let mut redirect = None;
        let mut err_redirect = None;

        let is_where_cmd =
            name.parts.len() == 1 && matches!(&name.parts[0], WordPart::Literal(s) if s == "where");
        let is_test_cmd = name.parts.len() == 1
            && matches!(&name.parts[0], WordPart::Literal(s) if s == "test" || s == "[");

        while let Some(tok) = self.peek() {
            match &tok.kind {
                TokenKind::Newline
                | TokenKind::Semi
                | TokenKind::Amp
                | TokenKind::AndAnd
                | TokenKind::OrOr
                | TokenKind::Pipe
                | TokenKind::RBrace => break,
                TokenKind::Gt if is_where_cmd && args.len() == 1 => {
                    let arg_tok = self.bump().ok_or(ParseError {
                        message: String::from("unexpected EOF"),
                        offset: 0,
                    })?;
                    args.push(token_to_arg_expr(arg_tok)?);
                }
                TokenKind::Lt if is_where_cmd && args.len() == 1 => {
                    let arg_tok = self.bump().ok_or(ParseError {
                        message: String::from("unexpected EOF"),
                        offset: 0,
                    })?;
                    args.push(token_to_arg_expr(arg_tok)?);
                }
                TokenKind::Lt if !is_test_cmd => {
                    self.bump();
                    stdin_redirect = Some(self.parse_arg_expr()?);
                }
                TokenKind::Gt | TokenKind::GtGt => {
                    let is_append = matches!(tok.kind, TokenKind::GtGt);
                    self.bump();
                    let target = self.parse_arg_expr()?;
                    redirect = Some(if is_append {
                        Redirect::Append(target)
                    } else {
                        Redirect::Truncate(target)
                    });
                }
                TokenKind::ErrToOut => {
                    self.bump();
                    err_redirect = Some(ErrRedirect::ToStdout);
                }
                TokenKind::ErrGt | TokenKind::ErrGtGt => {
                    let is_append = matches!(tok.kind, TokenKind::ErrGtGt);
                    self.bump();
                    let target = self.parse_arg_expr()?;
                    err_redirect = Some(if is_append {
                        ErrRedirect::Append(target)
                    } else {
                        ErrRedirect::Truncate(target)
                    });
                }
                TokenKind::RBracket if is_test_cmd => {
                    self.bump();
                    args.push(ArgExpr {
                        parts: vec![WordPart::Literal(String::from("]"))],
                        raw_var_only: None,
                        quoted: false,
                    });
                }
                _ => {
                    let arg_tok = self.bump().ok_or(ParseError {
                        message: String::from("unexpected EOF"),
                        offset: 0,
                    })?;
                    args.push(token_to_arg_expr(arg_tok)?);
                }
            }
        }

        Ok(CommandCall {
            caps,
            negated,
            name,
            args,
            stdin_redirect,
            redirect,
            err_redirect,
        })
    }
}

fn is_valid_var_ident(w: &str) -> bool {
    let mut chars = w.bytes();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn keyword_str(k: Keyword) -> &'static str {
    match k {
        Keyword::Let => "let",
        Keyword::If => "if",
        Keyword::Elif => "elif",
        Keyword::Else => "else",
        Keyword::While => "while",
        Keyword::For => "for",
        Keyword::In => "in",
        Keyword::Fn => "fn",
        Keyword::Alias => "alias",
        Keyword::Break => "break",
        Keyword::Continue => "continue",
        Keyword::Return => "return",
        Keyword::Contains => "contains",
    }
}

fn token_to_arg_expr(tok: Token) -> Result<ArgExpr, ParseError> {
    let Span { start, .. } = tok.span;
    match tok.kind {
        TokenKind::Word(w) => Ok(ArgExpr {
            parts: vec![WordPart::Literal(w)],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::SingleQuoted(s) => Ok(ArgExpr {
            parts: vec![WordPart::Literal(s)],
            raw_var_only: None,
            quoted: true,
        }),
        TokenKind::Var(v) => Ok(ArgExpr {
            parts: vec![WordPart::Var(v.clone())],
            raw_var_only: Some(v),
            quoted: false,
        }),
        TokenKind::ArithSubst(expr) => Ok(ArgExpr {
            parts: vec![WordPart::ArithSubst(expr)],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::CmdSubst(script) => {
            let stmts = parse_script(&script).map_err(|e| ParseError {
                message: e.message,
                offset: start + e.offset,
            })?;
            Ok(ArgExpr {
                parts: vec![WordPart::CmdSubst(stmts)],
                raw_var_only: None,
                quoted: false,
            })
        }
        TokenKind::DoubleQuoted(qparts) => {
            let mut parts = Vec::with_capacity(qparts.len());
            for qp in qparts {
                match qp {
                    QuotePart::Literal(s) => parts.push(WordPart::Literal(s)),
                    QuotePart::Var(v) => parts.push(WordPart::Var(v)),
                    QuotePart::ArithSubst(expr) => parts.push(WordPart::ArithSubst(expr)),
                    QuotePart::CmdSubst(script) => {
                        let stmts = parse_script(&script).map_err(|e| ParseError {
                            message: e.message,
                            offset: start + e.offset,
                        })?;
                        parts.push(WordPart::CmdSubst(stmts));
                    }
                }
            }
            Ok(ArgExpr {
                parts,
                raw_var_only: None,
                quoted: true,
            })
        }
        TokenKind::Keyword(kw) => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from(keyword_str(kw)))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::Bang => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from("!"))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::Lt => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from("<"))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::Gt => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from(">"))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::Le => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from("<="))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::Ge => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from(">="))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::EqEq => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from("=="))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::NotEq => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from("!="))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::Eq => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from("="))],
            raw_var_only: None,
            quoted: false,
        }),
        TokenKind::Comma => Ok(ArgExpr {
            parts: vec![WordPart::Literal(String::from(","))],
            raw_var_only: None,
            quoted: false,
        }),
        _ => Err(ParseError {
            message: String::from("unexpected token in expression"),
            offset: start,
        }),
    }
}
