//! Shell lexer powered by `logos`.

use logos::Logos;

/// Shell tokens.
#[derive(Clone, Copy, Debug, PartialEq, Logos)]
#[logos(skip r"[ \t\r\n\f]+")]
pub enum Token<'src> {
    /// Command separator. The parser currently accepts only the first
    /// command, but keeping the token now makes sequence AST support easy.
    #[token(";")]
    Semicolon,
    /// Double-quoted atom without escape handling yet.
    #[regex(r#""[^"\r\n]*""#, |lex| lex.slice())]
    Quoted(&'src str),
    /// Bare word atom.
    #[regex(r"[^ \t\r\n\f;]+", |lex| lex.slice())]
    Word(&'src str),
}
