//! Recursive-descent-ish shell parser using a `Peekable` token iterator.

use crate::ast::{Ast, CommandAst, MAX_ARGS};
use crate::lexer::Token;
use core::iter::Peekable;
use logos::Logos;

/// Parser error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Logos reported an invalid token.
    InvalidToken,
    /// Command has more than `MAX_ARGS` arguments.
    TooManyArgs,
}

/// Parser over a `logos` lexer wrapped in `Peekable`.
pub struct Parser<'src> {
    tokens: Peekable<logos::Lexer<'src, Token<'src>>>,
}

impl<'src> Parser<'src> {
    /// Create a parser for `input`.
    pub fn new(input: &'src str) -> Self {
        Self {
            tokens: Token::lexer(input).peekable(),
        }
    }

    /// Parse one command line into an AST.
    pub fn parse(mut self) -> Result<Ast<'src>, ParseError> {
        while matches!(self.tokens.peek(), Some(Ok(Token::Semicolon))) {
            let _ = self.tokens.next();
        }

        let Some(first) = self.tokens.next() else {
            return Ok(Ast::Empty);
        };
        let name = match first {
            Ok(Token::Word(word)) | Ok(Token::Quoted(word)) => normalize_atom(word),
            Ok(Token::Semicolon) => return Ok(Ast::Empty),
            Err(_) => return Err(ParseError::InvalidToken),
        };

        let mut command = CommandAst {
            name,
            args: [""; MAX_ARGS],
            argc: 0,
        };

        loop {
            match self.tokens.peek() {
                None => break,
                Some(Ok(Token::Semicolon)) => {
                    let _ = self.tokens.next();
                    break;
                }
                Some(Ok(Token::Word(_))) | Some(Ok(Token::Quoted(_))) => {
                    let token = self.tokens.next().unwrap();
                    let arg = match token {
                        Ok(Token::Word(word)) | Ok(Token::Quoted(word)) => normalize_atom(word),
                        _ => return Err(ParseError::InvalidToken),
                    };
                    if command.argc >= command.args.len() {
                        return Err(ParseError::TooManyArgs);
                    }
                    command.args[command.argc] = arg;
                    command.argc += 1;
                }
                Some(Err(_)) => return Err(ParseError::InvalidToken),
            }
        }

        Ok(Ast::Command(command))
    }
}

fn normalize_atom(atom: &str) -> &str {
    let bytes = atom.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        &atom[1..atom.len() - 1]
    } else {
        atom
    }
}
