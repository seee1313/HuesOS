//! Shell AST nodes.

/// Maximum number of arguments accepted by one built-in command.
pub const MAX_ARGS: usize = 8;

/// Parsed command node.
#[derive(Clone, Copy)]
pub struct CommandAst<'src> {
    /// Built-in command name.
    pub name: &'src str,
    /// Positional arguments.
    pub args: [&'src str; MAX_ARGS],
    /// Number of valid entries in `args`.
    pub argc: usize,
}

/// Top-level AST node for one command line.
pub enum Ast<'src> {
    /// Empty line / no-op.
    Empty,
    /// One built-in command invocation.
    Command(CommandAst<'src>),
}
