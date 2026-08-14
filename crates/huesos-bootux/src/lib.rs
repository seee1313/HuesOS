//! Boot user-experience logic shared by init.
//!
//! This crate holds the parts of the boot splash that are pure
//! computation: configuration parsing, weighted progress tracking, and
//! splash geometry. It deliberately owns no I/O.
//!
//! The split exists so this logic is testable. The init binary is a
//! `no_std`/`no_main` crate in its own cargo workspace with a custom
//! ring3 target and `build-std`, which cannot host `cargo test` — a
//! host test build there collides on duplicate `core` lang items. By
//! keeping the arithmetic here, in a root-workspace member, `make test`
//! covers it on every run.

#![cfg_attr(not(test), no_std)]

pub mod config;
pub mod paint;
pub mod progress;
