//! Platform-specific extensions.
//!
//! `std` puts its platform extras under `std::os::<platform>`; the same shape
//! is used here, with one module so far:
//!
//! * [`huesos`] — capability-mask introspection, the scheduler's CPU and clock
//!   information, and the extension traits that give [`crate::process::Command`]
//!   HuesOS-only powers (choosing the capability mask a child starts with).

pub mod huesos;
