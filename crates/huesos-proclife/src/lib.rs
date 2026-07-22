//! # HuesOS Process Lifecycle Policy
//!
//! Host-testable, dependency-free model of the **per-process lifecycle state
//! machine**: creation → running → exited → reaped, with exit-status capture,
//! waiter coordination for blocking exit waits / port signals, and reap
//! eligibility. It advances [ROADMAP.md](../../docs/ROADMAP.md) Short-Term #5
//! (*multiple/dynamic userspace processes*: finish the process lifecycle around
//! the spawn path — blocking waits or port signals for exit, teardown/reaping).
//!
//! ## Relationship to `huesos-lifecycle`
//!
//! `huesos-lifecycle` models **registry-level** concerns (bounded zombie
//! reclamation, the two-counter object-collection decision). This crate models
//! the **per-process** state machine that decides when a process has exited,
//! when its exit can be observed, and when it may be reaped. They are
//! complementary: the per-process `Reaped` transition is what feeds a record
//! into the registry's bounded graveyard.
//!
//! ## What lives here
//!
//! - [`ProcState`] and [`can_transition`]: the lifecycle states and the valid
//!   transition relation.
//! - [`ExitInfo`]: the exit payload (koid, generation, exit code) delivered to a
//!   supervisor via a blocking wait or a port packet.
//! - [`ProcessLifecycle`]: a stateful per-process record with `start` / `exit`
//!   / `reap`, waiter accounting, and `exit_info`.
//!
//! ## What does NOT live here
//!
//! No scheduler, no address spaces, no syscalls, no locks. The privileged
//! integration (driving transitions from `ThreadStart`/exit, waking blocked
//! `ProcessWait` callers, emitting port packets, and invoking the registry
//! graveyard on `Reaped`) is verified on-target. See
//! `docs/DYNAMIC_PROCESSES.md`.
//!
//! ## Safety budget
//!
//! This crate is intentionally **budget-neutral**: no `unsafe` blocks, no
//! `unwrap` or `expect` calls, and no panicking macros anywhere — including its
//! tests — so it adds nothing to the surface tracked by
//! `tools/check-safety-budget.py`.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// Lifecycle state of a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcState {
    /// Created (process object exists) but no thread has started yet.
    Created,
    /// At least one thread is running.
    Running,
    /// Exited with a status; observable by waiters; not yet reaped.
    Exited,
    /// Reaped: metadata released; terminal.
    Reaped,
}

impl ProcState {
    /// True when this is the terminal (`Reaped`) state.
    pub fn is_terminal(self) -> bool {
        matches!(self, ProcState::Reaped)
    }
}

/// The valid process-lifecycle transition relation.
///
/// ```text
/// Created -> Running   (first thread started)
/// Created -> Exited    (spawn failure / killed before start)
/// Running -> Exited    (normal exit or killed)
/// Exited  -> Reaped    (observed and reaped)
/// ```
pub fn can_transition(from: ProcState, to: ProcState) -> bool {
    matches!(
        (from, to),
        (ProcState::Created, ProcState::Running)
            | (ProcState::Created, ProcState::Exited)
            | (ProcState::Running, ProcState::Exited)
            | (ProcState::Exited, ProcState::Reaped)
    )
}

/// Exit payload delivered to a supervisor (blocking wait or port packet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitInfo {
    /// Kernel object id of the exited process.
    pub koid: u64,
    /// Generation distinguishing a reused `koid` (ABA defense).
    pub generation: u64,
    /// Exit status.
    pub exit_code: i64,
}

/// A stateful per-process lifecycle record.
#[derive(Clone, Copy, Debug)]
pub struct ProcessLifecycle {
    koid: u64,
    generation: u64,
    state: ProcState,
    exit_code: Option<i64>,
    waiters: usize,
}

impl ProcessLifecycle {
    /// A freshly created process (state [`ProcState::Created`], no exit, no
    /// waiters).
    pub fn new(koid: u64, generation: u64) -> Self {
        Self {
            koid,
            generation,
            state: ProcState::Created,
            exit_code: None,
            waiters: 0,
        }
    }

    /// Current state.
    pub fn state(&self) -> ProcState {
        self.state
    }

    /// The process koid.
    pub fn koid(&self) -> u64 {
        self.koid
    }

    /// The process generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The exit code, if the process has exited.
    pub fn exit_code(&self) -> Option<i64> {
        self.exit_code
    }

    /// Number of currently registered exit waiters.
    pub fn waiter_count(&self) -> usize {
        self.waiters
    }

    /// True when running.
    pub fn is_running(&self) -> bool {
        self.state == ProcState::Running
    }

    /// True when exited (observable, not yet reaped).
    pub fn is_exited(&self) -> bool {
        self.state == ProcState::Exited
    }

    /// Start the process: `Created -> Running`. Returns whether the transition
    /// happened.
    pub fn start(&mut self) -> bool {
        if can_transition(self.state, ProcState::Running) {
            self.state = ProcState::Running;
            true
        } else {
            false
        }
    }

    /// Exit the process with `code`: `Created -> Exited` (spawn failure) or
    /// `Running -> Exited`. Returns whether the transition happened. A process
    /// can exit at most once.
    pub fn exit(&mut self, code: i64) -> bool {
        if can_transition(self.state, ProcState::Exited) {
            self.state = ProcState::Exited;
            self.exit_code = Some(code);
            true
        } else {
            false
        }
    }

    /// Register an exit waiter (a blocked `ProcessWait` / port subscription).
    pub fn add_waiter(&mut self) -> bool {
        if self.state != ProcState::Created && self.state != ProcState::Running {
            return false;
        }
        self.waiters = self.waiters.saturating_add(1);
        true
    }

    /// Release an exit waiter; saturates at zero.
    pub fn remove_waiter(&mut self) {
        self.waiters = self.waiters.saturating_sub(1);
    }

    /// True when exited and no waiters remain (safe to reap).
    pub fn can_reap(&self) -> bool {
        self.state == ProcState::Exited && self.waiters == 0
    }

    /// Reap the process: `Exited -> Reaped`, only when [`can_reap`](Self::can_reap).
    /// Returns whether the transition happened.
    pub fn reap(&mut self) -> bool {
        if self.can_reap() {
            self.state = ProcState::Reaped;
            true
        } else {
            false
        }
    }

    /// The exit payload, available once the process has exited (and still after
    /// it is reaped), for delivery via a blocking wait or port packet.
    pub fn exit_info(&self) -> Option<ExitInfo> {
        let observable = self.state == ProcState::Exited || self.state == ProcState::Reaped;
        if observable {
            self.exit_code.map(|code| ExitInfo {
                koid: self.koid,
                generation: self.generation,
                exit_code: code,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    //! Host tests. Kept free of `unwrap`, `expect`, and panicking macros
    //! (asserts expand to a panic at runtime but do not match the budget's
    //! textual panic-macro pattern), keeping this crate budget-neutral.

    use super::*;

    // --- transition relation ---

    #[test]
    fn valid_transitions() {
        assert!(can_transition(ProcState::Created, ProcState::Running));
        assert!(can_transition(ProcState::Created, ProcState::Exited));
        assert!(can_transition(ProcState::Running, ProcState::Exited));
        assert!(can_transition(ProcState::Exited, ProcState::Reaped));
    }

    #[test]
    fn invalid_transitions() {
        // No skipping Running -> Reaped, no resurrection, no double exit.
        assert!(!can_transition(ProcState::Running, ProcState::Reaped));
        assert!(!can_transition(ProcState::Exited, ProcState::Running));
        assert!(!can_transition(ProcState::Reaped, ProcState::Running));
        assert!(!can_transition(ProcState::Exited, ProcState::Exited));
        assert!(!can_transition(ProcState::Created, ProcState::Reaped));
    }

    #[test]
    fn reaped_is_terminal() {
        assert!(ProcState::Reaped.is_terminal());
        assert!(!ProcState::Created.is_terminal());
        assert!(!ProcState::Running.is_terminal());
        assert!(!ProcState::Exited.is_terminal());
    }

    // --- start / exit ---

    #[test]
    fn new_process_is_created() {
        let p = ProcessLifecycle::new(42, 1);
        assert_eq!(p.state(), ProcState::Created);
        assert_eq!(p.koid(), 42);
        assert_eq!(p.generation(), 1);
        assert_eq!(p.exit_code(), None);
        assert_eq!(p.waiter_count(), 0);
        assert_eq!(p.exit_info(), None);
    }

    #[test]
    fn start_then_exit() {
        let mut p = ProcessLifecycle::new(1, 1);
        assert!(p.start());
        assert!(p.is_running());
        // Starting again fails.
        assert!(!p.start());
        assert!(p.exit(7));
        assert!(p.is_exited());
        assert_eq!(p.exit_code(), Some(7));
        assert_eq!(
            p.exit_info(),
            Some(ExitInfo { koid: 1, generation: 1, exit_code: 7 })
        );
    }

    #[test]
    fn exit_once_only() {
        let mut p = ProcessLifecycle::new(1, 1);
        assert!(p.start());
        assert!(p.exit(0));
        // A second exit is rejected.
        assert!(!p.exit(99));
        assert_eq!(p.exit_code(), Some(0));
    }

    #[test]
    fn spawn_failure_exits_from_created() {
        let mut p = ProcessLifecycle::new(2, 1);
        // Killed / failed before any thread started.
        assert!(p.exit(-1));
        assert!(p.is_exited());
        assert_eq!(p.exit_code(), Some(-1));
    }

    // --- waiters + reap ---

    #[test]
    fn cannot_reap_while_running() {
        let mut p = ProcessLifecycle::new(1, 1);
        assert!(p.start());
        assert!(!p.can_reap());
        assert!(!p.reap());
        assert!(p.is_running());
    }

    #[test]
    fn waiters_block_reaping() {
        let mut p = ProcessLifecycle::new(1, 1);
        assert!(p.start());
        p.add_waiter();
        p.add_waiter();
        assert!(p.exit(0));
        // Still has waiters -> not reapable.
        assert!(!p.can_reap());
        assert!(!p.reap());
        p.remove_waiter();
        assert!(!p.can_reap());
        p.remove_waiter();
        assert!(p.can_reap());
        assert!(p.reap());
        assert_eq!(p.state(), ProcState::Reaped);
    }

    #[test]
    fn remove_waiter_saturates_at_zero() {
        let mut p = ProcessLifecycle::new(1, 1);
        p.remove_waiter();
        p.remove_waiter();
        assert_eq!(p.waiter_count(), 0);
        p.add_waiter();
        assert_eq!(p.waiter_count(), 1);
    }

    #[test]
    fn reap_with_no_waiters_after_exit() {
        let mut p = ProcessLifecycle::new(1, 1);
        assert!(p.start());
        assert!(p.exit(3));
        assert!(p.can_reap());
        assert!(p.reap());
        assert!(p.state().is_terminal());
    }

    // --- terminal state ---

    #[test]
    fn reaped_is_stable() {
        let mut p = ProcessLifecycle::new(1, 1);
        assert!(p.start());
        assert!(p.exit(5));
        assert!(p.reap());
        // No further transitions.
        assert!(!p.start());
        assert!(!p.exit(6));
        assert!(!p.reap());
        assert_eq!(p.state(), ProcState::Reaped);
        // Exit info remains observable after reap.
        assert_eq!(
            p.exit_info(),
            Some(ExitInfo { koid: 1, generation: 1, exit_code: 5 })
        );
    }

    #[test]
    fn exit_info_none_before_exit() {
        let mut p = ProcessLifecycle::new(9, 3);
        assert_eq!(p.exit_info(), None);
        assert!(p.start());
        assert_eq!(p.exit_info(), None);
    }
    #[test]
    fn exited_process_does_not_accept_new_waiters() {
        let mut p = ProcessLifecycle::new(3, 1);
        assert!(p.start());
        assert!(p.exit(0));
        assert!(!p.add_waiter());
        assert_eq!(p.waiter_count(), 0);
        assert!(p.can_reap());
    }

}
