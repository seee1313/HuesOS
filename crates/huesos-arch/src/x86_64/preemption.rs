//! Scheduler v2 preemption and migration guards.
//!
//! Preemption and migration are intentionally different: a Task holding a
//! [`MigrationGuard`] may be preempted, but must resume on the same CPU; a Task
//! holding a [`PreemptionGuard`] cannot be context-switched. Nesting state is
//! Task-owned through the pointer installed in [`super::cpu_local`].

use huesos_sched::GuardError;

static RESCHEDULE_HOOK: spin::Once<fn()> = spin::Once::new();

/// Install the one-time callback checked when the outermost preemption guard
/// is released. Scheduler initialization owns this operation.
pub fn set_reschedule_hook(hook: fn()) {
    RESCHEDULE_HOOK.call_once(|| hook);
}

fn fatal_guard_error(_error: GuardError) -> ! {
    x86_64::instructions::interrupts::disable();
    crate::serial::emergency_write("[preempt] fatal execution-guard imbalance\n");
    loop {
        crate::hlt();
    }
}

/// Disable Task preemption until the returned guard is dropped.
pub fn disable_preemption() -> Result<PreemptionGuard, GuardError> {
    super::cpu_local::update_current_execution_guards(|guards| guards.disable_preemption())?;
    Ok(PreemptionGuard { active: true })
}

/// Disable Task migration while retaining kernel preemptibility.
pub fn disable_migration() -> Result<MigrationGuard, GuardError> {
    super::cpu_local::update_current_execution_guards(|guards| guards.disable_migration())?;
    Ok(MigrationGuard { active: true })
}

/// Whether ordinary Task preemption is currently legal.
pub fn can_preempt() -> bool {
    super::cpu_local::current_execution_guards().can_preempt()
}

/// Whether a preempted kernel context may move to another CPU.
pub fn can_migrate() -> bool {
    super::cpu_local::current_execution_guards().can_migrate()
}

/// Whether the current context may enter a scheduler-backed sleep.
pub fn can_sleep() -> bool {
    super::cpu_local::current_execution_guards().can_sleep()
}

/// Guard forbidding context switch of the current Task.
#[must_use = "dropping the guard re-enables preemption"]
pub struct PreemptionGuard {
    active: bool,
}

impl Drop for PreemptionGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let outermost =
            super::cpu_local::update_current_execution_guards(|guards| guards.enable_preemption())
                .unwrap_or_else(|error| fatal_guard_error(error));
        if outermost && x86_64::instructions::interrupts::are_enabled() {
            if let Some(hook) = RESCHEDULE_HOOK.get().copied() {
                hook();
            }
        }
    }
}

/// Guard pinning a preemptible Task to its current CPU.
#[must_use = "dropping the guard permits migration"]
pub struct MigrationGuard {
    active: bool,
}

impl Drop for MigrationGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let _outermost =
            super::cpu_local::update_current_execution_guards(|guards| guards.enable_migration())
                .unwrap_or_else(|error| fatal_guard_error(error));
    }
}
