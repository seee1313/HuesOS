//! NVMe production reliability and telemetry policy core.
//!
//! Stage U keeps reset/timeout/queue-depth decisions host-testable before they
//! are wired into the live DriverHost. This module is no-heap and does not touch
//! hardware directly.

/// NVMe reliability policy error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReliabilityError {
    /// No queue slot is available.
    QueueFull,
    /// Request id was not found.
    NotFound,
    /// Request timed out.
    TimedOut,
    /// Controller reset is required before more I/O.
    ResetRequired,
    /// Operation is not supported by the current namespace/controller.
    Unsupported,
}

/// Queue slot state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueSlot {
    /// Client request id.
    pub request_id: u64,
    /// Submission tick.
    pub submitted_tick: u64,
    /// Timeout deadline tick.
    pub deadline_tick: u64,
}

/// Fixed-depth request slot tracker.
pub struct QueueSlotTracker<const N: usize> {
    slots: [Option<QueueSlot>; N],
}

impl<const N: usize> Default for QueueSlotTracker<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> QueueSlotTracker<N> {
    /// Create an empty tracker.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; N],
        }
    }

    /// Submit one request into a free slot.
    pub fn submit(
        &mut self,
        request_id: u64,
        now_tick: u64,
        timeout_ticks: u64,
    ) -> Result<(), ReliabilityError> {
        let deadline_tick = now_tick
            .checked_add(timeout_ticks)
            .ok_or(ReliabilityError::TimedOut)?;
        let mut index = 0usize;
        while index < self.slots.len() {
            if self.slots[index].is_none() {
                self.slots[index] = Some(QueueSlot {
                    request_id,
                    submitted_tick: now_tick,
                    deadline_tick,
                });
                return Ok(());
            }
            index += 1;
        }
        Err(ReliabilityError::QueueFull)
    }

    /// Complete one request id.
    pub fn complete(&mut self, request_id: u64) -> Result<QueueSlot, ReliabilityError> {
        let mut index = 0usize;
        while index < self.slots.len() {
            if let Some(slot) = self.slots[index] {
                if slot.request_id == request_id {
                    self.slots[index] = None;
                    return Ok(slot);
                }
            }
            index += 1;
        }
        Err(ReliabilityError::NotFound)
    }

    /// Return the first expired request id, if any.
    pub fn expired_request(&self, now_tick: u64) -> Option<u64> {
        let mut index = 0usize;
        while index < self.slots.len() {
            if let Some(slot) = self.slots[index] {
                if now_tick >= slot.deadline_tick {
                    return Some(slot.request_id);
                }
            }
            index += 1;
        }
        None
    }

    /// Count active slots.
    pub fn active(&self) -> usize {
        let mut count = 0usize;
        let mut index = 0usize;
        while index < self.slots.len() {
            if self.slots[index].is_some() {
                count += 1;
            }
            index += 1;
        }
        count
    }
}

/// Controller recovery state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResetState {
    /// Controller accepts normal I/O.
    Online,
    /// A command timeout was observed; new I/O should be blocked.
    TimedOut { request_id: u64 },
    /// Reset command sequence is in progress.
    Resetting { started_tick: u64 },
    /// Identify/queue setup must be rerun after reset.
    Reidentify,
    /// Controller failed permanently until service restart/operator action.
    Failed,
}

/// Reset state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetController {
    state: ResetState,
    max_reset_ticks: u64,
}

impl ResetController {
    /// Create an online reset controller.
    pub const fn new(max_reset_ticks: u64) -> Self {
        Self {
            state: ResetState::Online,
            max_reset_ticks,
        }
    }

    /// Current state.
    pub const fn state(&self) -> ResetState {
        self.state
    }

    /// Record a timeout.
    pub fn command_timed_out(&mut self, request_id: u64) {
        if matches!(self.state, ResetState::Online) {
            self.state = ResetState::TimedOut { request_id };
        }
    }

    /// Begin reset after timeout.
    pub fn begin_reset(&mut self, now_tick: u64) -> Result<(), ReliabilityError> {
        match self.state {
            ResetState::TimedOut { .. } => {
                self.state = ResetState::Resetting {
                    started_tick: now_tick,
                };
                Ok(())
            }
            _ => Err(ReliabilityError::ResetRequired),
        }
    }

    /// Poll reset completion/timeout.
    pub fn poll_reset(&mut self, now_tick: u64, hardware_ready: bool) -> ResetState {
        match self.state {
            ResetState::Resetting { started_tick } if hardware_ready => {
                self.state = ResetState::Reidentify;
            }
            ResetState::Resetting { started_tick }
                if now_tick.saturating_sub(started_tick) > self.max_reset_ticks =>
            {
                self.state = ResetState::Failed;
            }
            _ => {}
        }
        self.state
    }

    /// Mark re-identification and queue recreation complete.
    pub fn reidentify_complete(&mut self) {
        if matches!(self.state, ResetState::Reidentify) {
            self.state = ResetState::Online;
        }
    }
}

/// Block-level maintenance operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceOp {
    /// NVMe Flush command.
    Flush,
    /// NVMe Dataset Management deallocate/TRIM hint.
    Discard { lba: u64, blocks: u32 },
    /// NVMe Write Zeroes command.
    WriteZeroes { lba: u64, blocks: u32 },
}

/// Validate a maintenance operation against namespace support.
pub fn validate_maintenance(
    op: MaintenanceOp,
    discard_supported: bool,
    write_zeroes_supported: bool,
) -> Result<(), ReliabilityError> {
    match op {
        MaintenanceOp::Flush => Ok(()),
        MaintenanceOp::Discard { blocks, .. } if blocks == 0 => Err(ReliabilityError::Unsupported),
        MaintenanceOp::Discard { .. } if discard_supported => Ok(()),
        MaintenanceOp::Discard { .. } => Err(ReliabilityError::Unsupported),
        MaintenanceOp::WriteZeroes { blocks, .. } if blocks == 0 => {
            Err(ReliabilityError::Unsupported)
        }
        MaintenanceOp::WriteZeroes { .. } if write_zeroes_supported => Ok(()),
        MaintenanceOp::WriteZeroes { .. } => Err(ReliabilityError::Unsupported),
    }
}

/// NVMe telemetry counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NvmeTelemetry {
    /// Submitted commands.
    pub submitted: u64,
    /// Completed commands.
    pub completed: u64,
    /// Timed-out commands.
    pub timeouts: u64,
    /// Controller resets.
    pub resets: u64,
    /// Queue-full events.
    pub queue_full: u64,
    /// Flush commands.
    pub flushes: u64,
    /// Discard/TRIM commands.
    pub discards: u64,
    /// Write-zeroes commands.
    pub write_zeroes: u64,
}

impl NvmeTelemetry {
    /// Record submitted command.
    pub fn record_submit(&mut self) {
        self.submitted = self.submitted.saturating_add(1);
    }

    /// Record completed command.
    pub fn record_complete(&mut self) {
        self.completed = self.completed.saturating_add(1);
    }

    /// Record timeout.
    pub fn record_timeout(&mut self) {
        self.timeouts = self.timeouts.saturating_add(1);
    }

    /// Record reset.
    pub fn record_reset(&mut self) {
        self.resets = self.resets.saturating_add(1);
    }

    /// Record queue-full event.
    pub fn record_queue_full(&mut self) {
        self.queue_full = self.queue_full.saturating_add(1);
    }

    /// Record maintenance op.
    pub fn record_maintenance(&mut self, op: MaintenanceOp) {
        match op {
            MaintenanceOp::Flush => self.flushes = self.flushes.saturating_add(1),
            MaintenanceOp::Discard { .. } => self.discards = self.discards.saturating_add(1),
            MaintenanceOp::WriteZeroes { .. } => {
                self.write_zeroes = self.write_zeroes.saturating_add(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_slots_track_completion_and_timeout() {
        let mut tracker = QueueSlotTracker::<2>::new();
        assert_eq!(tracker.submit(10, 1, 5), Ok(()));
        assert_eq!(tracker.submit(11, 2, 5), Ok(()));
        assert_eq!(tracker.submit(12, 3, 5), Err(ReliabilityError::QueueFull));
        assert_eq!(tracker.expired_request(5), None);
        assert_eq!(tracker.expired_request(6), Some(10));
        assert_eq!(tracker.complete(10).map(|slot| slot.request_id), Ok(10));
        assert_eq!(tracker.active(), 1);
    }

    #[test]
    fn reset_state_machine_requires_reidentify() {
        let mut reset = ResetController::new(10);
        reset.command_timed_out(7);
        assert_eq!(reset.state(), ResetState::TimedOut { request_id: 7 });
        assert_eq!(reset.begin_reset(100), Ok(()));
        assert_eq!(reset.poll_reset(105, true), ResetState::Reidentify);
        reset.reidentify_complete();
        assert_eq!(reset.state(), ResetState::Online);
    }

    #[test]
    fn maintenance_support_is_explicit() {
        assert_eq!(
            validate_maintenance(MaintenanceOp::Flush, false, false),
            Ok(())
        );
        assert_eq!(
            validate_maintenance(MaintenanceOp::Discard { lba: 1, blocks: 8 }, false, false),
            Err(ReliabilityError::Unsupported)
        );
        assert_eq!(
            validate_maintenance(
                MaintenanceOp::WriteZeroes { lba: 1, blocks: 8 },
                false,
                true
            ),
            Ok(())
        );
    }

    #[test]
    fn telemetry_saturates_and_counts() {
        let mut telemetry = NvmeTelemetry::default();
        telemetry.record_submit();
        telemetry.record_complete();
        telemetry.record_timeout();
        telemetry.record_reset();
        telemetry.record_queue_full();
        telemetry.record_maintenance(MaintenanceOp::Flush);
        telemetry.record_maintenance(MaintenanceOp::Discard { lba: 0, blocks: 1 });
        assert_eq!(telemetry.submitted, 1);
        assert_eq!(telemetry.flushes, 1);
        assert_eq!(telemetry.discards, 1);
    }
}
