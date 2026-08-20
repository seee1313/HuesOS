//! Host-testable policy core for HuesOS Scheduler/SMP v2.
//!
//! This crate contains no context switching, APIC access, allocation, or
//! privileged synchronization. It defines identities, masks, lifecycle
//! transitions, remote-inbox geometry, EEVDF policy, and CBS admission as pure
//! or bounded mechanisms. The kernel integration must preserve these
//! invariants; passing these tests alone is not a production-grade claim.

#![no_std]
#![forbid(unsafe_code)]

use core::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};

/// Maximum logical CPUs represented by Scheduler v2 masks.
pub const MAX_CPUS: usize = 256;
/// Maximum live/published scheduler Task slots.
pub const MAX_TASKS: usize = 8192;
/// Number of Task bits in one inbox word.
pub const TASK_BITS_PER_WORD: usize = u64::BITS as usize;
/// Task bitmap words in one CPU inbox.
pub const TASK_INBOX_WORDS: usize = MAX_TASKS / TASK_BITS_PER_WORD;
/// First-level summary words needed to name every Task bitmap word.
pub const TASK_INBOX_SUMMARY_WORDS: usize = TASK_INBOX_WORDS / TASK_BITS_PER_WORD;
/// Normalized weight representing an ordinary task.
pub const NICE_0_WEIGHT: u64 = 1024;
/// Initial CBS + threaded-IRQ admission ceiling, in parts per million.
pub const DEFAULT_CBS_CEILING_PPM: u32 = 800_000;

const _: () = assert!(MAX_CPUS.is_multiple_of(u64::BITS as usize));
const _: () = assert!(MAX_TASKS.is_power_of_two());
const _: () = assert!(TASK_INBOX_WORDS.is_multiple_of(u64::BITS as usize));

/// A dense CPU array/mask index. Hardware APIC IDs are a different type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CpuIndex(u16);

impl CpuIndex {
    /// Validate a dense CPU index.
    pub const fn new(index: usize) -> Option<Self> {
        if index < MAX_CPUS {
            Some(Self(index as u16))
        } else {
            None
        }
    }

    /// Return this dense index as `usize`.
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

/// A 256-bit CPU mask independent of hardware APIC IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuMask {
    words: [u64; MAX_CPUS / 64],
}

impl CpuMask {
    /// Empty mask.
    pub const fn empty() -> Self {
        Self {
            words: [0; MAX_CPUS / 64],
        }
    }

    /// Mask containing every representable dense CPU.
    pub const fn full() -> Self {
        Self {
            words: [u64::MAX; MAX_CPUS / 64],
        }
    }

    /// Build a mask with one CPU.
    pub const fn one(cpu: CpuIndex) -> Self {
        let mut mask = Self::empty();
        mask.words[cpu.as_usize() / 64] = 1u64 << (cpu.as_usize() % 64);
        mask
    }

    /// Set a CPU bit.
    pub fn insert(&mut self, cpu: CpuIndex) {
        self.words[cpu.as_usize() / 64] |= 1u64 << (cpu.as_usize() % 64);
    }

    /// Clear a CPU bit.
    pub fn remove(&mut self, cpu: CpuIndex) {
        self.words[cpu.as_usize() / 64] &= !(1u64 << (cpu.as_usize() % 64));
    }

    /// Whether a CPU belongs to this mask.
    pub const fn contains(self, cpu: CpuIndex) -> bool {
        self.words[cpu.as_usize() / 64] & (1u64 << (cpu.as_usize() % 64)) != 0
    }

    /// Number of selected CPUs.
    pub fn count(self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// Whether the mask has no selected CPUs.
    pub const fn is_empty(self) -> bool {
        let mut index = 0;
        while index < self.words.len() {
            if self.words[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    /// Intersection of two masks.
    pub const fn intersection(self, other: Self) -> Self {
        let mut out = Self::empty();
        let mut index = 0;
        while index < self.words.len() {
            out.words[index] = self.words[index] & other.words[index];
            index += 1;
        }
        out
    }

    /// Union of two masks.
    pub const fn union(self, other: Self) -> Self {
        let mut out = Self::empty();
        let mut index = 0;
        while index < self.words.len() {
            out.words[index] = self.words[index] | other.words[index];
            index += 1;
        }
        out
    }

    /// First selected CPU, if any.
    pub fn first(self) -> Option<CpuIndex> {
        for (word_index, word) in self.words.iter().copied().enumerate() {
            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                return CpuIndex::new(word_index * 64 + bit);
            }
        }
        None
    }

    /// Expose words for ABI/atomic integration tests.
    pub const fn words(self) -> [u64; MAX_CPUS / 64] {
        self.words
    }
}

impl Default for CpuMask {
    fn default() -> Self {
        Self::empty()
    }
}

/// Number of low bits occupied by the 8192-slot index.
const TASK_INDEX_BITS: u32 = MAX_TASKS.trailing_zeros();
const TASK_INDEX_MASK: u64 = (1u64 << TASK_INDEX_BITS) - 1;
/// Largest generation representable without producing raw zero.
pub const MAX_TASK_GENERATION: u64 = u64::MAX >> TASK_INDEX_BITS;

/// Stable Task identity. CPU ownership is deliberately not encoded.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TaskId(u64);

impl TaskId {
    /// Construct an ID for a valid slot and non-zero generation.
    pub const fn new(slot: usize, generation: u64) -> Option<Self> {
        if slot >= MAX_TASKS || generation == 0 || generation > MAX_TASK_GENERATION {
            return None;
        }
        Some(Self((generation << TASK_INDEX_BITS) | slot as u64))
    }

    /// Decode a non-zero raw ID.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 {
            return None;
        }
        let id = Self(raw);
        if id.slot() < MAX_TASKS && id.generation() != 0 {
            Some(id)
        } else {
            None
        }
    }

    /// Raw stable representation.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Global registry slot.
    pub const fn slot(self) -> usize {
        (self.0 & TASK_INDEX_MASK) as usize
    }

    /// Slot generation.
    pub const fn generation(self) -> u64 {
        self.0 >> TASK_INDEX_BITS
    }

    /// Next generation for the same slot, or `None` when the slot must retire.
    pub const fn next_generation(self) -> Option<Self> {
        let generation = self.generation();
        if generation == MAX_TASK_GENERATION {
            None
        } else {
            Self::new(self.slot(), generation + 1)
        }
    }
}

/// Preemption behavior selected at boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreemptionProfile {
    /// Ordinary Fair work may preempt kernel process context.
    Full,
    /// Fair preemption may wait for a lazy boundary; CBS urgency stays direct.
    Lazy,
}

/// Nested execution guards carried by a Task across CPU migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionGuards {
    preempt_depth: u16,
    migration_depth: u16,
}

/// Invalid guard transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardError {
    /// A nesting counter would overflow.
    Overflow,
    /// An unmatched enable/drop was attempted.
    Underflow,
}

impl ExecutionGuards {
    /// No disabled execution property.
    pub const fn new() -> Self {
        Self {
            preempt_depth: 0,
            migration_depth: 0,
        }
    }

    /// Disable preemption in a nested scope.
    pub fn disable_preemption(&mut self) -> Result<(), GuardError> {
        self.preempt_depth = self
            .preempt_depth
            .checked_add(1)
            .ok_or(GuardError::Overflow)?;
        Ok(())
    }

    /// Leave one preemption-disabled scope. Returns true at the outer edge.
    pub fn enable_preemption(&mut self) -> Result<bool, GuardError> {
        self.preempt_depth = self
            .preempt_depth
            .checked_sub(1)
            .ok_or(GuardError::Underflow)?;
        Ok(self.preempt_depth == 0)
    }

    /// Pin the Task to its current CPU while retaining preemptibility.
    pub fn disable_migration(&mut self) -> Result<(), GuardError> {
        self.migration_depth = self
            .migration_depth
            .checked_add(1)
            .ok_or(GuardError::Overflow)?;
        Ok(())
    }

    /// Leave one migration-disabled scope. Returns true at the outer edge.
    pub fn enable_migration(&mut self) -> Result<bool, GuardError> {
        self.migration_depth = self
            .migration_depth
            .checked_sub(1)
            .ok_or(GuardError::Underflow)?;
        Ok(self.migration_depth == 0)
    }

    /// Whether ordinary scheduling may preempt this Task.
    pub const fn can_preempt(self) -> bool {
        self.preempt_depth == 0
    }

    /// Whether a preempted Task may be transferred to another CPU.
    pub const fn can_migrate(self) -> bool {
        self.preempt_depth == 0 && self.migration_depth == 0
    }

    /// Whether sleeping is legal. Temporary CPU-local borrows forbid it.
    pub const fn can_sleep(self) -> bool {
        self.preempt_depth == 0 && self.migration_depth == 0
    }

    /// Current preemption nesting depth.
    pub const fn preempt_depth(self) -> u16 {
        self.preempt_depth
    }

    /// Current migration nesting depth.
    pub const fn migration_depth(self) -> u16 {
        self.migration_depth
    }
}

impl Default for ExecutionGuards {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable lifecycle states. Transitional metadata is carried by
/// [`TaskLifecycle`] so rollback remains explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    Embryo,
    DeferredReady,
    Ready,
    Running,
    Blocking,
    Blocked,
    Waking,
    Migrating,
    Dying,
    Dead,
    Reaped,
}

/// Source state retained during two-phase migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationSource {
    Ready,
    Blocked,
}

/// Invalid lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    WrongState,
    StaleEpoch,
    SameCpu,
    MigrationUnsafe,
}

/// Pure lifecycle oracle for kernel atomic-state integration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskLifecycle {
    state: TaskState,
    owner: Option<CpuIndex>,
    target: Option<CpuIndex>,
    wait_epoch: u32,
    migration_generation: u32,
    migration_source: Option<MigrationSource>,
    wake_pending: bool,
}

impl TaskLifecycle {
    pub const fn new() -> Self {
        Self {
            state: TaskState::Embryo,
            owner: None,
            target: None,
            wait_epoch: 0,
            migration_generation: 0,
            migration_source: None,
            wake_pending: false,
        }
    }

    pub const fn state(self) -> TaskState {
        self.state
    }

    pub const fn owner(self) -> Option<CpuIndex> {
        self.owner
    }

    pub const fn target(self) -> Option<CpuIndex> {
        self.target
    }

    pub const fn wait_epoch(self) -> u32 {
        self.wait_epoch
    }

    pub const fn migration_generation(self) -> u32 {
        self.migration_generation
    }

    pub const fn wake_pending(self) -> bool {
        self.wake_pending
    }

    pub fn defer_ready(&mut self, target: CpuIndex) -> Result<(), LifecycleError> {
        if self.state != TaskState::Embryo {
            return Err(LifecycleError::WrongState);
        }
        self.state = TaskState::DeferredReady;
        self.target = Some(target);
        Ok(())
    }

    pub fn enqueue_ready(&mut self, cpu: CpuIndex) -> Result<(), LifecycleError> {
        if self.state != TaskState::DeferredReady || self.target != Some(cpu) {
            return Err(LifecycleError::WrongState);
        }
        self.state = TaskState::Ready;
        self.owner = Some(cpu);
        self.target = None;
        Ok(())
    }

    pub fn start_running(&mut self, cpu: CpuIndex) -> Result<(), LifecycleError> {
        if self.state != TaskState::Ready || self.owner != Some(cpu) {
            return Err(LifecycleError::WrongState);
        }
        self.state = TaskState::Running;
        Ok(())
    }

    pub fn preempt(&mut self, cpu: CpuIndex) -> Result<(), LifecycleError> {
        if self.state != TaskState::Running || self.owner != Some(cpu) {
            return Err(LifecycleError::WrongState);
        }
        self.state = TaskState::Ready;
        Ok(())
    }

    pub fn begin_block(&mut self, cpu: CpuIndex, epoch: u32) -> Result<(), LifecycleError> {
        if self.state != TaskState::Running || self.owner != Some(cpu) {
            return Err(LifecycleError::WrongState);
        }
        self.state = TaskState::Blocking;
        self.wait_epoch = epoch;
        self.wake_pending = false;
        Ok(())
    }

    pub fn complete_block(&mut self, cpu: CpuIndex, epoch: u32) -> Result<bool, LifecycleError> {
        if self.state != TaskState::Blocking || self.owner != Some(cpu) {
            return Err(LifecycleError::WrongState);
        }
        if self.wait_epoch != epoch {
            return Err(LifecycleError::StaleEpoch);
        }
        if self.wake_pending {
            self.state = TaskState::Waking;
            if self.target.is_none() {
                self.target = Some(cpu);
            }
            Ok(false)
        } else {
            self.state = TaskState::Blocked;
            Ok(true)
        }
    }

    pub fn wake(&mut self, target: CpuIndex, epoch: u32) -> Result<bool, LifecycleError> {
        if self.wait_epoch != epoch {
            return Err(LifecycleError::StaleEpoch);
        }
        match self.state {
            TaskState::Blocking => {
                self.wake_pending = true;
                self.target = Some(target);
                Ok(true)
            }
            TaskState::Blocked => {
                self.state = TaskState::Waking;
                self.target = Some(target);
                Ok(true)
            }
            TaskState::Waking | TaskState::Ready | TaskState::Running => Ok(false),
            _ => Err(LifecycleError::WrongState),
        }
    }

    pub fn complete_wake(&mut self, cpu: CpuIndex, epoch: u32) -> Result<(), LifecycleError> {
        if self.state != TaskState::Waking || self.target != Some(cpu) {
            return Err(LifecycleError::WrongState);
        }
        if self.wait_epoch != epoch {
            return Err(LifecycleError::StaleEpoch);
        }
        self.state = TaskState::Ready;
        self.owner = Some(cpu);
        self.target = None;
        self.wake_pending = false;
        Ok(())
    }

    pub fn begin_migration(
        &mut self,
        target: CpuIndex,
        guards: ExecutionGuards,
    ) -> Result<u32, LifecycleError> {
        if !guards.can_migrate() {
            return Err(LifecycleError::MigrationUnsafe);
        }
        let source = match self.state {
            TaskState::Ready => MigrationSource::Ready,
            TaskState::Blocked => MigrationSource::Blocked,
            _ => return Err(LifecycleError::WrongState),
        };
        if self.owner == Some(target) {
            return Err(LifecycleError::SameCpu);
        }
        self.migration_generation = self.migration_generation.wrapping_add(1).max(1);
        self.migration_source = Some(source);
        self.target = Some(target);
        self.state = TaskState::Migrating;
        Ok(self.migration_generation)
    }

    pub fn commit_migration(
        &mut self,
        target: CpuIndex,
        generation: u32,
    ) -> Result<(), LifecycleError> {
        if self.state != TaskState::Migrating || self.target != Some(target) {
            return Err(LifecycleError::WrongState);
        }
        if self.migration_generation != generation {
            return Err(LifecycleError::StaleEpoch);
        }
        self.state = match self.migration_source {
            Some(MigrationSource::Ready) => TaskState::Ready,
            Some(MigrationSource::Blocked) => TaskState::Blocked,
            None => return Err(LifecycleError::WrongState),
        };
        self.owner = Some(target);
        self.target = None;
        self.migration_source = None;
        Ok(())
    }

    pub fn rollback_migration(&mut self, generation: u32) -> Result<(), LifecycleError> {
        if self.state != TaskState::Migrating {
            return Err(LifecycleError::WrongState);
        }
        if self.migration_generation != generation {
            return Err(LifecycleError::StaleEpoch);
        }
        self.state = match self.migration_source {
            Some(MigrationSource::Ready) => TaskState::Ready,
            Some(MigrationSource::Blocked) => TaskState::Blocked,
            None => return Err(LifecycleError::WrongState),
        };
        self.target = None;
        self.migration_source = None;
        Ok(())
    }

    pub fn begin_dying(&mut self) -> Result<(), LifecycleError> {
        match self.state {
            TaskState::Ready | TaskState::Running | TaskState::Blocked => {
                self.state = TaskState::Dying;
                self.target = None;
                self.wake_pending = false;
                Ok(())
            }
            _ => Err(LifecycleError::WrongState),
        }
    }

    pub fn mark_dead(&mut self) -> Result<(), LifecycleError> {
        if self.state != TaskState::Dying {
            return Err(LifecycleError::WrongState);
        }
        self.state = TaskState::Dead;
        Ok(())
    }

    pub fn reap(&mut self) -> Result<(), LifecycleError> {
        if self.state != TaskState::Dead {
            return Err(LifecycleError::WrongState);
        }
        self.state = TaskState::Reaped;
        self.owner = None;
        Ok(())
    }
}

impl Default for TaskLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

/// A validated Task bitmap location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxLocation {
    pub task_word: usize,
    pub task_bit: u64,
    pub summary_word: usize,
    pub summary_bit: u64,
}

/// Map a stable registry slot into the two-level inbox bitmap.
pub const fn inbox_location(slot: usize) -> Option<InboxLocation> {
    if slot >= MAX_TASKS {
        return None;
    }
    let task_word = slot / 64;
    let summary_slot = task_word;
    Some(InboxLocation {
        task_word,
        task_bit: 1u64 << (slot % 64),
        summary_word: summary_slot / 64,
        summary_bit: 1u64 << (summary_slot % 64),
    })
}

/// Result of publishing one remote Task operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishResult {
    /// True when the caller must send a coalesced reschedule IPI.
    pub send_ipi: bool,
    /// True when this publication set a previously clear Task bit.
    pub newly_pending: bool,
}

/// Allocation-free multi-producer, single-owner Task notification bitmap.
pub struct TaskInbox {
    words: [AtomicU64; TASK_INBOX_WORDS],
    summary: [AtomicU64; TASK_INBOX_SUMMARY_WORDS],
    armed: AtomicBool,
}

impl TaskInbox {
    pub const fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; TASK_INBOX_WORDS],
            summary: [const { AtomicU64::new(0) }; TASK_INBOX_SUMMARY_WORDS],
            armed: AtomicBool::new(false),
        }
    }

    /// Publish a Task slot after its operation metadata was stored.
    pub fn publish(&self, slot: usize) -> Option<PublishResult> {
        let location = inbox_location(slot)?;
        let previous =
            self.words[location.task_word].fetch_or(location.task_bit, Ordering::Release);
        self.summary[location.summary_word].fetch_or(location.summary_bit, Ordering::Release);
        let send_ipi = !self.armed.swap(true, Ordering::AcqRel);
        Some(PublishResult {
            send_ipi,
            newly_pending: previous & location.task_bit == 0,
        })
    }

    /// Drain all currently published Task slots. Only the owner CPU calls this.
    ///
    /// Returns the number of unique Task bits consumed. New publications that
    /// race with the final disarm either keep this drain running or cause a new
    /// IPI; they cannot be silently stranded.
    pub fn drain(&self, mut consume: impl FnMut(usize)) -> usize {
        let mut consumed = 0usize;
        loop {
            for summary_index in 0..TASK_INBOX_SUMMARY_WORDS {
                let mut dirty = self.summary[summary_index].swap(0, Ordering::AcqRel);
                while dirty != 0 {
                    let bit = dirty.trailing_zeros() as usize;
                    dirty &= dirty - 1;
                    let word_index = summary_index * 64 + bit;
                    let mut tasks = self.words[word_index].swap(0, Ordering::AcqRel);
                    while tasks != 0 {
                        let task_bit = tasks.trailing_zeros() as usize;
                        tasks &= tasks - 1;
                        consumed += 1;
                        consume(word_index * 64 + task_bit);
                    }
                }
            }

            self.armed.store(false, Ordering::Release);
            fence(Ordering::SeqCst);
            if !self.has_pending() {
                return consumed;
            }
            // If a producer already re-armed the inbox, it will send an IPI.
            // Return and let that delivery own the next drain. Otherwise claim
            // the work ourselves and continue without an unnecessary IPI.
            if self.armed.swap(true, Ordering::AcqRel) {
                return consumed;
            }
        }
    }

    /// Approximate pending state used only for the drain/disarm handshake.
    pub fn has_pending(&self) -> bool {
        self.summary
            .iter()
            .any(|word| word.load(Ordering::Acquire) != 0)
    }
}

impl Default for TaskInbox {
    fn default() -> Self {
        Self::new()
    }
}

/// One request in the pure EEVDF policy oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EevdfEntity {
    pub id: TaskId,
    pub weight: u64,
    pub request_ns: u64,
    pub virtual_start: u128,
    pub virtual_finish: u128,
    pub service_ns: u64,
}

/// EEVDF policy error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EevdfError {
    InvalidWeight,
    InvalidRequest,
    Full,
    Duplicate,
    NotFound,
    Overflow,
}

/// Fixed-capacity `O(n)` policy oracle. Runtime integration uses an augmented
/// indexed WAVL tree but must make the same selection decisions as this model.
pub struct EevdfModel<const N: usize> {
    virtual_time: u128,
    entities: [Option<EevdfEntity>; N],
}

impl<const N: usize> EevdfModel<N> {
    pub const fn new() -> Self {
        Self {
            virtual_time: 0,
            entities: [None; N],
        }
    }

    pub const fn virtual_time(&self) -> u128 {
        self.virtual_time
    }

    pub fn len(&self) -> usize {
        self.entities.iter().filter(|entry| entry.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn enqueue(
        &mut self,
        id: TaskId,
        weight: u64,
        request_ns: u64,
        preserved_start: Option<u128>,
    ) -> Result<(), EevdfError> {
        if weight == 0 {
            return Err(EevdfError::InvalidWeight);
        }
        if request_ns == 0 {
            return Err(EevdfError::InvalidRequest);
        }
        if self.entities.iter().flatten().any(|entity| entity.id == id) {
            return Err(EevdfError::Duplicate);
        }
        let virtual_start = preserved_start.unwrap_or(self.virtual_time);
        let delta = virtual_delta(request_ns, weight)?;
        let virtual_finish = virtual_start
            .checked_add(delta)
            .ok_or(EevdfError::Overflow)?;
        let slot = self
            .entities
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(EevdfError::Full)?;
        *slot = Some(EevdfEntity {
            id,
            weight,
            request_ns,
            virtual_start,
            virtual_finish,
            service_ns: 0,
        });
        Ok(())
    }

    pub fn remove(&mut self, id: TaskId) -> Result<EevdfEntity, EevdfError> {
        let slot = self
            .entities
            .iter_mut()
            .find(|entry| entry.is_some_and(|entity| entity.id == id))
            .ok_or(EevdfError::NotFound)?;
        slot.take().ok_or(EevdfError::NotFound)
    }

    /// Select the eligible request with earliest virtual finish. If runnable
    /// work exists but none is eligible, snap virtual time to earliest start.
    pub fn pick(&mut self) -> Option<TaskId> {
        if self.is_empty() {
            return None;
        }
        if !self
            .entities
            .iter()
            .flatten()
            .any(|entity| entity.virtual_start <= self.virtual_time)
        {
            if let Some(start) = self
                .entities
                .iter()
                .flatten()
                .map(|entity| entity.virtual_start)
                .min()
            {
                self.virtual_time = start;
            }
        }
        self.entities
            .iter()
            .flatten()
            .filter(|entity| entity.virtual_start <= self.virtual_time)
            .min_by_key(|entity| (entity.virtual_finish, entity.id))
            .map(|entity| entity.id)
    }

    /// Charge elapsed runtime and start the entity's next request.
    pub fn complete_request(&mut self, id: TaskId, elapsed_ns: u64) -> Result<(), EevdfError> {
        let total_weight = self
            .entities
            .iter()
            .flatten()
            .try_fold(0u64, |total, entity| total.checked_add(entity.weight))
            .ok_or(EevdfError::Overflow)?;
        let consumed = virtual_delta(elapsed_ns, total_weight)?;
        self.virtual_time = self
            .virtual_time
            .checked_add(consumed)
            .ok_or(EevdfError::Overflow)?;

        let entity = self
            .entities
            .iter_mut()
            .flatten()
            .find(|entity| entity.id == id)
            .ok_or(EevdfError::NotFound)?;
        entity.service_ns = entity
            .service_ns
            .checked_add(elapsed_ns)
            .ok_or(EevdfError::Overflow)?;
        // Requests form one virtual-time chain. Do not clamp the next start to
        // queue virtual time: an under-served entity must keep its positive
        // lag and remain eligible until it catches up.
        entity.virtual_start = entity.virtual_finish;
        entity.virtual_finish = entity
            .virtual_start
            .checked_add(virtual_delta(entity.request_ns, entity.weight)?)
            .ok_or(EevdfError::Overflow)?;
        Ok(())
    }

    pub fn entity(&self, id: TaskId) -> Option<EevdfEntity> {
        self.entities
            .iter()
            .flatten()
            .find(|entity| entity.id == id)
            .copied()
    }
}

impl<const N: usize> Default for EevdfModel<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn virtual_delta(runtime_ns: u64, weight: u64) -> Result<u128, EevdfError> {
    if weight == 0 {
        return Err(EevdfError::InvalidWeight);
    }
    let numerator = u128::from(runtime_ns)
        .checked_mul(u128::from(NICE_0_WEIGHT))
        .ok_or(EevdfError::Overflow)?;
    Ok(numerator.div_ceil(u128::from(weight)).max(1))
}

/// Validated CBS reservation parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CbsReservation {
    pub capacity_ns: u64,
    pub deadline_ns: u64,
    pub period_ns: u64,
}

/// CBS/admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Zero,
    InvalidOrder,
    Arithmetic,
    Overcommitted,
    NotReserved,
}

impl CbsReservation {
    pub const fn new(
        capacity_ns: u64,
        deadline_ns: u64,
        period_ns: u64,
    ) -> Result<Self, AdmissionError> {
        if capacity_ns == 0 || deadline_ns == 0 || period_ns == 0 {
            return Err(AdmissionError::Zero);
        }
        if capacity_ns > deadline_ns || deadline_ns > period_ns {
            return Err(AdmissionError::InvalidOrder);
        }
        Ok(Self {
            capacity_ns,
            deadline_ns,
            period_ns,
        })
    }

    /// Utilization rounded upward in parts per million.
    pub fn utilization_ppm(self) -> Result<u32, AdmissionError> {
        let scaled = u128::from(self.capacity_ns)
            .checked_mul(1_000_000)
            .ok_or(AdmissionError::Arithmetic)?;
        let ppm = scaled.div_ceil(u128::from(self.period_ns));
        u32::try_from(ppm).map_err(|_| AdmissionError::Arithmetic)
    }
}

/// Pure admission oracle. Kernel integration uses atomic target-first
/// reservations but must preserve these bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionControl {
    ceiling_ppm: u32,
    admitted_ppm: u32,
}

impl AdmissionControl {
    pub const fn new(ceiling_ppm: u32) -> Option<Self> {
        if ceiling_ppm == 0 || ceiling_ppm > 1_000_000 {
            None
        } else {
            Some(Self {
                ceiling_ppm,
                admitted_ppm: 0,
            })
        }
    }

    pub const fn production_default() -> Self {
        Self {
            ceiling_ppm: DEFAULT_CBS_CEILING_PPM,
            admitted_ppm: 0,
        }
    }

    pub const fn ceiling_ppm(self) -> u32 {
        self.ceiling_ppm
    }

    pub const fn admitted_ppm(self) -> u32 {
        self.admitted_ppm
    }

    pub fn reserve(&mut self, reservation: CbsReservation) -> Result<u32, AdmissionError> {
        let ppm = reservation.utilization_ppm()?;
        let next = self
            .admitted_ppm
            .checked_add(ppm)
            .ok_or(AdmissionError::Arithmetic)?;
        if next > self.ceiling_ppm {
            return Err(AdmissionError::Overcommitted);
        }
        self.admitted_ppm = next;
        Ok(ppm)
    }

    pub fn release_ppm(&mut self, ppm: u32) -> Result<(), AdmissionError> {
        self.admitted_ppm = self
            .admitted_ppm
            .checked_sub(ppm)
            .ok_or(AdmissionError::NotReserved)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(index: usize) -> CpuIndex {
        CpuIndex::new(index).unwrap_or_else(|| unreachable!())
    }

    fn task(slot: usize) -> TaskId {
        TaskId::new(slot, 1).unwrap_or_else(|| unreachable!())
    }

    #[test]
    fn cpu_mask_covers_all_256_dense_indexes() {
        let mut mask = CpuMask::empty();
        mask.insert(cpu(0));
        mask.insert(cpu(63));
        mask.insert(cpu(64));
        mask.insert(cpu(255));
        assert_eq!(mask.count(), 4);
        assert!(mask.contains(cpu(255)));
        mask.remove(cpu(63));
        assert!(!mask.contains(cpu(63)));
        assert_eq!(mask.first(), Some(cpu(0)));
        assert!(CpuIndex::new(256).is_none());
    }

    #[test]
    fn task_id_is_stable_and_generation_safe_without_cpu_bits() {
        let id = TaskId::new(MAX_TASKS - 1, 7).unwrap_or_else(|| unreachable!());
        assert_eq!(id.slot(), MAX_TASKS - 1);
        assert_eq!(id.generation(), 7);
        assert_eq!(TaskId::from_raw(id.raw()), Some(id));
        assert_eq!(id.next_generation().map(TaskId::generation), Some(8));
        assert!(TaskId::new(MAX_TASKS, 1).is_none());
        assert!(TaskId::new(0, 0).is_none());
        assert!(TaskId::from_raw(0).is_none());
    }

    #[test]
    fn execution_guards_distinguish_preemption_from_migration() {
        let mut guards = ExecutionGuards::new();
        guards
            .disable_migration()
            .unwrap_or_else(|_| unreachable!());
        assert!(guards.can_preempt());
        assert!(!guards.can_migrate());
        assert!(!guards.can_sleep());
        guards
            .disable_preemption()
            .unwrap_or_else(|_| unreachable!());
        assert!(!guards.can_preempt());
        assert_eq!(guards.enable_preemption(), Ok(true));
        assert_eq!(guards.enable_migration(), Ok(true));
        assert!(guards.can_migrate());
        assert_eq!(guards.enable_migration(), Err(GuardError::Underflow));
    }

    #[test]
    fn wake_during_blocking_cannot_be_lost() {
        let mut state = TaskLifecycle::new();
        state.defer_ready(cpu(0)).unwrap_or_else(|_| unreachable!());
        state
            .enqueue_ready(cpu(0))
            .unwrap_or_else(|_| unreachable!());
        state
            .start_running(cpu(0))
            .unwrap_or_else(|_| unreachable!());
        state
            .begin_block(cpu(0), 11)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(state.wake(cpu(1), 11), Ok(true));
        assert_eq!(state.complete_block(cpu(0), 11), Ok(false));
        assert_eq!(state.state(), TaskState::Waking);
        assert_eq!(state.target(), Some(cpu(1)));
        state
            .complete_wake(cpu(1), 11)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(state.state(), TaskState::Ready);
        assert_eq!(state.owner(), Some(cpu(1)));
    }

    #[test]
    fn migration_commit_and_rollback_keep_identity_out_of_state() {
        let mut state = TaskLifecycle::new();
        state.defer_ready(cpu(0)).unwrap_or_else(|_| unreachable!());
        state
            .enqueue_ready(cpu(0))
            .unwrap_or_else(|_| unreachable!());
        let generation = state
            .begin_migration(cpu(9), ExecutionGuards::new())
            .unwrap_or_else(|_| unreachable!());
        state
            .rollback_migration(generation)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(state.owner(), Some(cpu(0)));
        let generation = state
            .begin_migration(cpu(9), ExecutionGuards::new())
            .unwrap_or_else(|_| unreachable!());
        state
            .commit_migration(cpu(9), generation)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(state.owner(), Some(cpu(9)));
        assert_eq!(state.state(), TaskState::Ready);
    }

    #[test]
    fn migration_refuses_cpu_local_borrow() {
        let mut state = TaskLifecycle::new();
        state.defer_ready(cpu(0)).unwrap_or_else(|_| unreachable!());
        state
            .enqueue_ready(cpu(0))
            .unwrap_or_else(|_| unreachable!());
        let mut guards = ExecutionGuards::new();
        guards
            .disable_migration()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            state.begin_migration(cpu(1), guards),
            Err(LifecycleError::MigrationUnsafe)
        );
    }

    #[test]
    fn inbox_geometry_covers_first_boundaries_and_last_slot() {
        assert_eq!(
            inbox_location(0).map(|x| (x.task_word, x.task_bit)),
            Some((0, 1))
        );
        assert_eq!(inbox_location(63).map(|x| x.task_word), Some(0));
        assert_eq!(inbox_location(64).map(|x| x.task_word), Some(1));
        let last = inbox_location(MAX_TASKS - 1).unwrap_or_else(|| unreachable!());
        assert_eq!(last.task_word, TASK_INBOX_WORDS - 1);
        assert_eq!(last.summary_word, TASK_INBOX_SUMMARY_WORDS - 1);
        assert!(inbox_location(MAX_TASKS).is_none());
    }

    #[test]
    fn inbox_coalesces_duplicates_and_drains_unique_slots() {
        let inbox = TaskInbox::new();
        let first = inbox.publish(7).unwrap_or_else(|| unreachable!());
        let duplicate = inbox.publish(7).unwrap_or_else(|| unreachable!());
        let second = inbox.publish(4097).unwrap_or_else(|| unreachable!());
        assert!(first.send_ipi);
        assert!(first.newly_pending);
        assert!(!duplicate.send_ipi);
        assert!(!duplicate.newly_pending);
        assert!(!second.send_ipi);
        let mut seen = [usize::MAX; 2];
        let mut cursor = 0;
        let count = inbox.drain(|slot| {
            seen[cursor] = slot;
            cursor += 1;
        });
        assert_eq!(count, 2);
        assert_eq!(seen, [7, 4097]);
        assert!(!inbox.has_pending());
        assert!(inbox.publish(8).unwrap_or_else(|| unreachable!()).send_ipi);
    }

    #[test]
    fn eevdf_selects_earliest_finish_among_eligible_requests() {
        let mut queue = EevdfModel::<4>::new();
        queue
            .enqueue(task(1), 1024, 1_000, None)
            .unwrap_or_else(|_| unreachable!());
        queue
            .enqueue(task(2), 2048, 1_000, None)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(queue.pick(), Some(task(2)));
        queue
            .complete_request(task(2), 1_000)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(queue.pick(), Some(task(1)));
    }

    #[test]
    fn eevdf_weight_two_receives_twice_the_requests_over_time() {
        let mut queue = EevdfModel::<2>::new();
        let normal = task(1);
        let heavy = task(2);
        queue
            .enqueue(normal, NICE_0_WEIGHT, 1_000, None)
            .unwrap_or_else(|_| unreachable!());
        queue
            .enqueue(heavy, NICE_0_WEIGHT * 2, 1_000, None)
            .unwrap_or_else(|_| unreachable!());
        let mut normal_runs = 0usize;
        let mut heavy_runs = 0usize;
        for _ in 0..60 {
            let selected = queue.pick();
            if selected == Some(normal) {
                normal_runs += 1;
                queue
                    .complete_request(normal, 1_000)
                    .unwrap_or_else(|_| unreachable!());
            } else if selected == Some(heavy) {
                heavy_runs += 1;
                queue
                    .complete_request(heavy, 1_000)
                    .unwrap_or_else(|_| unreachable!());
            } else {
                assert!(false, "non-empty EEVDF queue must select a request");
            }
        }
        assert_eq!(heavy_runs, normal_runs * 2);
    }

    #[test]
    fn eevdf_snaps_to_future_eligible_time_without_idling() {
        let mut queue = EevdfModel::<2>::new();
        queue
            .enqueue(task(1), 1024, 1_000, Some(50_000))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(queue.virtual_time(), 0);
        assert_eq!(queue.pick(), Some(task(1)));
        assert_eq!(queue.virtual_time(), 50_000);
    }

    #[test]
    fn eevdf_refuses_invalid_or_duplicate_entities() {
        let mut queue = EevdfModel::<1>::new();
        assert_eq!(
            queue.enqueue(task(0), 0, 1, None),
            Err(EevdfError::InvalidWeight)
        );
        assert_eq!(
            queue.enqueue(task(0), 1, 0, None),
            Err(EevdfError::InvalidRequest)
        );
        queue
            .enqueue(task(0), 1, 1, None)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            queue.enqueue(task(0), 1, 1, None),
            Err(EevdfError::Duplicate)
        );
        assert_eq!(queue.enqueue(task(1), 1, 1, None), Err(EevdfError::Full));
    }

    #[test]
    fn cbs_validation_and_80_percent_admission_are_exactly_bounded() {
        let quarter =
            CbsReservation::new(250_000, 1_000_000, 1_000_000).unwrap_or_else(|_| unreachable!());
        assert_eq!(quarter.utilization_ppm(), Ok(250_000));
        assert_eq!(
            CbsReservation::new(2, 1, 3),
            Err(AdmissionError::InvalidOrder)
        );
        let mut admission = AdmissionControl::production_default();
        assert_eq!(admission.reserve(quarter), Ok(250_000));
        assert_eq!(admission.reserve(quarter), Ok(250_000));
        assert_eq!(admission.reserve(quarter), Ok(250_000));
        assert_eq!(
            admission.reserve(quarter),
            Err(AdmissionError::Overcommitted)
        );
        assert_eq!(admission.admitted_ppm(), 750_000);
        assert_eq!(admission.release_ppm(250_000), Ok(()));
        assert_eq!(admission.admitted_ppm(), 500_000);
    }

    #[test]
    fn utilization_rounds_up_so_admission_never_undercharges() {
        let reservation = CbsReservation::new(1, 3, 3).unwrap_or_else(|_| unreachable!());
        assert_eq!(reservation.utilization_ppm(), Ok(333_334));
    }
}
