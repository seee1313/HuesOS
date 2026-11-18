//! Generation-safe CPU0-affine deferred work queue and IRQ lifecycle
//! state for `uacpi-runtime` (AP-12). Zero `unsafe` in this module.

use spin::Mutex;

const MAX_WORK_ITEMS: usize = 64;
const MAX_IRQ_HANDLERS: usize = 8;

/// Kind of deferred uACPI work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkKind {
    /// GPE execution (CPU0-affine).
    Gpe,
    /// AML Notify() handler.
    Notification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkItem {
    generation: u64,
    kind: WorkKind,
    id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IrqSlot {
    gsi: u32,
    generation: u64,
    in_flight: bool,
}

struct WorkState {
    generation: u64,
    queue: [Option<WorkItem>; MAX_WORK_ITEMS],
    head: usize,
    len: usize,
    irqs: [Option<IrqSlot>; MAX_IRQ_HANDLERS],
}

impl WorkState {
    const fn new() -> Self {
        Self {
            generation: 1,
            queue: [None; MAX_WORK_ITEMS],
            head: 0,
            len: 0,
            irqs: [None; MAX_IRQ_HANDLERS],
        }
    }
}

static WORK_STATE: Mutex<WorkState> = Mutex::new(WorkState::new());

/// Advance generation, revoking all installed IRQ handlers and discarding
/// any queued work from previous generations.
pub fn reset_generation(new_generation: u64) {
    let mut state = WORK_STATE.lock();
    state.generation = new_generation.max(1);
    state.head = 0;
    state.len = 0;
    state.queue = [None; MAX_WORK_ITEMS];
    state.irqs = [None; MAX_IRQ_HANDLERS];
}

/// Install an IRQ handler for `gsi` in the current generation.
/// Rejects duplicates.
#[allow(clippy::result_unit_err)]
pub fn install_irq(gsi: u32) -> Result<(), ()> {
    let mut state = WORK_STATE.lock();
    let gen = state.generation;
    if state
        .irqs
        .iter()
        .flatten()
        .any(|slot| slot.gsi == gsi && slot.generation == gen)
    {
        return Err(());
    }
    for slot in &mut state.irqs {
        if slot.is_none() {
            *slot = Some(IrqSlot {
                gsi,
                generation: gen,
                in_flight: false,
            });
            return Ok(());
        }
    }
    Err(())
}

/// Remove an IRQ handler for `gsi` in the current generation.
#[allow(clippy::result_unit_err)]
pub fn uninstall_irq(gsi: u32) -> Result<(), ()> {
    let mut state = WORK_STATE.lock();
    let gen = state.generation;
    for slot in &mut state.irqs {
        if let Some(entry) = slot {
            if entry.gsi == gsi && entry.generation == gen {
                *slot = None;
                return Ok(());
            }
        }
    }
    Err(())
}

/// Enqueue a bounded CPU0-affine work item. Returns `Err(())` on overflow.
#[allow(clippy::result_unit_err)]
pub fn schedule_work(kind: WorkKind, id: u64) -> Result<(), ()> {
    let mut state = WORK_STATE.lock();
    if state.len >= MAX_WORK_ITEMS {
        return Err(());
    }
    let tail = (state.head + state.len) % MAX_WORK_ITEMS;
    state.queue[tail] = Some(WorkItem {
        generation: state.generation,
        kind,
        id,
    });
    state.len += 1;
    Ok(())
}

/// Drain interrupt callbacks before queued work, respecting a bounded
/// iteration/tick deadline.
pub fn wait_for_work_completion(max_steps: usize) -> bool {
    let mut steps = 0usize;
    loop {
        if steps >= max_steps {
            return false;
        }
        steps += 1;
        let mut state = WORK_STATE.lock();
        if state.irqs.iter().flatten().any(|slot| slot.in_flight) {
            continue;
        }
        if state.len == 0 {
            return true;
        }
        let head = state.head;
        let item = state.queue[head].take();
        state.head = (head + 1) % MAX_WORK_ITEMS;
        state.len -= 1;
        if let Some(work) = item {
            let _ = (work.generation, work.kind, work.id);
        }
    }
}
