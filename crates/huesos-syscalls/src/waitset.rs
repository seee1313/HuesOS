//! WaitSetWait syscall: multiplexed multi-object wait.
//!
//! Uses the host-tested [`huesos_waitset`] policy crate for signal-set
//! algebra, Any/All completion, and cancellation precedence.

use alloc::sync::Arc;
use alloc::vec::Vec;
use huesos_abi::{ErrorCode, WaitSetWaitArgs};
use huesos_object::{KernelObjectExt, Rights};
use huesos_waitset::{Signals, WaitMode, WaitOutcome, WaitSet};

use crate::{user_memory, util::current_proc, SyscallResult};

/// Maximum number of items in a single WaitSetWait call.
const MAX_WAIT_ITEMS: usize = 16;

pub(crate) fn sys_waitset_wait(args_ptr: *const WaitSetWaitArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    let item_count = args.item_count as usize;

    if item_count == 0 || item_count > MAX_WAIT_ITEMS {
        return Err(ErrorCode::InvalidArgs);
    }

    user_memory::validate_write_array(args.out_results, item_count)?;
    user_memory::validate_write(args.out_count)?;

    let items = user_memory::read_array(args.items, item_count)?;

    let mode = match args.mode {
        0 => WaitMode::Any,
        1 => WaitMode::All,
        _ => return Err(ErrorCode::InvalidArgs),
    };

    let proc = current_proc()?;
    let mut waitset: WaitSet<MAX_WAIT_ITEMS> = WaitSet::new();
    let mut watched: Vec<Arc<dyn huesos_object::KernelObject>> = Vec::new();
    watched
        .try_reserve_exact(item_count)
        .map_err(|_| ErrorCode::NoMemory)?;

    for item in &items {
        let h = proc.handles.get(item.handle).ok_or(ErrorCode::BadHandle)?;
        if !h.has_rights(Rights::READ) {
            return Err(ErrorCode::AccessDenied);
        }
        let object = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
        let awaited = Signals::from_bits(item.awaited_signals);
        if !waitset.add(item.key, awaited) {
            return Err(ErrorCode::InvalidArgs);
        }
        watched.push(object);
    }

    // Compute an absolute deadline once, up front, in scheduler-tick
    // units. `timeout_ticks == 0` means "wait forever" (deadline =
    // None), matching every other blocking wait primitive.
    let deadline: Option<u64> = if args.timeout_ticks == 0 {
        None
    } else {
        let now = current_tick();
        Some(now.saturating_add(args.timeout_ticks))
    };

    loop {
        update_waitset_signals(&mut waitset, &items, &watched, &proc)?;

        match waitset.poll_at(mode, current_tick(), deadline) {
            WaitOutcome::Signaled | WaitOutcome::Canceled => {
                return write_results(&waitset, &items, &args);
            }
            WaitOutcome::TimedOut => {
                user_memory::write_value(args.out_count, &0u32)?;
                return Err(ErrorCode::TimedOut);
            }
            WaitOutcome::Pending => {}
        }

        let Some(task) = huesos_object::wait::current_task() else {
            return Err(ErrorCode::Internal);
        };
        enqueue_waiters(&watched, task);
        update_waitset_signals(&mut waitset, &items, &watched, &proc)?;
        match waitset.poll_at(mode, current_tick(), deadline) {
            WaitOutcome::Signaled | WaitOutcome::Canceled => {
                remove_waiters(&watched, task);
                return write_results(&waitset, &items, &args);
            }
            WaitOutcome::TimedOut => {
                remove_waiters(&watched, task);
                user_memory::write_value(args.out_count, &0u32)?;
                return Err(ErrorCode::TimedOut);
            }
            WaitOutcome::Pending => {}
        }
        let result = huesos_object::wait::park_current_until(deadline);
        remove_waiters(&watched, task);
        if matches!(result, huesos_object::wait::ParkResult::TimedOut) {
            user_memory::write_value(args.out_count, &0u32)?;
            return Err(ErrorCode::TimedOut);
        }
    }
}

/// Snapshot the scheduler's monotonic tick counter for deadline
/// arithmetic. Falls back to `0` before the kernel has installed a
/// clock callback (very early boot); in that window `timeout_ticks`
/// is effectively meaningless because no time has elapsed either
/// way. Every real syscall path runs after
/// `huesos_syscalls::set_clock_fn`.
fn current_tick() -> u64 {
    // Drop the lock before calling the callback (see
    // `huesos_object::wait::park_current` for why holding a callback
    // mutex guard across the call is unsafe in general, even though this
    // particular callback is short and non-blocking).
    let clock_fn = *crate::callbacks::CLOCK_FN.lock();
    match clock_fn {
        Some(f) => f(),
        None => 0,
    }
}

fn update_waitset_signals(
    waitset: &mut WaitSet<MAX_WAIT_ITEMS>,
    items: &[huesos_abi::WaitSetItem],
    watched: &[Arc<dyn huesos_object::KernelObject>],
    proc: &huesos_object::Process,
) -> SyscallResult {
    for (item, obj) in items.iter().zip(watched.iter()) {
        let mut active = Signals::from_bits(0);
        if proc.handles.get(item.handle).is_none() {
            active = active.union(Signals::CANCELED);
        }

        if let Some(ch) = obj.downcast_ref::<huesos_object::Channel>() {
            if ch.peek().is_ok_and(|opt| opt.is_some()) {
                active = active.union(Signals::READABLE);
            }
            if ch.peer_closed() {
                active = active.union(Signals::PEER_CLOSED);
            }
        }

        if let Some(port) = obj.downcast_ref::<huesos_object::Port>() {
            // Non-destructive readiness check. The historical
            // `port.read().is_some()` idiom silently dequeued the
            // packet during the ready probe — every IRQ delivered
            // while a driver was parked in wait_any was consumed
            // by the kernel and never surfaced to the driver, which
            // is why keystrokes were vanishing after PR #126.
            //
            // Report the readiness under `READABLE` so callers can
            // await on the same signal name they use for Channels;
            // the previous `SIGNALED` bit never intersected with
            // driver `awaited = READABLE` masks and so `wait_any`
            // never fired for ports at all — a second, latent bug
            // that the drain-on-probe bug happened to mask.
            if port.has_pending() {
                active = active.union(Signals::READABLE);
            }
        }

        if let Some(process) = obj.downcast_ref::<huesos_object::Process>() {
            if process.exit_code().is_some() {
                active = active.union(Signals::SIGNALED);
            }
        }

        waitset.set_active(item.key, active);
    }
    Ok(0)
}

fn enqueue_waiters(objects: &[Arc<dyn huesos_object::KernelObject>], task: huesos_object::TaskId) {
    for obj in objects {
        if let Some(ch) = obj.downcast_ref::<huesos_object::Channel>() {
            ch.reader_queue().enqueue(task);
        } else if let Some(port) = obj.downcast_ref::<huesos_object::Port>() {
            port.wait_queue().enqueue(task);
        } else if let Some(process) = obj.downcast_ref::<huesos_object::Process>() {
            process.exit_waiters.enqueue(task);
        }
    }
}

fn remove_waiters(objects: &[Arc<dyn huesos_object::KernelObject>], task: huesos_object::TaskId) {
    for obj in objects {
        if let Some(ch) = obj.downcast_ref::<huesos_object::Channel>() {
            ch.reader_queue().remove(task);
        } else if let Some(port) = obj.downcast_ref::<huesos_object::Port>() {
            port.wait_queue().remove(task);
        } else if let Some(process) = obj.downcast_ref::<huesos_object::Process>() {
            process.exit_waiters.remove(task);
        }
    }
}

fn write_results(
    waitset: &WaitSet<MAX_WAIT_ITEMS>,
    items: &[huesos_abi::WaitSetItem],
    args: &WaitSetWaitArgs,
) -> SyscallResult {
    let mut results: Vec<huesos_abi::WaitSetResult> = Vec::new();
    results
        .try_reserve_exact(items.len())
        .map_err(|_| ErrorCode::NoMemory)?;

    for item in items {
        if let Some(wait_item) = waitset.get(item.key) {
            if wait_item.is_satisfied() {
                results.push(huesos_abi::WaitSetResult {
                    key: item.key,
                    active_signals: wait_item.satisfied_signals().bits(),
                });
            }
        }
    }

    let count = results.len() as u32;
    user_memory::write_array(args.out_results, &results)?;
    user_memory::write_value(args.out_count, &count)?;
    Ok(0)
}
