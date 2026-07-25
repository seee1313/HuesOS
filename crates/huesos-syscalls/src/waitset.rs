//! WaitSetWait syscall: multiplexed multi-object wait.
//!
//! Uses the host-tested [`huesos_waitset`] policy crate for signal-set
//! algebra, Any/All completion, and cancellation precedence.

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

    for item in &items {
        let h = proc.handles.get(item.handle).ok_or(ErrorCode::BadHandle)?;
        if !h.has_rights(Rights::READ) {
            return Err(ErrorCode::AccessDenied);
        }
        let awaited = Signals::from_bits(item.awaited_signals);
        if !waitset.add(item.key, awaited) {
            return Err(ErrorCode::InvalidArgs);
        }
    }

    update_waitset_signals(&mut waitset, &items, &proc)?;

    let outcome = waitset.poll(mode);
    match outcome {
        WaitOutcome::Signaled | WaitOutcome::Canceled => {
            return write_results(&waitset, &items, &args);
        }
        WaitOutcome::TimedOut if args.timeout_ticks == 0 => {}
        WaitOutcome::TimedOut => {
            user_memory::write_value(args.out_count, &0u32)?;
            return Err(ErrorCode::TimedOut);
        }
        WaitOutcome::Pending => {}
    }

    loop {
        let yield_fn = *crate::callbacks::YIELD_FN.lock();
        if let Some(y) = yield_fn {
            y();
        }

        update_waitset_signals(&mut waitset, &items, &proc)?;

        let outcome = waitset.poll(mode);
        match outcome {
            WaitOutcome::Signaled | WaitOutcome::Canceled => {
                return write_results(&waitset, &items, &args);
            }
            WaitOutcome::TimedOut => {
                user_memory::write_value(args.out_count, &0u32)?;
                return Err(ErrorCode::TimedOut);
            }
            WaitOutcome::Pending => continue,
        }
    }
}

fn update_waitset_signals(
    waitset: &mut WaitSet<MAX_WAIT_ITEMS>,
    items: &[huesos_abi::WaitSetItem],
    proc: &huesos_object::Process,
) -> SyscallResult {
    for item in items {
        let h = proc.handles.get(item.handle).ok_or(ErrorCode::BadHandle)?;
        let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
        let mut active = Signals::from_bits(0);

        if let Some(ch) = obj.downcast_ref::<huesos_object::Channel>() {
            if ch.peek().is_ok_and(|opt| opt.is_some()) {
                active = active.union(Signals::READABLE);
            }
            if ch.peer_closed() {
                active = active.union(Signals::PEER_CLOSED);
            }
        }

        if let Some(port) = obj.downcast_ref::<huesos_object::Port>() {
            if port.read().is_some() {
                active = active.union(Signals::SIGNALED);
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
