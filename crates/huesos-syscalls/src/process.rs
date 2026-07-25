//! Process/thread/VMAR launch syscalls plus yield/exit.

use huesos_abi::{ErrorCode, HandleValue, VmarMapArgs, VmarOpArgs, BOOTSTRAP_HANDLE};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{
    callbacks::{
        EXIT_FN, PROCESS_CREATE_FN, THREAD_START_FN, VMAR_MAP_FN, VMAR_PROTECT_FN, VMAR_UNMAP_FN,
        YIELD_FN,
    },
    user_memory,
    util::{current_proc, DeferGuard},
    SyscallResult,
};

pub(crate) fn sys_yield() -> SyscallResult {
    // Never hold a callback mutex across a context switch.
    let yield_fn = *YIELD_FN.lock();
    if let Some(f) = yield_fn {
        f();
    }
    Ok(0)
}

const MAX_PROCESS_NAME_LEN: usize = 64;

pub(crate) fn sys_process_create(
    name_ptr: *const u8,
    name_len: usize,
    out_process: *mut HandleValue,
    out_root_vmar: *mut HandleValue,
) -> SyscallResult {
    if name_len > MAX_PROCESS_NAME_LEN || out_process == out_root_vmar {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_write(out_process)?;
    user_memory::validate_write(out_root_vmar)?;

    let name_storage;
    let name = if name_len == 0 {
        "process"
    } else {
        name_storage = user_memory::copy_from_user(name_ptr, name_len)?;
        core::str::from_utf8(&name_storage).map_err(|_| ErrorCode::InvalidArgs)?
    };

    let create = (*PROCESS_CREATE_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let (process, root_vmar) = create(name)?;
    let process_koid = process.koid();
    let root_vmar_koid = root_vmar.koid();

    let caller = current_proc()?;
    let process_handle = caller
        .handles
        .add(Handle::new(process_koid, Rights::DEFAULT));
    let root_vmar_handle = caller.handles.add(Handle::new(
        root_vmar_koid,
        Rights::DEFAULT | Rights::SET_PROPERTY,
    ));

    // Rollback: if either write_value fails after the objects are registered
    // and handles inserted, undo everything to maintain the all-or-nothing
    // syscall contract.
    let rollback = DeferGuard::new(|| {
        let _ = caller.handles.remove(process_handle);
        let _ = caller.handles.remove(root_vmar_handle);
        huesos_object::unregister_object(process_koid);
        huesos_object::unregister_object(root_vmar_koid);
    });

    user_memory::write_value(out_process, &process_handle)?;
    user_memory::write_value(out_root_vmar, &root_vmar_handle)?;
    rollback.commit();
    Ok(0)
}

pub(crate) fn sys_thread_create(
    process_handle: HandleValue,
    name_ptr: *const u8,
    name_len: usize,
    out_thread: *mut HandleValue,
) -> SyscallResult {
    if name_len > MAX_PROCESS_NAME_LEN {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_write(out_thread)?;

    let name_storage;
    let name = if name_len == 0 {
        "thread"
    } else {
        name_storage = user_memory::copy_from_user(name_ptr, name_len)?;
        core::str::from_utf8(&name_storage).map_err(|_| ErrorCode::InvalidArgs)?
    };

    let caller = current_proc()?;
    let process_h = caller
        .handles
        .get(process_handle)
        .ok_or(ErrorCode::BadHandle)?;
    if !process_h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }

    let process_obj = huesos_object::lookup_object(process_h.koid).ok_or(ErrorCode::BadHandle)?;
    let process = process_obj
        .downcast_ref::<huesos_object::Process>()
        .ok_or(ErrorCode::WrongType)?;

    let thread = huesos_object::Thread::new_for_process(name, process.koid());
    let thread_koid = thread.koid();
    huesos_object::register_object(thread);
    let thread_handle = caller
        .handles
        .add(Handle::new(thread_koid, Rights::DEFAULT));

    // Rollback: if write_value fails after the thread is registered and the
    // handle inserted, undo both to prevent an orphaned thread object.
    let rollback = DeferGuard::new(|| {
        let _ = caller.handles.remove(thread_handle);
        huesos_object::unregister_object(thread_koid);
    });

    user_memory::write_value(out_thread, &thread_handle)?;
    rollback.commit();
    Ok(0)
}

pub(crate) fn sys_thread_start(
    thread_handle: HandleValue,
    entry: u64,
    stack: u64,
    out_parent_bootstrap: *mut HandleValue,
) -> SyscallResult {
    let userspace = huesos_abi::USER_ASPACE_BASE..huesos_abi::USER_ASPACE_END;
    if !userspace.contains(&entry) || !userspace.contains(&stack) {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_write(out_parent_bootstrap)?;

    let caller = current_proc()?;
    let thread_h = caller
        .handles
        .get(thread_handle)
        .ok_or(ErrorCode::BadHandle)?;
    if !thread_h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }

    let thread_obj = huesos_object::lookup_object(thread_h.koid).ok_or(ErrorCode::BadHandle)?;
    let thread = thread_obj
        .downcast_ref::<huesos_object::Thread>()
        .ok_or(ErrorCode::WrongType)?;

    if thread.task_id.lock().is_some() {
        return Err(ErrorCode::Busy);
    }

    let child_process =
        huesos_object::lookup_process(thread.process()).ok_or(ErrorCode::BadHandle)?;

    let (parent_bootstrap, child_bootstrap) =
        huesos_object::Channel::pair().map_err(|_| ErrorCode::NoMemory)?;
    let parent_koid = parent_bootstrap.koid();
    let child_koid = child_bootstrap.koid();
    huesos_object::register_object(parent_bootstrap);
    huesos_object::register_object(child_bootstrap);

    child_process
        .handles
        .insert_at(BOOTSTRAP_HANDLE, Handle::new(child_koid, Rights::DEFAULT))
        .map_err(|_| {
            // Rollback channel registration before returning.
            huesos_object::unregister_object(parent_koid);
            huesos_object::unregister_object(child_koid);
            ErrorCode::Busy
        })?;

    let start = (*THREAD_START_FN.lock()).ok_or(ErrorCode::NotSupported)?;

    let parent_handle = caller
        .handles
        .add(Handle::new(parent_koid, Rights::DEFAULT));

    // From this point, the rollback must handle the case where `start()`
    // fails (thread not yet running) or `write_value` fails (thread is
    // running but parent handle delivery failed).
    let rollback = DeferGuard::new(|| {
        // Remove the child bootstrap handle from the child process. If the
        // thread was started, this is a best-effort cleanup — the running
        // child may have already observed the handle.
        let _ = child_process.handles.remove(BOOTSTRAP_HANDLE);
        let _ = caller.handles.remove(parent_handle);
        huesos_object::unregister_object(parent_koid);
        huesos_object::unregister_object(child_koid);
    });

    let task_id = start(thread, entry, stack)?;
    // Thread is now running. If write_value fails below, we still run the
    // rollback which unregisters the parent bootstrap channel and removes
    // the parent handle. The child bootstrap is also cleaned up, but the
    // running thread may have already captured its copy. The channel pair
    // stays alive through the remaining Arc references (if any).
    user_memory::write_value(out_parent_bootstrap, &parent_handle)?;
    rollback.commit();
    Ok(task_id as i64)
}

pub(crate) fn sys_vmar_map(args_ptr: *const VmarMapArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;

    let proc = current_proc()?;
    let vmar_handle = proc.handles.get(args.vmar).ok_or(ErrorCode::BadHandle)?;
    if !vmar_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let vmo_handle = proc.handles.get(args.vmo).ok_or(ErrorCode::BadHandle)?;
    let required_vmo_rights =
        huesos_object::Rights::from_bits_retain(huesos_abi::rights::mapping_required(args.flags));
    if !vmo_handle.has_rights(required_vmo_rights) {
        return Err(ErrorCode::AccessDenied);
    }

    let vmar_obj = huesos_object::lookup_object(vmar_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let vmar = vmar_obj
        .downcast_ref::<huesos_object::Vmar>()
        .ok_or(ErrorCode::WrongType)?;

    let vmo_obj = huesos_object::lookup_object(vmo_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = vmo_obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;

    let map = (*VMAR_MAP_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let mapped = map(vmar, vmo, args)?;
    Ok(mapped as i64)
}

pub(crate) fn sys_vmar_unmap(args_ptr: *const VmarOpArgs) -> SyscallResult {
    sys_vmar_op(args_ptr, false, &VMAR_UNMAP_FN)
}

pub(crate) fn sys_vmar_protect(args_ptr: *const VmarOpArgs) -> SyscallResult {
    sys_vmar_op(args_ptr, true, &VMAR_PROTECT_FN)
}

fn sys_vmar_op(
    args_ptr: *const VmarOpArgs,
    protect: bool,
    callback: &spin::Mutex<Option<crate::callbacks::VmarOpFn>>,
) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    let proc = current_proc()?;
    let vmar_handle = proc.handles.get(args.vmar).ok_or(ErrorCode::BadHandle)?;
    let required = if protect {
        Rights::SET_PROPERTY
    } else {
        Rights::WRITE
    };
    if !vmar_handle.has_rights(required) {
        return Err(ErrorCode::AccessDenied);
    }
    let object = huesos_object::lookup_object(vmar_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let vmar = object
        .downcast_ref::<huesos_object::Vmar>()
        .ok_or(ErrorCode::WrongType)?;
    if vmar.process() != proc.koid() {
        return Err(ErrorCode::AccessDenied);
    }
    let callback = (*callback.lock()).ok_or(ErrorCode::NotSupported)?;
    callback(vmar, args).map(|value| value as i64)
}

pub(crate) fn sys_process_exit(code: i64) -> SyscallResult {
    let exit_fn = *EXIT_FN.lock();
    if let Some(f) = exit_fn {
        f(code);
    }
    loop {
        huesos_arch::hlt();
    }
}

pub(crate) fn sys_process_wait(handle: HandleValue, out_code: *mut i64) -> SyscallResult {
    // Validate before parking so a bad pointer cannot consume a wakeup and
    // fault only after the target has exited.
    user_memory::validate_write(out_code)?;
    let target = process_for_wait(handle)?;
    let registered = target.add_exit_waiter();
    loop {
        // Enqueue BEFORE checking so we are visible to exit wakers; this
        // closes the lost-wakeup race where the target exits between the
        // condition check and the internal enqueue.
        let prepared = match huesos_object::wait::WaitQueue::prepare(&target.exit_waiters) {
            Some(p) => p,
            None => {
                // Early boot: scheduler not yet ready. Use hues-async
                // block_on + yield_now to poll the exit condition without
                // allocation (hues-async is allocation-free by design and
                // is being integrated as a ring-0 kernel primitive).
                let code = hues_async::block_on(
                    async {
                        loop {
                            hues_async::yield_now().await;
                            if let Some(code) = target.exit_code() {
                                return code;
                            }
                        }
                    },
                    || {
                        huesos_arch::hlt();
                    },
                );
                if registered {
                    target.remove_exit_waiter();
                }
                user_memory::write_value(out_code, &code)?;
                return Ok(0);
            }
        };
        // Re-check after enqueue: the target may have exited between the
        // first check and prepare().
        if let Some(code) = target.exit_code() {
            prepared.cancel();
            if registered {
                target.remove_exit_waiter();
            }
            user_memory::write_value(out_code, &code)?;
            return Ok(0);
        }
        prepared.park();
    }
}

pub(crate) fn sys_process_get_exit_code(handle: HandleValue, out_code: *mut i64) -> SyscallResult {
    user_memory::validate_write(out_code)?;
    let target = process_for_wait(handle)?;
    let code = target.exit_code().ok_or(ErrorCode::ShouldWait)?;
    user_memory::write_value(out_code, &code)?;
    Ok(0)
}

fn process_for_wait(
    handle: HandleValue,
) -> Result<alloc::sync::Arc<huesos_object::Process>, ErrorCode> {
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    huesos_object::lookup_process(h.koid).ok_or(ErrorCode::WrongType)
}
