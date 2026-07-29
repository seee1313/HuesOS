//! Process/thread/VMAR launch syscalls plus yield/exit.

use huesos_abi::{
    ErrorCode, HandleValue, ProcessBindExitPortArgs, ProcessCreateInJobArgs, VmarCreateChildArgs,
    VmarMapArgs, VmarOpArgs, BOOTSTRAP_HANDLE,
};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{
    callbacks::{
        EXIT_FN, PROCESS_CREATE_FN, PROCESS_CREATE_IN_JOB_FN, THREAD_START_FN, VMAR_MAP_FN,
        VMAR_PROTECT_FN, VMAR_UNMAP_FN, YIELD_FN,
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
    match caller.handles.add_pair_with_commit(
        Handle::new(process_koid, Rights::DEFAULT),
        Handle::new(root_vmar_koid, Rights::DEFAULT | Rights::SET_PROPERTY),
        |process_handle, root_vmar_handle| {
            user_memory::write_value(out_process, &process_handle)?;
            user_memory::write_value(out_root_vmar, &root_vmar_handle)
        },
    ) {
        Ok(_) => Ok(0),
        Err(error) => {
            huesos_object::unregister_object(process_koid);
            huesos_object::unregister_object(root_vmar_koid);
            Err(error)
        }
    }
}

fn process_from_handle(
    process_handle: HandleValue,
    rights: Rights,
) -> Result<alloc::sync::Arc<dyn huesos_object::KernelObject>, ErrorCode> {
    let caller = current_proc()?;
    let process_h = caller
        .handles
        .get(process_handle)
        .ok_or(ErrorCode::BadHandle)?;
    if !process_h.has_rights(rights) {
        return Err(ErrorCode::AccessDenied);
    }
    huesos_object::lookup_object(process_h.koid).ok_or(ErrorCode::BadHandle)
}

fn validate_affinity(mask: u64, home_cpu: usize) -> Result<(), ErrorCode> {
    const MAX_CPUS: usize = 64;
    if mask == 0 || home_cpu >= MAX_CPUS || (mask & (1u64 << home_cpu)) == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let online = (*crate::callbacks::CPU_MASK_FN.lock()).ok_or(ErrorCode::NotSupported)?();
    if mask & !online != 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    Ok(())
}

pub(crate) fn sys_process_create_in_job(args_ptr: *const ProcessCreateInJobArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    if args.name_len as usize > MAX_PROCESS_NAME_LEN || args.out_process == args.out_root_vmar {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_write(args.out_process)?;
    user_memory::validate_write(args.out_root_vmar)?;
    let proc = current_proc()?;
    let job_handle = proc.handles.get(args.job).ok_or(ErrorCode::BadHandle)?;
    if !job_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let job_obj = huesos_object::lookup_object(job_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let job = job_obj
        .downcast_arc::<huesos_object::Job>()
        .map_err(|_| ErrorCode::WrongType)?;

    let name_storage;
    let name = if args.name_len == 0 {
        "process"
    } else {
        name_storage = user_memory::copy_from_user(args.name, args.name_len as usize)?;
        core::str::from_utf8(&name_storage).map_err(|_| ErrorCode::InvalidArgs)?
    };
    let create = (*PROCESS_CREATE_IN_JOB_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let (process, root_vmar) = create(name, job)?;
    let process_koid = process.koid();
    let root_vmar_koid = root_vmar.koid();

    match proc.handles.add_pair_with_commit(
        Handle::new(process_koid, Rights::DEFAULT),
        Handle::new(root_vmar_koid, Rights::DEFAULT | Rights::SET_PROPERTY),
        |process_handle, root_vmar_handle| {
            user_memory::write_value(args.out_process, &process_handle)?;
            user_memory::write_value(args.out_root_vmar, &root_vmar_handle)
        },
    ) {
        Ok(_) => Ok(0),
        Err(error) => {
            huesos_object::unregister_object(process_koid);
            huesos_object::unregister_object(root_vmar_koid);
            Err(error)
        }
    }
}

pub(crate) fn sys_process_set_affinity(process_handle: HandleValue, cpu: usize) -> SyscallResult {
    let mask = 1u64.checked_shl(cpu as u32).ok_or(ErrorCode::InvalidArgs)?;
    sys_process_set_affinity_mask(process_handle, mask, cpu)
}

pub(crate) fn sys_process_set_affinity_mask(
    process_handle: HandleValue,
    mask: u64,
    home_cpu: usize,
) -> SyscallResult {
    validate_affinity(mask, home_cpu)?;
    let process_obj = process_from_handle(process_handle, Rights::WRITE)?;
    let process = process_obj
        .downcast_ref::<huesos_object::Process>()
        .ok_or(ErrorCode::WrongType)?;
    if process.set_affinity_mask(mask, home_cpu) {
        Ok(0)
    } else {
        Err(ErrorCode::Busy)
    }
}

pub(crate) fn sys_process_set_scheduler_flags(
    process_handle: HandleValue,
    flags: u32,
) -> SyscallResult {
    const ALLOWED: u32 = huesos_abi::scheduler_flags::STEAL_OPT_IN;
    let process_obj = process_from_handle(process_handle, Rights::WRITE)?;
    let process = process_obj
        .downcast_ref::<huesos_object::Process>()
        .ok_or(ErrorCode::WrongType)?;
    if process.set_scheduler_flags(flags, ALLOWED) {
        Ok(0)
    } else {
        Err(ErrorCode::InvalidArgs)
    }
}

pub(crate) fn sys_process_get_affinity(
    process_handle: HandleValue,
    out_mask: *mut u64,
    out_home_cpu: *mut u64,
) -> SyscallResult {
    user_memory::validate_write(out_mask)?;
    user_memory::validate_write(out_home_cpu)?;
    let process_obj = process_from_handle(process_handle, Rights::READ)?;
    let process = process_obj
        .downcast_ref::<huesos_object::Process>()
        .ok_or(ErrorCode::WrongType)?;
    let mask = process.affinity_mask();
    let home = process.home_cpu() as u64;
    user_memory::write_value(out_mask, &mask)?;
    user_memory::write_value(out_home_cpu, &home)?;
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
    caller
        .handles
        .add_with_commit(Handle::new(thread_koid, Rights::DEFAULT), |thread_handle| {
            user_memory::write_value(out_thread, &thread_handle)
        })
        .map(|_| 0)
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

    if !thread.begin_start() {
        return Err(ErrorCode::Busy);
    }
    let start_guard = DeferGuard::new(|| thread.cancel_start());

    let child_process =
        huesos_object::lookup_process(thread.process()).ok_or(ErrorCode::BadHandle)?;
    if !child_process.reserve_initial_thread_start() {
        return Err(ErrorCode::Busy);
    }
    let process_start_guard = DeferGuard::new(|| child_process.cancel_initial_thread_start());

    let start = (*THREAD_START_FN.lock()).ok_or(ErrorCode::NotSupported)?;

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
            huesos_object::unregister_object(parent_koid);
            huesos_object::unregister_object(child_koid);
            ErrorCode::Busy
        })?;

    let parent_handle = core::cell::Cell::new(None::<HandleValue>);
    let committed = core::cell::Cell::new(false);
    let rollback = DeferGuard::new(|| {
        let _ = child_process.handles.remove(BOOTSTRAP_HANDLE);
        if !committed.get() {
            if let Some(handle) = parent_handle.get() {
                let _ = caller.handles.remove(handle);
            }
            huesos_object::unregister_object(parent_koid);
            huesos_object::unregister_object(child_koid);
            child_process.cancel_initial_thread_start();
            thread.cancel_start();
        }
    });

    // Copy the parent endpoint out before publishing the child task as runnable.
    // The handle-table insertion and copy-out are serialized inside
    // add_with_commit so sibling threads cannot observe the parent endpoint
    // before this syscall's output is valid.
    let (handle_value, _) = caller
        .handles
        .add_with_commit(Handle::new(parent_koid, Rights::DEFAULT), |handle| {
            user_memory::write_value(out_parent_bootstrap, &handle)
        })?;
    parent_handle.set(Some(handle_value));

    let task_id = start(thread, entry, stack)?;
    thread.finish_start(task_id);
    child_process.finish_initial_thread_start();
    committed.set(true);
    rollback.commit();
    process_start_guard.commit();
    start_guard.commit();
    Ok(task_id as i64)
}

const VMAR_PAGE_SIZE: u64 = 4096;

pub(crate) fn sys_process_bind_exit_port(
    args_ptr: *const ProcessBindExitPortArgs,
) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    if args.flags != 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let process_handle = proc.handles.get(args.process).ok_or(ErrorCode::BadHandle)?;
    if !process_handle.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let port_handle = proc.handles.get(args.port).ok_or(ErrorCode::BadHandle)?;
    if !port_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }

    let process_obj =
        huesos_object::lookup_object(process_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let process = process_obj
        .downcast_ref::<huesos_object::Process>()
        .ok_or(ErrorCode::WrongType)?;
    let port_obj = huesos_object::lookup_object(port_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let port = port_obj
        .downcast_arc::<huesos_object::Port>()
        .map_err(|_| ErrorCode::WrongType)?;
    process
        .bind_exit_port(port, args.key)
        .map_err(|error| match error {
            huesos_object::ProcessExitPortError::Full => ErrorCode::Busy,
            huesos_object::ProcessExitPortError::OutOfMemory => ErrorCode::NoMemory,
        })?;
    Ok(0)
}

pub(crate) fn sys_vmar_create_child(args_ptr: *const VmarCreateChildArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    if args.flags != 0
        || args.len == 0
        || !args.addr.is_multiple_of(VMAR_PAGE_SIZE)
        || !args.len.is_multiple_of(VMAR_PAGE_SIZE)
    {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_write(args.out_child)?;

    let proc = current_proc()?;
    let parent_handle = proc.handles.get(args.parent).ok_or(ErrorCode::BadHandle)?;
    if !parent_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let parent_obj =
        huesos_object::lookup_object(parent_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let parent = parent_obj
        .downcast_ref::<huesos_object::Vmar>()
        .ok_or(ErrorCode::WrongType)?;
    if parent.process() != proc.koid() {
        return Err(ErrorCode::AccessDenied);
    }

    let _parent_ref =
        huesos_object::acquire_kernel_ref(parent.koid()).ok_or(ErrorCode::BadHandle)?;
    let child = huesos_object::Vmar::new_child(parent, args.addr, args.len);
    let child_record = huesos_object::VmarChild {
        koid: child.koid(),
        base: args.addr,
        size: args.len,
    };
    parent
        .record_child(child_record)
        .map_err(|error| match error {
            huesos_object::VmarError::InvalidRange => ErrorCode::InvalidArgs,
            huesos_object::VmarError::Overlap => ErrorCode::Busy,
        })?;

    let child_koid = child.koid();
    huesos_object::register_object(child);
    match proc
        .handles
        .add_with_commit(Handle::new(child_koid, parent_handle.rights), |handle| {
            user_memory::write_value(args.out_child, &handle)
        }) {
        Ok((handle, _)) => Ok(handle as i64),
        Err(error) => {
            huesos_object::unregister_object(child_koid);
            Err(error)
        }
    }
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
