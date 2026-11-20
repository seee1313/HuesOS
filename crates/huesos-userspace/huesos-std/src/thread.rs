//! Threads, sleep and parking.
//!
//! A HuesOS process starts with one thread; `thread::spawn` asks the loader's
//! runtime (`libcanvas::thread`) for a new kernel thread with its own stack and
//! its own Variant-II TLS block, and joins it by handle. The entry point is a
//! closure, not a function pointer, because the trampoline that reclaims the
//! closure lives in `libcanvas` where the pointer plumbing is allowed.
//!
//! # What `park` means here
//! `std` parks "the current thread" and finds its token through thread-local
//! storage. HuesOS user space has TLS — `ld-huesos.so` sets up `%fs` for every
//! thread — but no way for a library to *name* the calling thread, so a free
//! `park()` always uses the process' default parking token. A thread that wants
//! to be woken individually therefore parks through the handle it was given:
//!
//! ```ignore
//! let handle = threads::spawn(move || { /* ... */ });
//! handle.thread().unpark();          // wakes that thread's own token
//! ```
//!
//! `Builder::spawn` allocates a token per thread and exposes it as
//! [`JoinHandle::thread`], so targeted wake-ups are exact. Both forms block on
//! the futex; nothing here spins.

use alloc::string::String;

use libcanvas::thread as sys;
use libcanvas::ErrorCode;

use crate::error::{Error, Result};
use crate::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::sync::{Arc, Mutex};
use crate::time::Duration;

/// The default stack size: the loader's 64 KiB intra-process profile.
pub const DEFAULT_STACK_SIZE: usize = 0;

/// A parking token plus the futex word it waits on.
struct Parker {
    /// A wake-up that arrived while nobody was parked is remembered here, so
    /// `unpark()` followed by `park()` does not block.
    permit: AtomicBool,
    /// Bumped on every unpark; waiters park on the value they read.
    sequence: AtomicU32,
}

impl Parker {
    const fn new() -> Self {
        Self {
            permit: AtomicBool::new(false),
            sequence: AtomicU32::new(0),
        }
    }

    fn park(&self) {
        loop {
            if self.permit.swap(false, Ordering::Acquire) {
                return;
            }
            let sequence = self.sequence.load(Ordering::Acquire);
            // Re-check after reading the sequence: an unpark in between bumps
            // the sequence, so the wait below returns immediately.
            if self.permit.swap(false, Ordering::Acquire) {
                return;
            }
            let _ = libcanvas::futex::wait(&self.sequence, sequence, 0);
        }
    }

    fn park_timeout(&self, timeout: Duration) {
        if self.permit.swap(false, Ordering::Acquire) {
            return;
        }
        let sequence = self.sequence.load(Ordering::Acquire);
        let _ = libcanvas::futex::wait(&self.sequence, sequence, timeout.as_ticks_ceil());
    }

    fn unpark(&self) {
        self.permit.store(true, Ordering::Release);
        self.sequence.fetch_add(1, Ordering::Release);
        let _ = libcanvas::futex::wake_all(&self.sequence);
    }
}

impl core::fmt::Debug for Parker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Parker")
            .field("permit", &self.permit.load(Ordering::Relaxed))
            .field("sequence", &self.sequence.load(Ordering::Relaxed))
            .finish()
    }
}

/// The process' default parking token, used by the free `park` functions.
static DEFAULT_PARKER: Parker = Parker::new();

/// Identifier of a thread, unique within the process.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ThreadId(u64);

impl ThreadId {
    /// The raw number, usable as a map key or in a log line.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A handle to a thread: its id and its parking token.
#[derive(Clone, Copy, Debug)]
pub struct Thread {
    id: ThreadId,
    parker: &'static Parker,
}

impl Thread {
    /// This thread's id.
    pub const fn id(&self) -> ThreadId {
        self.id
    }

    /// The thread that is running now.
    ///
    /// Without a way to look the calling thread up, this is the process'
    /// default token; see the module documentation.
    pub fn current() -> Thread {
        Thread {
            id: ThreadId(0),
            parker: &DEFAULT_PARKER,
        }
    }

    /// Block until [`Thread::unpark`] is called on this handle.
    pub fn park(&self) {
        self.parker.park();
    }

    /// Block until unparked or `timeout` expires.
    pub fn park_timeout(&self, timeout: Duration) {
        self.parker.park_timeout(timeout);
    }

    /// Remember a wake-up for this thread (or release a parked one).
    pub fn unpark(&self) {
        self.parker.unpark();
    }
}

/// Owns a thread's stack and token, and joins it on drop.
pub struct JoinHandle<T> {
    inner: Option<sys::JoinHandle>,
    slot: Arc<Mutex<Option<T>>>,
    thread: Thread,
    /// Set when the thread could not be started at all.
    spawn_error: Option<Error>,
}

impl<T> JoinHandle<T> {
    /// The thread this handle refers to.
    pub fn thread(&self) -> &Thread {
        &self.thread
    }

    /// Block until the thread finishes and return what it produced.
    pub fn join(mut self) -> Result<T> {
        if let Some(error) = self.spawn_error {
            return Err(error);
        }
        let handle = match self.inner.take() {
            Some(handle) => handle,
            None => return Err(Error::new(crate::error::ErrorKind::Other)),
        };
        handle.join()?;
        let value = self.slot.lock().take();
        match value {
            Some(value) => Ok(value),
            None => Err(Error::new(crate::error::ErrorKind::Other)),
        }
    }
}

impl<T> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        // `libcanvas::JoinHandle::drop` joins, so detaching is just dropping.
        self.inner = None;
    }
}

/// Builder for [`spawn`], mirroring `std::thread::Builder`.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    name: Option<String>,
    stack_size: Option<usize>,
}

impl Builder {
    /// A builder with the default name and stack size.
    pub fn new() -> Self {
        Self::default()
    }

    /// Name the thread (visible in the kernel's thread list).
    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Stack size in bytes; `None` and `0` both mean the 64 KiB default.
    pub fn stack_size(mut self, size: usize) -> Self {
        self.stack_size = Some(size);
        self
    }

    /// Start the thread.
    pub fn spawn<F, T>(self, task: F) -> Result<JoinHandle<T>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let slot = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&slot);
        let parker: &'static Parker =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(Parker::new()));
        let name = self.name.unwrap_or_else(|| String::from("worker"));
        let stack_size = match self.stack_size {
            Some(size) => size,
            None => DEFAULT_STACK_SIZE,
        };
        let inner = sys::spawn_task(
            &name,
            move || {
                let value = task();
                *sink.lock() = Some(value);
                0
            },
            stack_size,
        )?;
        Ok(JoinHandle {
            thread: Thread {
                id: ThreadId(inner.thread_id()),
                parker,
            },
            inner: Some(inner),
            slot,
            spawn_error: None,
        })
    }
}

/// Start a thread with the default name and stack size.
pub fn spawn<F, T>(task: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match Builder::new().spawn(task) {
        Ok(handle) => handle,
        // `std::thread::spawn` panics; a HuesOS program gets a dead handle
        // whose `join` reports the spawn failure instead of taking the whole
        // process down over a resource-limit race.
        Err(error) => JoinHandle {
            inner: None,
            slot: Arc::new(Mutex::new(None)),
            thread: Thread {
                id: ThreadId(u64::MAX),
                parker: &DEFAULT_PARKER,
            },
            spawn_error: Some(error),
        },
    }
}

/// Block the calling thread for `duration` (at least one scheduler tick).
pub fn sleep(duration: Duration) {
    static SLEEP_WORD: AtomicU32 = AtomicU32::new(0);
    // A private futex word with no waker: the wait always runs to its timeout,
    // which is exactly what "sleep" means, and the thread is parked in the
    // scheduler rather than spinning.
    let _ = libcanvas::futex::wait(&SLEEP_WORD, 0, duration.as_ticks_ceil().max(1));
}

/// Give the scheduler a chance to run another thread.
pub fn yield_now() {
    crate::process::yield_now();
}

/// Stop only the calling thread.
pub fn exit(code: i32) -> ! {
    sys::exit(i64::from(code))
}

/// True when this error means "the thread was already joined".
pub fn is_join_error(error: &Error) -> bool {
    matches!(error.code(), Some(ErrorCode::InvalidArgs))
}
