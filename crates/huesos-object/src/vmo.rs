//! Virtual Memory Object implementation.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use spin::Mutex;

use crate::{alloc_koid, phys_to_virt, KernelObject, Koid, ObjectType};

/// Virtual Memory Object — a resizable collection of physical page frames.
///
/// Backed by real physical memory (via `huesos-pmm`), not a `Vec<u8>` — so
/// it can actually be mapped into a process's page tables.
pub struct Vmo {
    koid: Koid,
    name: Mutex<String>,
    size: Mutex<usize>,
    /// Physical frame addresses, one per 4 KiB page.
    frames: Mutex<Vec<u64>>,
}

const PAGE_SIZE: usize = 4096;

/// VMO allocation/resize failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmoError {
    /// Physical memory could not satisfy the requested page count.
    OutOfMemory,
}

impl Vmo {
    /// Create a VMO covering at least `size` bytes, backed by freshly
    /// allocated, zeroed physical frames.
    ///
    /// Returns [`VmoError::OutOfMemory`] if the host is out of physical memory, instead of
    /// panicking: a userspace process requesting an oversized VMO (or many
    /// processes collectively exhausting memory) is an entirely ordinary,
    /// expected condition that must surface as a syscall error
    /// (`SyscallError::NoMemory`), not take down the whole kernel. Any
    /// frames already allocated before the failure are freed back to the
    /// PMM before returning, so a failed allocation never leaks memory.
    pub fn new(size: usize) -> Result<Arc<Self>, VmoError> {
        let koid = alloc_koid();
        let page_count = size.div_ceil(PAGE_SIZE).max(1);
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(page_count)
            .map_err(|_| VmoError::OutOfMemory)?;
        for _ in 0..page_count {
            let frame = match huesos_pmm::alloc_frame() {
                Ok(f) => f,
                Err(_) => {
                    for f in frames {
                        huesos_pmm::free_frame(f);
                    }
                    return Err(VmoError::OutOfMemory);
                }
            };
            let virt = phys_to_virt(frame) as *mut u8;
            unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE) };
            frames.push(frame);
        }
        Ok(Arc::new(Self {
            koid,
            name: Mutex::new(String::new()),
            size: Mutex::new(size),
            frames: Mutex::new(frames),
        }))
    }

    /// Number of 4 KiB pages backing this VMO.
    pub fn page_count(&self) -> usize {
        self.frames.lock().len()
    }

    /// Physical address of the `index`-th page, if present.
    pub fn frame_at(&self, index: usize) -> Option<u64> {
        self.frames.lock().get(index).copied()
    }

    /// Logical size in bytes.
    pub fn size(&self) -> usize {
        *self.size.lock()
    }

    /// Read bytes at `offset`, copying into `buf`. Returns bytes copied.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
        let size = self.size();
        if offset >= size {
            return 0;
        }
        let len = buf.len().min(size - offset);
        let frames = self.frames.lock();
        let mut copied = 0;
        while copied < len {
            let abs = offset + copied;
            let page_idx = abs / PAGE_SIZE;
            let page_off = abs % PAGE_SIZE;
            let Some(&frame) = frames.get(page_idx) else {
                break;
            };
            let chunk = (PAGE_SIZE - page_off).min(len - copied);
            let src = (phys_to_virt(frame) as *const u8).wrapping_add(page_off);
            unsafe {
                core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr().add(copied), chunk);
            }
            copied += chunk;
        }
        copied
    }

    /// Write bytes at `offset` from `buf`. Returns bytes copied.
    pub fn write(&self, offset: usize, buf: &[u8]) -> usize {
        let size = self.size();
        if offset >= size {
            return 0;
        }
        let len = buf.len().min(size - offset);
        let frames = self.frames.lock();
        let mut copied = 0;
        while copied < len {
            let abs = offset + copied;
            let page_idx = abs / PAGE_SIZE;
            let page_off = abs % PAGE_SIZE;
            let Some(&frame) = frames.get(page_idx) else {
                break;
            };
            let chunk = (PAGE_SIZE - page_off).min(len - copied);
            let dst = (phys_to_virt(frame) as *mut u8).wrapping_add(page_off);
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr().add(copied), dst, chunk);
            }
            copied += chunk;
        }
        copied
    }

    /// Grow the VMO to `new_size` bytes, allocating new physical frames as
    /// needed. Shrinking is not supported in the MVP.
    ///
    /// Returns [`VmoError::OutOfMemory`] instead of panicking (see
    /// [`Vmo::new`]'s docs for why). On failure, the VMO is left at
    /// whatever size it successfully grew to before running out of frames
    /// (still fully valid/usable at that smaller size) rather than in some
    /// half-initialized state.
    pub fn set_size(&self, new_size: usize) -> Result<(), VmoError> {
        let mut size = self.size.lock();
        if new_size <= *size {
            return Ok(());
        }
        let mut frames = self.frames.lock();
        let needed_pages = new_size.div_ceil(PAGE_SIZE);
        while frames.len() < needed_pages {
            let frame = match huesos_pmm::alloc_frame() {
                Ok(f) => f,
                Err(_) => {
                    *size = frames.len() * PAGE_SIZE;
                    return Err(VmoError::OutOfMemory);
                }
            };
            let virt = phys_to_virt(frame) as *mut u8;
            unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE) };
            frames.push(frame);
        }
        *size = new_size;
        Ok(())
    }
}

impl KernelObject for Vmo {
    fn object_type(&self) -> ObjectType {
        ObjectType::Vmo
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Drop for Vmo {
    fn drop(&mut self) {
        // Return every physical frame to the PMM. Safe because Arc drops
        // only when the last handle/reference is gone and no mapping still
        // owns a live Arc (mappings hold koids, not Arcs — frames stay
        // valid until VMO is fully unreferenced).
        let frames = core::mem::take(&mut *self.frames.lock());
        for f in frames {
            huesos_pmm::free_frame(f);
        }
    }
}
