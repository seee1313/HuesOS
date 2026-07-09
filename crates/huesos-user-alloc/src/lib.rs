//! Scudo-like Userspace Allocator for HuesOS.
//!
//! This allocator implements segregated fits, quarantine for UAF detection,
//! and uses guard pages to detect overflows.

#![no_std]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Trait for page-level allocation, to be implemented by the kernel
/// when setting up the userspace process.
pub trait PageProvider {
    fn allocate_pages(&self, count: usize) -> Option<NonNull<u8>>;
    fn free_pages(&self, ptr: NonNull<u8>, count: usize);
    fn protect_page(&self, ptr: NonNull<u8>, protect: PageProtection);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

/// Size classes for segregated fits.
const SIZE_CLASSES: &[usize] = &[
    16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
];

pub struct ScudoAllocator<P: PageProvider> {
    page_provider: P,
    quarantine: Quarantine,
    // In a full implementation, we'd have a list of slabs for each size class.
    // For the MVP, we'll simplify.
}

struct Quarantine {
    buffer: [Option<NonNull<u8>>; 64],
    index: AtomicUsize,
}

impl Quarantine {
    const fn new() -> Self {
        Self {
            buffer: [None; 64],
            index: AtomicUsize::new(0),
        }
    }

    fn push(&mut self, ptr: NonNull<u8>) {
        let idx = self.index.fetch_add(1, Ordering::SeqCst) % 64;
        self.buffer[idx] = Some(ptr);
    }

    fn pop_and_free<P: PageProvider>(&mut self, provider: &P) {
        let idx = self.index.load(Ordering::SeqCst) % 64;
        if let Some(ptr) = self.buffer[idx].take() {
            provider.free_pages(ptr, 1); // Simplified: assume 1 page
        }
    }
}

impl<P: PageProvider> ScudoAllocator<P> {
    pub const fn new(provider: P) -> Self {
        Self {
            page_provider: provider,
            quarantine: Quarantine::new(),
        }
    }

    pub fn alloc(&mut self, size: usize) -> Option<NonNull<u8>> {
        let class = SIZE_CLASSES.iter().find(|&&s| s >= size)?;
        let class_size = *class;

        // simplified: allocate enough pages for the size class plus one guard page.
        let pages_needed = class_size.div_ceil(4096);
        let ptr = self.page_provider.allocate_pages(pages_needed + 1)?;
        
        // Protect the second page as Guard Page
        unsafe {
            let guard_ptr = NonNull::new_unchecked(ptr.as_ptr().add(4096));
            self.page_provider.protect_page(guard_ptr, PageProtection::NoAccess);
        }

        Some(ptr)
    }

    pub fn free(&mut self, ptr: NonNull<u8>) {
        self.quarantine.push(ptr);
        self.quarantine.pop_and_free(&self.page_provider);
    }
}
