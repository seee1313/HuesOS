//! Zero-heap, `#![forbid(unsafe_code)]` TRB completion waker table for single-threaded
//! Ring-3 xHCI executors (`hues-async`).
//!
//! Each in-flight Command Ring or Transfer Ring request registers the physical DMA
//! address of the TRB whose completion event will fire (`CommandCompletion` or
//! `TransferEvent`). When the interrupt/event-ring pump drains completions from the
//! xHCI Event Ring, [`TrbCompletionTable::complete_by_trb`] deposits the result and
//! wakes the waiting `Future` via `core::task::Waker`. Dropping a [`TrbWaitFuture`]
//! automatically releases its table slot.

use crate::xhci::CompletionCode;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

/// Outcome delivered when an awaited TRB completes on the Event Ring (or is aborted).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrbOutcome {
    /// Decoded xHCI Completion Code (`Success`, `ShortPacket`, `StallError`, etc.).
    pub code: CompletionCode,
    /// Residual transfer byte count (`TransferEvent`) or `0` for commands.
    pub residual_len: u32,
    /// Slot ID reported in the completion TRB (`1..=255`).
    pub slot_id: u8,
    /// Endpoint DCI reported in a `TransferEvent` (`0` for commands).
    pub dci: u8,
}

impl TrbOutcome {
    /// True if `code` indicates normal or short-packet transfer completion.
    pub const fn is_transfer_ok(&self) -> bool {
        self.code.is_ok()
    }

    /// True if `code == CompletionCode::Success`.
    pub const fn is_cmd_ok(&self) -> bool {
        matches!(self.code, CompletionCode::Success)
    }
}

#[derive(Clone, Debug)]
struct WaitSlot {
    in_use: bool,
    generation: u32,
    trb_iova: u64,
    slot_filter: u8,
    outcome: Option<TrbOutcome>,
    waker: Option<Waker>,
}

impl WaitSlot {
    const fn empty() -> Self {
        Self {
            in_use: false,
            generation: 1,
            trb_iova: 0,
            slot_filter: 0,
            outcome: None,
            waker: None,
        }
    }
}

/// Fixed-capacity (`N` concurrent operations) zero-heap TRB completion table.
pub struct TrbCompletionTable<const N: usize> {
    slots: RefCell<[WaitSlot; N]>,
}

/// Opaque generation-checked ticket returned by [`TrbCompletionTable::register`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitTicket {
    index: usize,
    generation: u32,
}

impl<const N: usize> Default for TrbCompletionTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TrbCompletionTable<N> {
    /// Construct an empty completion table with `N` reusable waiter slots.
    pub const fn new() -> Self {
        Self {
            slots: RefCell::new([const { WaitSlot::empty() }; N]),
        }
    }

    /// Reserve a waiter slot watching for a completion event referencing `trb_iova`.
    pub fn register(&self, trb_iova: u64, slot_filter: u8) -> Option<WaitTicket> {
        let mut slots = self.slots.borrow_mut();
        let mut idx = 0usize;
        while idx < N {
            if !slots[idx].in_use {
                let gen_val = slots[idx].generation;
                slots[idx].in_use = true;
                slots[idx].trb_iova = trb_iova & !0xF;
                slots[idx].slot_filter = slot_filter;
                slots[idx].outcome = None;
                slots[idx].waker = None;
                return Some(WaitTicket {
                    index: idx,
                    generation: gen_val,
                });
            }
            idx += 1;
        }
        None
    }

    /// Turn a reserved [`WaitTicket`] into an awaitable RAII [`TrbWaitFuture`].
    pub const fn wait(&self, ticket: WaitTicket) -> TrbWaitFuture<'_, N> {
        TrbWaitFuture {
            table: self,
            ticket,
            completed: false,
        }
    }

    /// Deliver a completion event matching `trb_iova`. Returns `true` if a waiter
    /// matched and was woken.
    pub fn complete_by_trb(&self, trb_iova: u64, outcome: TrbOutcome) -> bool {
        let target = trb_iova & !0xF;
        let waker = {
            let mut slots = self.slots.borrow_mut();
            let mut found = None;
            let mut idx = 0usize;
            while idx < N {
                if slots[idx].in_use
                    && slots[idx].trb_iova == target
                    && slots[idx].outcome.is_none()
                {
                    slots[idx].outcome = Some(outcome);
                    found = slots[idx].waker.take();
                    break;
                }
                idx += 1;
            }
            found
        };
        if let Some(w) = waker {
            w.wake();
            return true;
        }
        false
    }

    /// Cancel all in-flight Transfer Ring waiters belonging to `slot_id` (e.g. when a
    /// root/hub port disconnects) with `code`, waking every affected task.
    pub fn abort_device_slot(&self, slot_id: u8, code: CompletionCode) -> usize {
        if slot_id == 0 {
            return 0;
        }
        let mut to_wake: [Option<Waker>; N] = [const { None }; N];
        let mut count = 0usize;
        {
            let mut slots = self.slots.borrow_mut();
            let mut idx = 0usize;
            while idx < N {
                if slots[idx].in_use
                    && slots[idx].slot_filter == slot_id
                    && slots[idx].outcome.is_none()
                {
                    slots[idx].outcome = Some(TrbOutcome {
                        code,
                        residual_len: 0,
                        slot_id,
                        dci: 0,
                    });
                    to_wake[count] = slots[idx].waker.take();
                    count += 1;
                }
                idx += 1;
            }
        }
        let mut i = 0usize;
        while i < count {
            if let Some(w) = to_wake[i].take() {
                w.wake();
            }
            i += 1;
        }
        count
    }

    fn poll_ticket(&self, ticket: WaitTicket, cx: &mut Context<'_>) -> Poll<Option<TrbOutcome>> {
        let mut slots = self.slots.borrow_mut();
        let Some(slot) = slots.get_mut(ticket.index) else {
            return Poll::Ready(None);
        };
        if !slot.in_use || slot.generation != ticket.generation {
            return Poll::Ready(None);
        }
        if let Some(outcome) = slot.outcome.take() {
            slot.in_use = false;
            slot.trb_iova = 0;
            slot.slot_filter = 0;
            slot.waker = None;
            slot.generation = slot.generation.wrapping_add(1).max(1);
            return Poll::Ready(Some(outcome));
        }
        let replace = match &slot.waker {
            Some(existing) => !existing.will_wake(cx.waker()),
            None => true,
        };
        if replace {
            slot.waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }

    fn cancel_ticket(&self, ticket: WaitTicket) {
        let mut slots = self.slots.borrow_mut();
        let Some(slot) = slots.get_mut(ticket.index) else {
            return;
        };
        if slot.in_use && slot.generation == ticket.generation {
            slot.in_use = false;
            slot.trb_iova = 0;
            slot.slot_filter = 0;
            slot.outcome = None;
            slot.waker = None;
            slot.generation = slot.generation.wrapping_add(1).max(1);
        }
    }
}

/// RAII future awaiting a single TRB completion in [`TrbCompletionTable`].
pub struct TrbWaitFuture<'a, const N: usize> {
    table: &'a TrbCompletionTable<N>,
    ticket: WaitTicket,
    completed: bool,
}

impl<const N: usize> Future for TrbWaitFuture<'_, N> {
    type Output = Option<TrbOutcome>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.table.poll_ticket(self.ticket, cx) {
            Poll::Ready(res) => {
                self.completed = true;
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<const N: usize> Drop for TrbWaitFuture<'_, N> {
    fn drop(&mut self) {
        if !self.completed {
            self.table.cancel_ticket(self.ticket);
        }
    }
}
