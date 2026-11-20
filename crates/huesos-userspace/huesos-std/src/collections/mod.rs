//! Collections: hash map, hash set, and the ordered containers from `alloc`.
//!
//! # What is written here and what is not
//! `alloc` ships `BTreeMap`, `BTreeSet`, `VecDeque`, `BinaryHeap` and
//! `LinkedList` — and those are *exactly* the types `std::collections`
//! re-exports; `std` has no second implementation of a B-tree. They are
//! re-exported here for the same reason `std` does it: so a program can
//! `use huesos_std::collections::BTreeMap` and not care which crate defines it.
//!
//! `alloc` has **no** hash table. `std` gets one from `hashbrown`, which
//! `huesos-std` cannot use (it is `no_std`-hostile and pulls in `raw_entry`
//! `unsafe`), so [`HashMap`] and [`HashSet`] are implemented here: linear
//! probing over a power-of-two table, with stored hashes, tombstones, and a
//! per-process SipHash-1-3 key so that `HashMap::new()` is safe against
//! collision attacks without needing an entropy syscall.
//!
//! ```
//! use huesos_std::collections::HashMap;
//!
//! let mut counts: HashMap<&str, u32> = HashMap::new();
//! for word in ["a", "b", "a"] {
//!     *counts.entry(word).or_insert(0) += 1;
//! }
//! assert_eq!(counts.get("a"), Some(&2));
//! ```

pub mod hash;
pub mod hash_map;
pub mod hash_set;

pub use hash::{
    hash_one, BuildHasher, DefaultHasher, Hasher, IdentityHasher, RandomState, SipHasher13,
};
pub use hash_map::{
    Drain as HashMapDrain, Entry, HashMap, IntoIter as HashMapIntoIter, Iter as HashMapIter,
    IterMut as HashMapIterMut, Keys, OccupiedEntry, VacantEntry, Values, ValuesMut,
};
pub use hash_set::{
    Drain as HashSetDrain, HashSet, IntoIter as HashSetIntoIter, Iter as HashSetIter,
};

/// The ordered map, re-exported from `alloc` (the implementation `std` uses).
pub use alloc::collections::BTreeMap;
/// The ordered set, re-exported from `alloc` (the implementation `std` uses).
pub use alloc::collections::BTreeSet;
/// The max-heap, re-exported from `alloc`.
pub use alloc::collections::BinaryHeap;
/// The doubly linked list, re-exported from `alloc`.
pub use alloc::collections::LinkedList;
/// The double-ended queue, re-exported from `alloc`.
pub use alloc::collections::VecDeque;

/// `alloc`'s collection modules, so `collections::btree_map::Entry` resolves.
pub use alloc::collections::{binary_heap, btree_map, btree_set, linked_list, vec_deque};

/// A reference to a value that cannot exist.
///
/// The hash table's `match` arms after a successful lookup are unreachable, and
/// engineering a `panic!` for them would spend budget the project tracks
/// (`panic_macros` in `safety-budget.json`) on a branch that never runs. Parking
/// the thread keeps the code total and turns a would-be UB bug into a hang that
/// the smoke tests catch.
pub(crate) fn unreachable_ref<'a, T>() -> &'a T {
    loop {
        core::hint::spin_loop();
    }
}

/// Mutable form of [`unreachable_ref`].
pub(crate) fn unreachable_mut<'a, T>() -> &'a mut T {
    loop {
        core::hint::spin_loop();
    }
}

/// Value form of [`unreachable_ref`], for arms that return owned data.
pub(crate) fn unreachable_value<T>() -> T {
    loop {
        core::hint::spin_loop();
    }
}
