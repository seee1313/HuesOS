//! An open-addressing `HashMap` with the hash-function choice exposed.
//!
//! # Why this exists at all
//! `std::collections::HashMap` is `hashbrown`; `alloc` has no hash map, so a
//! `no_std` library that wants one has to write it. This is a linear-probing
//! table with stored hashes and tombstoned deletion:
//!
//! * the table is a `Vec` of [`Bucket`]s whose length is always a power of two,
//!   so probing is a mask instead of a modulo;
//! * every occupied bucket keeps its full 64-bit hash, so a probe that lands on
//!   the wrong key rejects it after one comparison instead of running the key's
//!   `Eq` (string comparison, block-UUID comparison) again;
//! * deletion writes a tombstone, and the table rehashes when tombstones reach
//!   a quarter of the capacity, which keeps probe runs short under churn.
//!
//! The default hasher is [`RandomState`] (SipHash-1-3 keyed per process), so
//! `HashMap::new()` works with no setup and no entropy syscall.

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::iter::FusedIterator;

use super::hash::RandomState;

/// Smallest table: eight slots, so a single-entry map still probes cleanly.
const MIN_CAPACITY: usize = 8;

/// One slot of the table.
enum Bucket<K, V> {
    /// Never used.
    Empty,
    /// Freed by `remove`; a probe must step over it but may reuse it.
    Deleted,
    /// A live entry, with its precomputed hash.
    Full {
        /// The hash of `key` under the map's hasher.
        hash: u64,
        /// The key as stored.
        key: K,
        /// The value as stored.
        value: V,
    },
}

impl<K, V> Bucket<K, V> {
    fn value_mut(&mut self) -> Option<&mut V> {
        match self {
            Bucket::Full { value, .. } => Some(value),
            _ => None,
        }
    }

    fn is_full(&self) -> bool {
        matches!(self, Bucket::Full { .. })
    }
}

/// A hash map with linear probing.
///
/// The `S` parameter is the hash builder; the default is the process-keyed
/// [`RandomState`]. Use [`HashMap::with_hasher`] with
/// [`super::hash::IdentityHasher`] when the keys are already uniform.
pub struct HashMap<K, V, S = RandomState> {
    buckets: Vec<Bucket<K, V>>,
    /// Number of `Full` buckets.
    live: usize,
    /// Number of `Deleted` buckets.
    deleted: usize,
    hasher: S,
}

impl<K, V> HashMap<K, V, RandomState> {
    /// An empty map with the process' default hasher.
    pub fn new() -> Self {
        Self::with_hasher(RandomState::new())
    }

    /// An empty map with room for `capacity` entries before the first rehash.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_hasher(capacity, RandomState::new())
    }
}

impl<K, V> Default for HashMap<K, V, RandomState> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V, S> HashMap<K, V, S> {
    /// An empty map using `hasher`.
    pub const fn with_hasher(hasher: S) -> Self {
        Self {
            buckets: Vec::new(),
            live: 0,
            deleted: 0,
            hasher,
        }
    }

    /// An empty map with `hasher` and room for `capacity` entries.
    pub fn with_capacity_and_hasher(capacity: usize, hasher: S) -> Self {
        Self {
            buckets: if capacity == 0 {
                Vec::new()
            } else {
                empty_table(table_size(capacity))
            },
            live: 0,
            deleted: 0,
            hasher,
        }
    }

    /// The hash builder this map uses.
    pub fn hasher(&self) -> &S {
        &self.hasher
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.live
    }

    /// True when there are no entries.
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Entries that fit before the next rehash.
    pub fn capacity(&self) -> usize {
        // Keep the 3/4 load factor of the resize rule visible to callers.
        self.buckets.len() / 4 * 3
    }

    /// Remove every entry, keeping the allocation.
    pub fn clear(&mut self) {
        self.buckets = Vec::new();
        self.live = 0;
        self.deleted = 0;
    }

    /// Every entry, in table order.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            inner: self.buckets.iter(),
        }
    }

    /// Every entry with mutable values, in table order.
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        IterMut {
            inner: self.buckets.iter_mut(),
        }
    }

    /// Every key, in table order.
    pub fn keys(&self) -> Keys<'_, K, V> {
        Keys { inner: self.iter() }
    }

    /// Every value, in table order.
    pub fn values(&self) -> Values<'_, K, V> {
        Values { inner: self.iter() }
    }

    /// Every value, mutable, in table order.
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V> {
        ValuesMut {
            inner: self.iter_mut(),
        }
    }

    /// Empty the map and iterate its entries by value.
    pub fn drain(&mut self) -> Drain<'_, K, V> {
        self.live = 0;
        self.deleted = 0;
        Drain {
            inner: core::mem::take(&mut self.buckets).into_iter(),
            marker: core::marker::PhantomData,
        }
    }
    /// Drop tombstones and shrink the table to the smallest size that fits.
    pub fn shrink_to_fit(&mut self)
    where
        K: Eq + Hash,
        S: BuildHasher,
    {
        self.rehash(table_size(self.live));
    }
}

impl<K, V, S> HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    fn hash_key<Q: Hash + ?Sized>(&self, key: &Q) -> u64 {
        let mut hasher = self.hasher.build_hasher();
        key.hash(&mut hasher);
        core::hash::Hasher::finish(&hasher)
    }

    /// Index of the live entry for `key`, if any.
    fn find<Q>(&self, key: &Q, hash: u64) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if self.buckets.is_empty() {
            return None;
        }
        let mask = self.buckets.len() - 1;
        let mut index = (hash as usize) & mask;
        loop {
            match &self.buckets[index] {
                Bucket::Empty => return None,
                Bucket::Deleted => {}
                Bucket::Full {
                    hash: stored,
                    key: stored_key,
                    ..
                } => {
                    if *stored == hash && stored_key.borrow() == key {
                        return Some(index);
                    }
                }
            }
            index = (index + 1) & mask;
        }
    }

    /// First reusable slot for `key`, which must not already be present.
    fn vacant_index<Q>(&self, key: &Q, hash: u64) -> usize
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mask = self.buckets.len() - 1;
        let mut index = (hash as usize) & mask;
        let mut first_deleted = None;
        loop {
            match &self.buckets[index] {
                Bucket::Empty => return first_deleted.unwrap_or(index),
                Bucket::Deleted => {
                    if first_deleted.is_none() {
                        first_deleted = Some(index);
                    }
                }
                Bucket::Full {
                    hash: stored,
                    key: stored_key,
                    ..
                } => {
                    if *stored == hash && stored_key.borrow() == key {
                        // Already present: the caller asked for a vacant slot.
                        return index;
                    }
                }
            }
            index = (index + 1) & mask;
        }
    }

    /// True when the table would be over-full after one more insert.
    fn needs_growth(&self) -> bool {
        let slots = self.buckets.len();
        if slots == 0 {
            return true;
        }
        (self.live + self.deleted + 1) * 4 > slots * 3
    }

    /// Make room for one more entry.
    fn reserve_one(&mut self) {
        if !self.needs_growth() {
            return;
        }
        let target = if self.live * 2 > self.buckets.len() {
            table_size(self.live + 1)
        } else {
            // Mostly tombstones: same size, fresh table.
            self.buckets.len()
        };
        self.rehash(target.max(MIN_CAPACITY));
    }

    /// Rebuild the table with `slots` slots (must be a power of two).
    fn rehash(&mut self, slots: usize) {
        let old = core::mem::replace(&mut self.buckets, empty_table(slots));
        self.deleted = 0;
        self.live = 0;
        let mask = slots - 1;
        for bucket in old {
            if let Bucket::Full { hash, key, value } = bucket {
                let mut index = (hash as usize) & mask;
                while self.buckets[index].is_full() {
                    index = (index + 1) & mask;
                }
                self.buckets[index] = Bucket::Full { hash, key, value };
                self.live += 1;
            }
        }
    }

    /// Insert `value` at `key`, returning the previous value if there was one.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.reserve_one();
        let hash = self.hash_key(&key);
        let index = match self.find(&key, hash) {
            Some(index) => index,
            None => self.vacant_index(&key, hash),
        };
        if self.buckets[index].is_full() {
            if let Bucket::Full { value: slot, .. } = &mut self.buckets[index] {
                return Some(core::mem::replace(slot, value));
            }
        }
        if matches!(self.buckets[index], Bucket::Deleted) {
            self.deleted -= 1;
        }
        self.buckets[index] = Bucket::Full { hash, key, value };
        self.live += 1;
        None
    }

    /// The value stored for `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        let index = self.find(key, hash)?;
        match &self.buckets[index] {
            Bucket::Full { value, .. } => Some(value),
            _ => None,
        }
    }

    /// The key and value stored for `key`.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        let index = self.find(key, hash)?;
        match &self.buckets[index] {
            Bucket::Full { key, value, .. } => Some((key, value)),
            _ => None,
        }
    }

    /// Mutable access to the value stored for `key`.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        let index = self.find(key, hash)?;
        self.buckets[index].value_mut()
    }

    /// True when `key` is present.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        self.find(key, hash).is_some()
    }

    /// Remove `key`, returning its value.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove_entry(key).map(|(_, value)| value)
    }

    /// Remove `key`, returning its key and value.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        let index = self.find(key, hash)?;
        let bucket = core::mem::replace(&mut self.buckets[index], Bucket::Deleted);
        self.live -= 1;
        self.deleted += 1;
        match bucket {
            Bucket::Full { key, value, .. } => Some((key, value)),
            _ => None,
        }
    }

    /// Keep only the entries for which `keep` returns true.
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&mut self, mut keep: F) {
        for index in 0..self.buckets.len() {
            let remove = match &mut self.buckets[index] {
                Bucket::Full { key, value, .. } => !keep(key, value),
                _ => false,
            };
            if remove {
                self.buckets[index] = Bucket::Deleted;
                self.live -= 1;
                self.deleted += 1;
            }
        }
    }

    /// The entry for `key`, for insertion or in-place update.
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V, S> {
        self.reserve_one();
        let hash = self.hash_key(&key);
        match self.find(&key, hash) {
            Some(index) => Entry::Occupied(OccupiedEntry {
                map: self,
                index,
                hash,
            }),
            None => {
                let index = self.vacant_index(&key, hash);
                Entry::Vacant(VacantEntry {
                    map: self,
                    index,
                    hash,
                    key,
                })
            }
        }
    }

    /// The value for `key`, inserting the result of `default` if absent.
    pub fn get_or_insert_with<F: FnOnce() -> V>(&mut self, key: K, default: F) -> &mut V {
        match self.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }
}

impl<K, V, S> Clone for HashMap<K, V, S>
where
    K: Clone,
    V: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            buckets: self
                .buckets
                .iter()
                .map(|bucket| match bucket {
                    Bucket::Empty => Bucket::Empty,
                    Bucket::Deleted => Bucket::Deleted,
                    Bucket::Full { hash, key, value } => Bucket::Full {
                        hash: *hash,
                        key: key.clone(),
                        value: value.clone(),
                    },
                })
                .collect(),
            live: self.live,
            deleted: self.deleted,
            hasher: self.hasher.clone(),
        }
    }
}

impl<K, V, S> fmt::Debug for HashMap<K, V, S>
where
    K: fmt::Debug,
    V: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("{")?;
        let mut first = true;
        for (key, value) in self.iter() {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            fmt::Debug::fmt(key, f)?;
            f.write_str(": ")?;
            fmt::Debug::fmt(value, f)?;
        }
        f.write_str("}")
    }
}

impl<K, V, S> PartialEq for HashMap<K, V, S>
where
    K: Eq + Hash,
    V: PartialEq,
    S: BuildHasher,
{
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.iter()
            .all(|(key, value)| other.get(key).is_some_and(|other| other == value))
    }
}

impl<K, V, S> Eq for HashMap<K, V, S>
where
    K: Eq + Hash,
    V: Eq,
    S: BuildHasher,
{
}

impl<K, V, S> Extend<(K, V)> for HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (key, value) in iter {
            self.insert(key, value);
        }
    }
}

impl<K, V, S> FromIterator<(K, V)> for HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher + Default,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::with_hasher(S::default());
        map.extend(iter);
        map
    }
}

impl<K, V, S> IntoIterator for HashMap<K, V, S> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;

    fn into_iter(self) -> IntoIter<K, V> {
        IntoIter {
            inner: self.buckets.into_iter(),
        }
    }
}

impl<'a, K, V, S> IntoIterator for &'a HashMap<K, V, S> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Iter<'a, K, V> {
        self.iter()
    }
}

impl<'a, K, V, S> IntoIterator for &'a mut HashMap<K, V, S> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    fn into_iter(self) -> IterMut<'a, K, V> {
        self.iter_mut()
    }
}

/// Iterator over a map's entries by reference.
pub struct Iter<'a, K, V> {
    inner: core::slice::Iter<'a, Bucket<K, V>>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Bucket::Full { key, value, .. } = self.inner.next()? {
                return Some((key, value));
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.inner.len()))
    }
}

impl<K, V> FusedIterator for Iter<'_, K, V> {}

/// Iterator over a map's entries with mutable values.
pub struct IterMut<'a, K, V> {
    inner: core::slice::IterMut<'a, Bucket<K, V>>,
}

impl<'a, K, V> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Bucket::Full { key, value, .. } = self.inner.next()? {
                return Some((key, value));
            }
        }
    }
}

impl<K, V> FusedIterator for IterMut<'_, K, V> {}

/// Iterator over a map's keys.
pub struct Keys<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K, V> Iterator for Keys<'a, K, V> {
    type Item = &'a K;

    fn next(&mut self) -> Option<&'a K> {
        self.inner.next().map(|(key, _)| key)
    }
}

impl<K, V> FusedIterator for Keys<'_, K, V> {}

/// Iterator over a map's values.
pub struct Values<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K, V> Iterator for Values<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<&'a V> {
        self.inner.next().map(|(_, value)| value)
    }
}

impl<K, V> FusedIterator for Values<'_, K, V> {}

/// Iterator over a map's values, mutable.
pub struct ValuesMut<'a, K, V> {
    inner: IterMut<'a, K, V>,
}

impl<'a, K, V> Iterator for ValuesMut<'a, K, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<&'a mut V> {
        self.inner.next().map(|(_, value)| value)
    }
}

impl<K, V> FusedIterator for ValuesMut<'_, K, V> {}

/// Iterator that empties a map.
pub struct Drain<'a, K, V> {
    inner: alloc::vec::IntoIter<Bucket<K, V>>,
    /// Keeps the map borrow alive for the drain's whole life.
    marker: core::marker::PhantomData<&'a mut HashMap<K, V>>,
}

impl<K, V> Iterator for Drain<'_, K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<(K, V)> {
        loop {
            if let Bucket::Full { key, value, .. } = self.inner.next()? {
                return Some((key, value));
            }
        }
    }
}

/// Iterator that consumes a map.
pub struct IntoIter<K, V> {
    inner: alloc::vec::IntoIter<Bucket<K, V>>,
}

impl<K, V> Iterator for IntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<(K, V)> {
        loop {
            if let Bucket::Full { key, value, .. } = self.inner.next()? {
                return Some((key, value));
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.inner.len()))
    }
}

impl<K, V> FusedIterator for IntoIter<K, V> {}

/// A view into one map entry.
pub enum Entry<'a, K, V, S = RandomState> {
    /// The key is present.
    Occupied(OccupiedEntry<'a, K, V, S>),
    /// The key is absent.
    Vacant(VacantEntry<'a, K, V, S>),
}

impl<'a, K, V, S> Entry<'a, K, V, S>
where
    K: Eq + Hash,
{
    /// Run `default` and insert its result if the key is absent.
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default),
        }
    }

    /// Run `default` and insert its result if the key is absent.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }

    /// Run `default` with the key and insert its result if absent.
    pub fn or_insert_with_key<F: FnOnce(&K) -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = default(&entry.key);
                entry.insert(value)
            }
        }
    }

    /// The key this entry stands for.
    pub fn key(&self) -> &K {
        match self {
            Entry::Occupied(entry) => entry.key(),
            Entry::Vacant(entry) => &entry.key,
        }
    }

    /// Change the value if the key is present.
    pub fn and_modify<F: FnOnce(&mut V)>(self, modify: F) -> Self {
        match self {
            Entry::Occupied(mut entry) => {
                modify(entry.get_mut());
                Entry::Occupied(entry)
            }
            Entry::Vacant(entry) => Entry::Vacant(entry),
        }
    }

    /// Insert the default if absent, then return the value.
    pub fn or_default(self) -> &'a mut V
    where
        V: Default,
    {
        self.or_insert_with(V::default)
    }
}

/// An entry whose key is present.
pub struct OccupiedEntry<'a, K, V, S = RandomState> {
    map: &'a mut HashMap<K, V, S>,
    index: usize,
    hash: u64,
}

impl<'a, K, V, S> OccupiedEntry<'a, K, V, S>
where
    K: Eq + Hash,
{
    /// The stored key.
    pub fn key(&self) -> &K {
        match &self.map.buckets[self.index] {
            Bucket::Full { key, .. } => key,
            _ => super::unreachable_ref(),
        }
    }

    /// The stored value.
    pub fn get(&self) -> &V {
        match &self.map.buckets[self.index] {
            Bucket::Full { value, .. } => value,
            _ => super::unreachable_ref(),
        }
    }

    /// The stored value, mutable.
    pub fn get_mut(&mut self) -> &mut V {
        match self.map.buckets[self.index].value_mut() {
            Some(value) => value,
            None => super::unreachable_mut(),
        }
    }

    /// Replace the value, returning the old one.
    pub fn insert(&mut self, value: V) -> V {
        match &mut self.map.buckets[self.index] {
            Bucket::Full { value: slot, .. } => core::mem::replace(slot, value),
            _ => super::unreachable_value(),
        }
    }

    /// The value, borrowed for the rest of the map's life.
    pub fn into_mut(self) -> &'a mut V {
        let index = self.index;
        match self.map.buckets[index].value_mut() {
            Some(value) => value,
            None => super::unreachable_mut(),
        }
    }

    /// Remove the entry, returning its value.
    pub fn remove(self) -> V {
        self.remove_entry().1
    }

    /// Remove the entry, returning its key and value.
    pub fn remove_entry(self) -> (K, V) {
        let _ = self.hash;
        let bucket = core::mem::replace(&mut self.map.buckets[self.index], Bucket::Deleted);
        self.map.live -= 1;
        self.map.deleted += 1;
        match bucket {
            Bucket::Full { key, value, .. } => (key, value),
            _ => super::unreachable_value(),
        }
    }
}

/// An entry whose key is absent; inserting it is the only option.
pub struct VacantEntry<'a, K, V, S = RandomState> {
    map: &'a mut HashMap<K, V, S>,
    index: usize,
    hash: u64,
    /// The key, waiting to be stored.
    pub(super) key: K,
}

impl<'a, K, V, S> VacantEntry<'a, K, V, S>
where
    K: Eq + Hash,
{
    /// The key this entry would insert.
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Insert `value` and return a reference to it.
    pub fn insert(self, value: V) -> &'a mut V {
        let index = self.index;
        let map = self.map;
        let replaced = core::mem::replace(
            &mut map.buckets[index],
            Bucket::Full {
                hash: self.hash,
                key: self.key,
                value,
            },
        );
        if matches!(replaced, Bucket::Deleted) {
            map.deleted -= 1;
        }
        map.live += 1;
        match map.buckets[index].value_mut() {
            Some(value) => value,
            None => super::unreachable_mut(),
        }
    }
}

/// `slots` table entries for `capacity` live entries at a 3/4 load factor.
pub(crate) fn table_size(capacity: usize) -> usize {
    let needed = capacity.saturating_mul(4) / 3 + 1;
    let mut slots = MIN_CAPACITY;
    while slots < needed {
        slots *= 2;
    }
    slots
}

/// A table of `slots` empty buckets.
fn empty_table<K, V>(slots: usize) -> Vec<Bucket<K, V>> {
    let mut table = Vec::with_capacity(slots);
    table.resize_with(slots, || Bucket::Empty);
    table
}
