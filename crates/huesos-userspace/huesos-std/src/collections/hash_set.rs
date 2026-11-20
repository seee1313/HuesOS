//! A hash set, built on [`super::hash_map::HashMap`] with `()` values.
//!
//! The set keeps the map's key type as its element type, so `set.iter()`
//! yields `&T` straight from the table instead of a `(T, ())` pair.

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;
use core::hash::{BuildHasher, Hash};

use super::hash::RandomState;
use super::hash_map::{self, HashMap};

/// A set of unique values.
pub struct HashSet<T, S = RandomState> {
    map: HashMap<T, (), S>,
}

impl<T> HashSet<T, RandomState> {
    /// An empty set with the process' default hasher.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// An empty set with room for `capacity` elements.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
        }
    }
}

impl<T> Default for HashSet<T, RandomState> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, S> HashSet<T, S> {
    /// An empty set using `hasher`.
    pub const fn with_hasher(hasher: S) -> Self {
        Self {
            map: HashMap::with_hasher(hasher),
        }
    }

    /// An empty set with `hasher` and room for `capacity` elements.
    pub fn with_capacity_and_hasher(capacity: usize, hasher: S) -> Self {
        Self {
            map: HashMap::with_capacity_and_hasher(capacity, hasher),
        }
    }

    /// The hash builder this set uses.
    pub fn hasher(&self) -> &S {
        self.map.hasher()
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when the set is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Elements that fit before the next rehash.
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    /// Remove every element.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Every element, in table order.
    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            inner: self.map.iter(),
        }
    }

    /// Empty the set and iterate its elements by value.
    pub fn drain(&mut self) -> Drain<'_, T> {
        Drain {
            inner: self.map.drain(),
        }
    }

    /// Drop tombstones and shrink the table.
    pub fn shrink_to_fit(&mut self)
    where
        T: Eq + Hash,
        S: BuildHasher,
    {
        self.map.shrink_to_fit();
    }
}

impl<T, S> HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    /// Add `value`; returns false if it was already there.
    pub fn insert(&mut self, value: T) -> bool {
        self.map.insert(value, ()).is_none()
    }

    /// True when `value` is in the set.
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.contains_key(value)
    }

    /// The stored element equal to `value`.
    pub fn get<Q>(&self, value: &Q) -> Option<&T>
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_key_value(value).map(|(stored, _)| stored)
    }

    /// Remove `value`; returns true if it was there.
    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.remove(value).is_some()
    }

    /// Remove and return the stored element equal to `value`.
    pub fn take<Q>(&mut self, value: &Q) -> Option<T>
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.remove_entry(value).map(|(stored, _)| stored)
    }

    /// Keep only the elements for which `keep` returns true.
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, mut keep: F) {
        self.map.retain(|value, ()| keep(value));
    }

    /// Elements in either set.
    pub fn union<'a>(&'a self, other: &'a HashSet<T, S>) -> impl Iterator<Item = &'a T> {
        self.iter()
            .chain(other.iter().filter(move |value| !self.contains(*value)))
    }

    /// Elements in both sets.
    pub fn intersection<'a>(&'a self, other: &'a HashSet<T, S>) -> impl Iterator<Item = &'a T> {
        self.iter().filter(move |value| other.contains(*value))
    }

    /// Elements in this set but not in `other`.
    pub fn difference<'a>(&'a self, other: &'a HashSet<T, S>) -> impl Iterator<Item = &'a T> {
        self.iter().filter(move |value| !other.contains(*value))
    }

    /// Elements in exactly one of the two sets.
    pub fn symmetric_difference<'a>(
        &'a self,
        other: &'a HashSet<T, S>,
    ) -> impl Iterator<Item = &'a T> {
        self.difference(other).chain(other.difference(self))
    }

    /// True when every element of `self` is in `other`.
    pub fn is_subset(&self, other: &HashSet<T, S>) -> bool {
        self.iter().all(|value| other.contains(value))
    }

    /// True when every element of `other` is in `self`.
    pub fn is_superset(&self, other: &HashSet<T, S>) -> bool {
        other.is_subset(self)
    }

    /// True when the two sets have no element in common.
    pub fn is_disjoint(&self, other: &HashSet<T, S>) -> bool {
        self.intersection(other).next().is_none()
    }
}

impl<T, S> Clone for HashSet<T, S>
where
    T: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

impl<T, S> fmt::Debug for HashSet<T, S>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("{")?;
        let mut first = true;
        for value in self.iter() {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            fmt::Debug::fmt(value, f)?;
        }
        f.write_str("}")
    }
}

impl<T, S> PartialEq for HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.is_subset(other)
    }
}

impl<T, S> Eq for HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
}

impl<T, S> Extend<T> for HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for value in iter {
            self.insert(value);
        }
    }
}

impl<T, S> FromIterator<T> for HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher + Default,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = Self::with_hasher(S::default());
        set.extend(iter);
        set
    }
}

impl<T, S> IntoIterator for HashSet<T, S> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> IntoIter<T> {
        IntoIter {
            inner: self.map.into_iter(),
        }
    }
}

impl<'a, T, S> IntoIterator for &'a HashSet<T, S> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

/// Iterator over a set's elements by reference.
pub struct Iter<'a, T> {
    inner: hash_map::Iter<'a, T, ()>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.inner.next().map(|(value, ())| value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Iterator that empties a set.
pub struct Drain<'a, T> {
    inner: hash_map::Drain<'a, T, ()>,
}

impl<T> Iterator for Drain<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.inner.next().map(|(value, ())| value)
    }
}

/// Iterator that consumes a set.
pub struct IntoIter<T> {
    inner: hash_map::IntoIter<T, ()>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.inner.next().map(|(value, ())| value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Build a set from a slice of values, keeping the first occurrence.
pub fn from_slice<T: Clone + Eq + Hash>(values: &[T]) -> HashSet<T> {
    let mut set = HashSet::with_capacity(values.len());
    set.extend(values.iter().cloned());
    set
}

/// Collect the distinct values of an iterator, preserving first-seen order in
/// a separate `Vec` for callers that need to report them in input order.
pub fn distinct_ordered<T: Clone + Eq + Hash>(values: impl Iterator<Item = T>) -> Vec<T> {
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            ordered.push(value);
        }
    }
    ordered
}
