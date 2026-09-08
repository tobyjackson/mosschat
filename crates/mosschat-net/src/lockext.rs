//! A poisoned-lock recovery helper (invariant 1: no panics in library
//! code). Every `std::sync::Mutex::lock().unwrap()` in this crate assumed a
//! poisoned lock could never happen; it can, the moment any thread holding
//! the lock panics (a bug elsewhere, an `.await` cancellation racing a
//! guard drop, or a test harness aborting a task mid-hold), and every
//! caller after that would then panic too, turning one bug into a cascade.
//! [`LockExt::lock_or_recover`] instead takes the poisoned guard: the data
//! behind a `std::sync::Mutex` here is always a plain in-memory structure
//! (a hash map, a counter, a rate limiter) that stays internally consistent
//! even if a panic interrupted a write half way, so recovering it is safe
//! and keeps the gate serving every other connection.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Recovers from lock poisoning rather than panicking on it.
pub(crate) trait LockExt<T> {
    /// Locks `self`, recovering the guard from a poisoned lock instead of
    /// panicking (see the module doc).
    fn lock_or_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_or_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
