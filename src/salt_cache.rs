//! Salt replay protection: tracks recently-seen handshake salts.
//!
//! CVE-3: Without a salt cache, an attacker who captures a valid
//! `(salt, encrypted-handshake-chunk)` pair can re-send it to the server
//! to derive the same key, decrypt the same CONNECT request, and trigger
//! another outbound connection to the captured target. This is an
//! SSRF-style amplification primitive even though confidentiality is
//! preserved by AEAD.
//!
//! Mitigation: keep an LRU + TTL cache of seen salts. A repeat within
//! the TTL window is rejected; after the window elapses the salt is
//! eligible again (the attacker is rate-limited to 1 replay per TTL).

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;

/// ~100 K entries × ~64 B bookkeeping ≈ 6 MB RAM ceiling.
const SALT_CACHE_CAPACITY: usize = 100_000;
/// Replay window. Legitimate handshakes complete well within seconds; after
/// 5 minutes any captured salt is too stale to be useful.
const SALT_CACHE_TTL_SECS: u64 = 300;

pub type Salt = [u8; 16];

/// Thread-safe replay-protection cache. Cheap to `clone()` (it's an `Arc` inside).
#[derive(Clone)]
pub struct SaltCache {
    inner: Arc<Mutex<LruCache<Salt, Instant>>>,
    ttl: Duration,
}

impl SaltCache {
    pub fn new() -> Self {
        Self::with_capacity(SALT_CACHE_CAPACITY, Duration::from_secs(SALT_CACHE_TTL_SECS))
    }

    pub fn with_capacity(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("salt cache capacity > 0"),
            ))),
            ttl,
        }
    }

    /// Atomic check-and-insert. Returns `true` if the salt is fresh (and inserts
    /// it). Returns `false` if the same salt was seen within the TTL window —
    /// the caller MUST refuse the handshake to prevent replay.
    pub fn check_and_insert(&self, salt: &Salt) -> bool {
        let mut cache = self.inner.lock();
        let now = Instant::now();

        // `peek` checks without bumping LRU order — important so that an
        // attacker spamming replays doesn't keep their target salt at the MRU
        // position (which would prevent it from being evicted).
        if let Some(&seen_at) = cache.peek(salt)
            && now.duration_since(seen_at) < self.ttl
        {
            return false;
        }
        // On TTL expiry we fall through and `put` re-admits the salt, which
        // also promotes it to MRU — intentional, so the freshly-readmitted
        // salt gets a full new TTL window of protection.
        cache.put(*salt, now);
        true
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl Default for SaltCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn fresh_salt_accepted() {
        let c = SaltCache::new();
        assert!(c.check_and_insert(&[1u8; 16]));
    }

    #[test]
    fn duplicate_salt_within_ttl_rejected() {
        let c = SaltCache::new();
        let s = [2u8; 16];
        assert!(c.check_and_insert(&s));
        assert!(!c.check_and_insert(&s));
    }

    #[test]
    fn expired_salt_re_accepted_after_ttl() {
        let c = SaltCache::with_capacity(100, Duration::from_millis(50));
        let s = [3u8; 16];
        assert!(c.check_and_insert(&s));
        sleep(Duration::from_millis(100));
        assert!(c.check_and_insert(&s));
    }

    #[test]
    fn lru_evicts_oldest_when_capacity_reached() {
        let c = SaltCache::with_capacity(2, Duration::from_secs(60));
        assert!(c.check_and_insert(&[0u8; 16])); // cache = {0}
        assert!(c.check_and_insert(&[1u8; 16])); // cache = {0, 1}, 0 LRU
        assert!(c.check_and_insert(&[2u8; 16])); // cache = {1, 2}, evicts 0
        // Check survivors first — these are pure peeks, no LRU mutation.
        assert!(!c.check_and_insert(&[1u8; 16]));
        assert!(!c.check_and_insert(&[2u8; 16]));
        // [0; 16] was evicted, so it's fresh again.
        assert!(c.check_and_insert(&[0u8; 16]));
    }

    #[test]
    fn distinct_salts_all_accepted() {
        let c = SaltCache::new();
        for i in 0..100u8 {
            assert!(c.check_and_insert(&[i; 16]));
        }
    }

    #[test]
    fn clone_shares_state() {
        let a = SaltCache::new();
        let b = a.clone();
        let s = [9u8; 16];
        assert!(a.check_and_insert(&s));
        // b sees the same entry — replay through any clone is rejected.
        assert!(!b.check_and_insert(&s));
    }

    #[test]
    fn rejected_replay_does_not_bump_lru_position() {
        // Capacity 2; insert A then B; replay A many times; insert C; A must be
        // the one evicted (because peek does not bump LRU).
        let c = SaltCache::with_capacity(2, Duration::from_secs(60));
        let a = [0xAAu8; 16];
        let b = [0xBBu8; 16];
        let new = [0xCCu8; 16];
        assert!(c.check_and_insert(&a)); // cache = {A}
        assert!(c.check_and_insert(&b)); // cache = {A, B}, A is LRU
        for _ in 0..5 {
            assert!(!c.check_and_insert(&a)); // peeks only, LRU order preserved
        }
        assert!(c.check_and_insert(&new)); // cache = {B, C}, A evicted (was LRU)
        // Check B survived (peek doesn't disturb cache state).
        assert!(!c.check_and_insert(&b));
        // A was evicted → fresh again.
        assert!(c.check_and_insert(&a));
    }
}
