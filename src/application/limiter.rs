//! Rate limiter coordination logic.
//!
//! The rate limiter decides whether events should be allowed or suppressed
//! based on policies and tracks suppression counts.

use crate::application::circuit_breaker::CircuitBreaker;
use crate::application::metrics::Metrics;
use crate::application::ports::Storage;
use crate::application::registry::SuppressionRegistry;
use crate::domain::{
    metadata::EventMetadata,
    policy::{PolicyDecision, RateLimitPolicy},
    signature::EventSignature,
    summary::SuppressionSummary,
};
use std::panic;
use std::sync::Arc;

/// Decision about how to handle an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    /// Allow the event to pass through
    Allow,
    /// Suppress the event
    Suppress,
}

/// Coordinates rate limiting decisions.
#[derive(Clone)]
pub struct RateLimiter<S>
where
    S: Storage<EventSignature, crate::application::registry::EventState> + Clone,
{
    registry: SuppressionRegistry<S>,
    metrics: Metrics,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl<S> RateLimiter<S>
where
    S: Storage<EventSignature, crate::application::registry::EventState> + Clone,
{
    /// Create a new rate limiter.
    ///
    /// # Arguments
    /// * `registry` - The suppression registry (which contains the clock)
    /// * `metrics` - Metrics tracker
    /// * `circuit_breaker` - Circuit breaker for fail-safe operation
    pub fn new(
        registry: SuppressionRegistry<S>,
        metrics: Metrics,
        circuit_breaker: Arc<CircuitBreaker>,
    ) -> Self {
        Self {
            registry,
            metrics,
            circuit_breaker,
        }
    }

    /// Process an event and decide whether to allow or suppress it.
    ///
    /// # Arguments
    /// * `signature` - The event signature
    ///
    /// # Returns
    /// A `LimitDecision` indicating whether to allow or suppress the event.
    ///
    /// # Fail-Safe Behavior
    /// If rate limiting operations fail (circuit breaker open), this method fails open
    /// and allows all events through to preserve observability.
    ///
    /// # Performance
    /// This method is designed for the hot path:
    /// - Fast hash lookup in sharded map
    /// - Lock-free atomic operations where possible
    /// - No allocations in common case
    pub fn check_event(&self, signature: EventSignature) -> LimitDecision {
        self.check_event_inner(signature, None, false).0
    }

    /// Process an event and, when the policy treats an `Allow` as the end of a
    /// suppression episode, return a summary of the suppressions that have not
    /// yet been reported.
    ///
    /// The returned summary's suppressions are marked as reported, so the
    /// periodic emitter will not report them again. The caller is responsible
    /// for actually emitting the summary.
    pub fn check_event_with_summary(
        &self,
        signature: EventSignature,
    ) -> (LimitDecision, Option<SuppressionSummary>) {
        self.check_event_inner(signature, None, true)
    }

    /// Process an event with metadata and decide whether to allow or suppress it.
    ///
    /// This method captures event metadata on first occurrence for human-readable summaries.
    ///
    /// **Note:** Only available with the `human-readable` feature flag.
    ///
    /// # Arguments
    /// * `signature` - The event signature
    /// * `metadata` - Event details (level, message, target, fields)
    ///
    /// # Returns
    /// A `LimitDecision` indicating whether to allow or suppress the event.
    ///
    /// # Fail-Safe Behavior
    /// Same as `check_event`: fails open if rate limiting operations fail.
    #[cfg(feature = "human-readable")]
    pub fn check_event_with_metadata(
        &self,
        signature: EventSignature,
        metadata: EventMetadata,
    ) -> LimitDecision {
        self.check_event_inner(signature, Some(metadata), false).0
    }

    /// Like [`check_event_with_summary`](Self::check_event_with_summary), but
    /// also captures event metadata on first occurrence.
    ///
    /// **Note:** Only available with the `human-readable` feature flag.
    #[cfg(feature = "human-readable")]
    pub fn check_event_with_metadata_and_summary(
        &self,
        signature: EventSignature,
        metadata: EventMetadata,
    ) -> (LimitDecision, Option<SuppressionSummary>) {
        self.check_event_inner(signature, Some(metadata), true)
    }

    /// Shared implementation for all check variants.
    ///
    /// `close_episode` controls whether an episode-ending `Allow` claims the
    /// unreported suppressions and returns them as a summary. Variants that
    /// discard the summary must pass `false` so unreported suppressions stay
    /// available to the periodic emitter.
    fn check_event_inner(
        &self,
        signature: EventSignature,
        metadata: Option<EventMetadata>,
        close_episode: bool,
    ) -> (LimitDecision, Option<SuppressionSummary>) {
        #[cfg(not(feature = "human-readable"))]
        let _ = metadata;

        // Check circuit breaker state
        if !self.circuit_breaker.allow_request() {
            // Circuit is open, fail open (allow all events)
            self.metrics.record_allowed();
            return (LimitDecision::Allow, None);
        }

        // Attempt rate limiting operation with panic protection
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            self.registry.with_event_state(signature, |state, now| {
                // Capture metadata on first occurrence
                #[cfg(feature = "human-readable")]
                if let Some(metadata) = metadata {
                    state.set_metadata(metadata);
                }

                // Ask the policy whether to allow this event
                let decision = state.policy.register_event(now);

                match decision {
                    PolicyDecision::Allow => {
                        let episode = if close_episode && state.policy.allow_ends_episode() {
                            state.counter.claim_unreported().map(|unreported| {
                                #[cfg(feature = "human-readable")]
                                let metadata = state.metadata.clone();
                                #[cfg(not(feature = "human-readable"))]
                                let metadata = None;

                                SuppressionSummary::from_unreported(signature, unreported, metadata)
                            })
                        } else {
                            None
                        };
                        (LimitDecision::Allow, episode)
                    }
                    PolicyDecision::Suppress => {
                        // Record the suppression
                        state.counter.record_suppression(now);
                        (LimitDecision::Suppress, None)
                    }
                }
            })
        }));

        let (decision, episode) = match result {
            Ok(outcome) => {
                // Operation succeeded
                self.circuit_breaker.record_success();
                outcome
            }
            Err(_) => {
                // Operation panicked, record failure and fail open
                self.circuit_breaker.record_failure();
                (LimitDecision::Allow, None)
            }
        };

        // Record metrics
        match decision {
            LimitDecision::Allow => self.metrics.record_allowed(),
            LimitDecision::Suppress => self.metrics.record_suppressed(),
        }

        (decision, episode)
    }

    /// Get a reference to the registry.
    pub fn registry(&self) -> &SuppressionRegistry<S> {
        &self.registry
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Get a reference to the circuit breaker.
    pub fn circuit_breaker(&self) -> &Arc<CircuitBreaker> {
        &self.circuit_breaker
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::circuit_breaker::CircuitBreakerConfig;
    use crate::domain::policy::Policy;
    use crate::infrastructure::clock::SystemClock;
    use crate::infrastructure::mocks::MockClock;
    use crate::infrastructure::storage::ShardedStorage;
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn test_rate_limiter_basic() {
        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(2).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let limiter = RateLimiter::new(registry, Metrics::new(), Arc::new(CircuitBreaker::new()));

        let sig = EventSignature::simple("INFO", "Test message");

        // First two events allowed
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);

        // Third and beyond suppressed
        assert_eq!(limiter.check_event(sig), LimitDecision::Suppress);
        assert_eq!(limiter.check_event(sig), LimitDecision::Suppress);
    }

    #[test]
    fn test_rate_limiter_with_mock_clock() {
        use std::time::Duration;

        let storage = Arc::new(ShardedStorage::new());
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let policy = Policy::time_window(2, Duration::from_secs(60)).unwrap();
        let registry = SuppressionRegistry::new(storage, mock_clock.clone(), policy);
        let limiter = RateLimiter::new(registry, Metrics::new(), Arc::new(CircuitBreaker::new()));

        let sig = EventSignature::simple("INFO", "Test");

        // First 2 allowed
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);

        // 3rd suppressed
        assert_eq!(limiter.check_event(sig), LimitDecision::Suppress);

        // Advance time by 61 seconds
        mock_clock.advance(Duration::from_secs(61));

        // Should allow again
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);
    }

    #[test]
    fn test_rate_limiter_different_signatures() {
        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(1).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let limiter = RateLimiter::new(registry, Metrics::new(), Arc::new(CircuitBreaker::new()));

        let sig1 = EventSignature::simple("INFO", "Message 1");
        let sig2 = EventSignature::simple("INFO", "Message 2");

        // Each signature has independent limits
        assert_eq!(limiter.check_event(sig1), LimitDecision::Allow);
        assert_eq!(limiter.check_event(sig2), LimitDecision::Allow);

        assert_eq!(limiter.check_event(sig1), LimitDecision::Suppress);
        assert_eq!(limiter.check_event(sig2), LimitDecision::Suppress);
    }

    #[test]
    fn test_rate_limiter_suppression_counting() {
        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(1).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let limiter = RateLimiter::new(
            registry.clone(),
            Metrics::new(),
            Arc::new(CircuitBreaker::new()),
        );

        let sig = EventSignature::simple("INFO", "Test");

        // Allow first
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);

        // Suppress next 3
        assert_eq!(limiter.check_event(sig), LimitDecision::Suppress);
        assert_eq!(limiter.check_event(sig), LimitDecision::Suppress);
        assert_eq!(limiter.check_event(sig), LimitDecision::Suppress);

        // Check counter - 3 suppressions recorded
        registry.with_event_state(sig, |state, _now| {
            assert_eq!(state.counter.count(), 3);
        });
    }

    #[test]
    fn test_concurrent_rate_limiting() {
        use std::thread;

        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(50).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let limiter = Arc::new(RateLimiter::new(
            registry,
            Metrics::new(),
            Arc::new(CircuitBreaker::new()),
        ));

        let sig = EventSignature::simple("INFO", "Concurrent test");
        let mut handles = vec![];

        for _ in 0..10 {
            let limiter_clone = Arc::clone(&limiter);
            let handle = thread::spawn(move || {
                let mut allowed = 0;
                let mut suppressed = 0;

                for _ in 0..20 {
                    match limiter_clone.check_event(sig) {
                        LimitDecision::Allow => allowed += 1,
                        LimitDecision::Suppress => suppressed += 1,
                    }
                }

                (allowed, suppressed)
            });
            handles.push(handle);
        }

        let mut total_allowed = 0;
        let mut total_suppressed = 0;

        for handle in handles {
            let (allowed, suppressed) = handle.join().unwrap();
            total_allowed += allowed;
            total_suppressed += suppressed;
        }

        // Total events = 10 threads * 20 events = 200
        assert_eq!(total_allowed + total_suppressed, 200);

        // Should have allowed at most 50 (policy limit)
        assert!(total_allowed <= 50);

        // Should have suppressed the rest
        assert!(total_suppressed >= 150);
    }

    #[test]
    fn test_time_window_allow_closes_episode() {
        use std::time::Duration;

        let storage = Arc::new(ShardedStorage::new());
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let policy = Policy::time_window(1, Duration::from_secs(60)).unwrap();
        let registry = SuppressionRegistry::new(storage, mock_clock.clone(), policy);
        let limiter = RateLimiter::new(registry, Metrics::new(), Arc::new(CircuitBreaker::new()));

        let sig = EventSignature::simple("INFO", "Test");

        // 1 allowed, 9 suppressed
        assert_eq!(
            limiter.check_event_with_summary(sig).0,
            LimitDecision::Allow
        );
        for _ in 0..9 {
            assert_eq!(
                limiter.check_event_with_summary(sig).0,
                LimitDecision::Suppress
            );
        }

        // Window rolls over: the next Allow closes the episode
        mock_clock.advance(Duration::from_secs(61));
        let (decision, episode) = limiter.check_event_with_summary(sig);
        assert_eq!(decision, LimitDecision::Allow);
        let summary = episode.expect("episode summary expected");
        assert_eq!(summary.count, 9);

        // A new window without suppressions yields no episode summary
        mock_clock.advance(Duration::from_secs(61));
        let (decision, episode) = limiter.check_event_with_summary(sig);
        assert_eq!(decision, LimitDecision::Allow);
        assert!(episode.is_none());
    }

    #[test]
    fn test_token_bucket_allow_does_not_close_episode() {
        use std::time::Duration;

        let storage = Arc::new(ShardedStorage::new());
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let policy = Policy::token_bucket(1.0, 1.0).unwrap();
        let registry = SuppressionRegistry::new(storage, mock_clock.clone(), policy);
        let limiter = RateLimiter::new(
            registry.clone(),
            Metrics::new(),
            Arc::new(CircuitBreaker::new()),
        );

        let sig = EventSignature::simple("INFO", "Test");

        assert_eq!(
            limiter.check_event_with_summary(sig).0,
            LimitDecision::Allow
        );
        for _ in 0..5 {
            assert_eq!(
                limiter.check_event_with_summary(sig).0,
                LimitDecision::Suppress
            );
        }

        // Refill a token: allows and suppressions interleave under sustained
        // load, so an Allow must not claim the suppressions
        mock_clock.advance(Duration::from_secs(1));
        let (decision, episode) = limiter.check_event_with_summary(sig);
        assert_eq!(decision, LimitDecision::Allow);
        assert!(episode.is_none());

        // The suppressions stay available for the periodic emitter
        registry.with_event_state(sig, |state, _| {
            assert_eq!(state.counter.count(), 5);
            assert_eq!(state.counter.reported(), 0);
        });
    }

    #[test]
    fn test_check_event_does_not_claim_episode() {
        use std::time::Duration;

        let storage = Arc::new(ShardedStorage::new());
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let policy = Policy::time_window(1, Duration::from_secs(60)).unwrap();
        let registry = SuppressionRegistry::new(storage, mock_clock.clone(), policy);
        let limiter = RateLimiter::new(
            registry.clone(),
            Metrics::new(),
            Arc::new(CircuitBreaker::new()),
        );

        let sig = EventSignature::simple("INFO", "Test");

        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);
        for _ in 0..3 {
            limiter.check_event(sig);
        }

        // check_event discards no suppressions: they remain unreported
        mock_clock.advance(Duration::from_secs(61));
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);
        registry.with_event_state(sig, |state, _| {
            assert_eq!(state.counter.reported(), 0);
            assert_eq!(state.counter.count(), 3);
        });
    }

    #[test]
    fn test_fail_open_when_circuit_breaker_open() {
        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(1).unwrap(); // Very restrictive
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let cb = Arc::new(CircuitBreaker::new());
        let limiter = RateLimiter::new(registry, Metrics::new(), cb.clone());

        let sig = EventSignature::simple("ERROR", "Critical failure");

        // First event allowed
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);

        // Open circuit breaker by recording many failures
        for _ in 0..10 {
            cb.record_failure();
        }
        assert!(!cb.allow_request(), "Circuit breaker should be open");

        // Even though policy would suppress (count exceeded),
        // circuit breaker being open causes fail-open behavior
        let decision = limiter.check_event(sig);
        assert_eq!(
            decision,
            LimitDecision::Allow,
            "Should fail open when circuit breaker is open"
        );

        // Verify metrics recorded as allowed
        assert_eq!(limiter.metrics().events_allowed(), 2);
    }

    #[test]
    fn test_fail_open_updates_metrics() {
        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(1).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let cb = Arc::new(CircuitBreaker::new());
        let limiter = RateLimiter::new(registry, Metrics::new(), cb.clone());

        let sig = EventSignature::simple("ERROR", "Test");

        // Open the circuit breaker
        for _ in 0..10 {
            cb.record_failure();
        }

        // Process multiple events while circuit is open
        for _ in 0..5 {
            limiter.check_event(sig);
        }

        // All should be recorded as allowed (fail-open)
        assert_eq!(limiter.metrics().events_allowed(), 5);
        assert_eq!(limiter.metrics().events_suppressed(), 0);
    }

    #[test]
    fn test_circuit_breaker_half_open_allows_some_requests() {
        use std::time::Duration;

        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(1).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let cb = Arc::new(CircuitBreaker::with_config(CircuitBreakerConfig {
            failure_threshold: 5,
            recovery_timeout: Duration::from_millis(10),
        }));
        let limiter = RateLimiter::new(registry, Metrics::new(), cb.clone());

        let sig = EventSignature::simple("ERROR", "Test");

        // Open circuit breaker
        for _ in 0..10 {
            cb.record_failure();
        }

        // Wait for recovery timeout
        std::thread::sleep(Duration::from_millis(20));

        // Circuit should now be half-open
        // First request should be allowed through for testing
        let decision = limiter.check_event(sig);
        assert_eq!(decision, LimitDecision::Allow);

        // Since the operation succeeded, circuit breaker records success
        assert_eq!(cb.consecutive_failures(), 0);
    }

    #[test]
    fn test_normal_operation_after_circuit_breaker_closes() {
        use std::time::Duration;

        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(2).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let cb = Arc::new(CircuitBreaker::with_config(CircuitBreakerConfig {
            failure_threshold: 5,
            recovery_timeout: Duration::from_millis(10),
        }));
        let limiter = RateLimiter::new(registry, Metrics::new(), cb.clone());

        let sig = EventSignature::simple("INFO", "Test");

        // Open circuit breaker
        for _ in 0..10 {
            cb.record_failure();
        }

        // Wait for recovery
        std::thread::sleep(Duration::from_millis(20));

        // Process events - should allow and record success
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);

        // Circuit breaker should be closed now
        assert_eq!(cb.consecutive_failures(), 0);

        // Normal rate limiting should work again
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);
        assert_eq!(limiter.check_event(sig), LimitDecision::Suppress);
    }

    #[test]
    fn test_successful_operations_record_success_to_circuit_breaker() {
        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(10).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let cb = Arc::new(CircuitBreaker::new());
        let limiter = RateLimiter::new(registry, Metrics::new(), cb.clone());

        let sig = EventSignature::simple("INFO", "Test");

        // Process events successfully
        for _ in 0..5 {
            limiter.check_event(sig);
        }

        // Circuit breaker should have no failures recorded
        assert_eq!(cb.consecutive_failures(), 0);
    }

    #[test]
    fn test_concurrent_fail_open_behavior() {
        use std::thread;

        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(5).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let cb = Arc::new(CircuitBreaker::new());
        let limiter = Arc::new(RateLimiter::new(registry, Metrics::new(), cb.clone()));

        // Open circuit breaker
        for _ in 0..10 {
            cb.record_failure();
        }

        let sig = EventSignature::simple("ERROR", "Concurrent fail-open test");
        let mut handles = vec![];

        // Spawn multiple threads checking events while circuit is open
        for _ in 0..5 {
            let limiter_clone = Arc::clone(&limiter);
            let handle = thread::spawn(move || {
                let mut all_allowed = true;
                for _ in 0..10 {
                    if limiter_clone.check_event(sig) != LimitDecision::Allow {
                        all_allowed = false;
                    }
                }
                all_allowed
            });
            handles.push(handle);
        }

        // All threads should see only Allow decisions (fail-open)
        for handle in handles {
            assert!(
                handle.join().unwrap(),
                "All events should be allowed when circuit is open"
            );
        }

        // Total events = 5 threads * 10 events = 50
        // All should be allowed (fail-open)
        assert_eq!(limiter.metrics().events_allowed(), 50);
        assert_eq!(limiter.metrics().events_suppressed(), 0);
    }

    #[test]
    fn test_metrics_consistency_during_fail_open() {
        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(2).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let cb = Arc::new(CircuitBreaker::new());
        let limiter = RateLimiter::new(registry, Metrics::new(), cb.clone());

        let sig = EventSignature::simple("INFO", "Test");

        // Normal operation
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow); // 1 allowed
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow); // 2 allowed
        assert_eq!(limiter.check_event(sig), LimitDecision::Suppress); // 1 suppressed

        // Open circuit breaker
        for _ in 0..10 {
            cb.record_failure();
        }

        // Fail-open events
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow); // 3 allowed

        // Verify metrics are consistent
        let snapshot = limiter.metrics().snapshot();
        assert_eq!(snapshot.events_allowed, 3);
        assert_eq!(snapshot.events_suppressed, 1);
        assert_eq!(snapshot.total_events(), 4);
    }

    #[test]
    fn test_registry_state_unaffected_by_circuit_breaker() {
        let storage = Arc::new(ShardedStorage::new());
        let clock = Arc::new(SystemClock::new());
        let policy = Policy::count_based(1).unwrap();
        let registry = SuppressionRegistry::new(storage, clock, policy);
        let cb = Arc::new(CircuitBreaker::new());
        let limiter = RateLimiter::new(registry.clone(), Metrics::new(), cb.clone());

        let sig = EventSignature::simple("INFO", "Test");

        // Allow first event, establish state
        assert_eq!(limiter.check_event(sig), LimitDecision::Allow);

        // Verify state exists
        let initial_count = registry.with_event_state(sig, |state, _| state.counter.count());
        assert_eq!(initial_count, 0);

        // Open circuit breaker
        for _ in 0..10 {
            cb.record_failure();
        }

        // Process events while circuit is open (fail-open)
        for _ in 0..5 {
            limiter.check_event(sig);
        }

        // Registry state should NOT be modified during fail-open
        // (circuit breaker short-circuits before registry access)
        let final_count = registry.with_event_state(sig, |state, _| state.counter.count());
        assert_eq!(
            final_count, initial_count,
            "Registry state should not change during fail-open"
        );
    }
}
