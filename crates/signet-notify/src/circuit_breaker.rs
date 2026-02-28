//! Circuit breaker pattern for notification channels.
//!
//! Tracks endpoint health and prevents sending to failing endpoints.
//! Three states: Closed (healthy), Open (failing), HalfOpen (probing).

use signet_core::Timestamp;

use crate::types::{CircuitState, EndpointHealth};

/// Duration in seconds before an Open circuit transitions to HalfOpen
/// to allow a probe request.
const RECOVERY_TIMEOUT_SECONDS: u64 = 60;

/// Circuit breaker for a webhook endpoint.
///
/// Tracks consecutive failures and transitions between states:
/// - Closed: healthy, all requests pass through
/// - Open: unhealthy, requests are rejected immediately
/// - HalfOpen: one probe request is allowed to test recovery
pub struct CircuitBreaker {
    health: EndpointHealth,
    threshold: u32,
    opened_at: Option<Timestamp>,
    recovery_timeout_seconds: u64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given failure threshold.
    pub fn new(threshold: u32) -> Self {
        Self {
            health: EndpointHealth {
                consecutive_failures: 0,
                circuit_state: CircuitState::Closed,
                last_success: None,
                last_failure: None,
                total_deliveries: 0,
                total_failures: 0,
            },
            threshold,
            opened_at: None,
            recovery_timeout_seconds: RECOVERY_TIMEOUT_SECONDS,
        }
    }

    /// Create a circuit breaker with a custom recovery timeout (for testing).
    pub fn with_recovery_timeout(threshold: u32, recovery_timeout_seconds: u64) -> Self {
        Self {
            recovery_timeout_seconds,
            ..Self::new(threshold)
        }
    }

    /// Check if a request should be allowed through.
    ///
    /// Returns true if the circuit is Closed or if it's time for a HalfOpen probe.
    pub fn should_allow(&mut self) -> bool {
        match self.health.circuit_state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if recovery timeout has elapsed
                if let Some(opened_at) = self.opened_at {
                    let now = Timestamp::now();
                    if now.seconds_since_epoch
                        >= opened_at.seconds_since_epoch + self.recovery_timeout_seconds
                    {
                        self.health.circuit_state = CircuitState::HalfOpen;
                        tracing::info!("Circuit breaker transitioning to HalfOpen");
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful delivery.
    pub fn record_success(&mut self) {
        let now = Timestamp::now();
        self.health.consecutive_failures = 0;
        self.health.last_success = Some(now);
        self.health.total_deliveries += 1;

        match self.health.circuit_state {
            CircuitState::HalfOpen => {
                // Successful probe: close the circuit
                self.health.circuit_state = CircuitState::Closed;
                self.opened_at = None;
                tracing::info!("Circuit breaker closed after successful probe");
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
                self.health.circuit_state = CircuitState::Closed;
                self.opened_at = None;
            }
            CircuitState::Closed => {
                // Normal operation
            }
        }
    }

    /// Record a failed delivery.
    pub fn record_failure(&mut self) {
        let now = Timestamp::now();
        self.health.consecutive_failures += 1;
        self.health.last_failure = Some(now);
        self.health.total_deliveries += 1;
        self.health.total_failures += 1;

        match self.health.circuit_state {
            CircuitState::Closed => {
                if self.health.consecutive_failures >= self.threshold {
                    self.health.circuit_state = CircuitState::Open;
                    self.opened_at = Some(now);
                    tracing::warn!(
                        consecutive_failures = self.health.consecutive_failures,
                        "Circuit breaker opened"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Failed probe: reopen the circuit
                self.health.circuit_state = CircuitState::Open;
                self.opened_at = Some(now);
                tracing::warn!("Circuit breaker reopened after failed probe");
            }
            CircuitState::Open => {
                // Already open, update timestamp
                self.opened_at = Some(now);
            }
        }
    }

    /// Get the current health snapshot.
    pub fn health(&self) -> &EndpointHealth {
        &self.health
    }

    /// Get the current circuit state.
    pub fn state(&self) -> CircuitState {
        self.health.circuit_state
    }

    /// Reset the circuit breaker to Closed state.
    pub fn reset(&mut self) {
        self.health.consecutive_failures = 0;
        self.health.circuit_state = CircuitState::Closed;
        self.opened_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_circuit_breaker_is_closed() {
        let cb = CircuitBreaker::new(3);
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.health().consecutive_failures, 0);
        assert_eq!(cb.health().total_deliveries, 0);
    }

    #[test]
    fn test_closed_allows_requests() {
        let mut cb = CircuitBreaker::new(3);
        assert!(cb.should_allow());
    }

    #[test]
    fn test_failures_below_threshold_stay_closed() {
        let mut cb = CircuitBreaker::new(3);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.should_allow());
    }

    #[test]
    fn test_failures_at_threshold_opens_circuit() {
        let mut cb = CircuitBreaker::new(3);
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.should_allow());
    }

    #[test]
    fn test_success_resets_consecutive_failures() {
        let mut cb = CircuitBreaker::new(3);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.health().consecutive_failures, 0);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_open_blocks_requests() {
        let mut cb = CircuitBreaker::new(1);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.should_allow());
    }

    #[test]
    fn test_half_open_after_recovery_timeout() {
        let mut cb = CircuitBreaker::with_recovery_timeout(1, 0); // immediate recovery
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Recovery timeout is 0 seconds, so should immediately transition
        assert!(cb.should_allow());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_successful_probe_closes_circuit() {
        let mut cb = CircuitBreaker::with_recovery_timeout(1, 0);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Transition to HalfOpen
        cb.should_allow();
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Successful probe
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_failed_probe_reopens_circuit() {
        let mut cb = CircuitBreaker::with_recovery_timeout(1, 0);
        cb.record_failure();

        // Transition to HalfOpen
        cb.should_allow();
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Failed probe
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_reset() {
        let mut cb = CircuitBreaker::new(1);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.health().consecutive_failures, 0);
    }

    #[test]
    fn test_health_tracking() {
        let mut cb = CircuitBreaker::new(5);

        cb.record_success();
        cb.record_success();
        cb.record_failure();
        cb.record_success();

        assert_eq!(cb.health().total_deliveries, 4);
        assert_eq!(cb.health().total_failures, 1);
        assert!(cb.health().last_success.is_some());
        assert!(cb.health().last_failure.is_some());
    }

    #[test]
    fn test_threshold_boundary() {
        // Exactly at threshold-1 should still be closed
        let mut cb = CircuitBreaker::new(5);
        for _ in 0..4 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Closed);

        // One more should open it
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_interleaved_success_resets_count() {
        let mut cb = CircuitBreaker::new(3);
        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // resets count
        cb.record_failure();
        cb.record_failure();
        // Only 2 consecutive failures, not 3
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_half_open_allows_one_request() {
        let mut cb = CircuitBreaker::with_recovery_timeout(1, 0);
        cb.record_failure();

        // Transition to HalfOpen
        assert!(cb.should_allow());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // HalfOpen allows requests
        assert!(cb.should_allow());
    }

    #[test]
    fn test_total_failures_accumulate() {
        let mut cb = CircuitBreaker::new(10);
        for _ in 0..5 {
            cb.record_failure();
            cb.record_success(); // resets consecutive but not total
        }
        assert_eq!(cb.health().total_failures, 5);
        assert_eq!(cb.health().total_deliveries, 10);
        assert_eq!(cb.health().consecutive_failures, 0);
    }
}
