//! Composable credential decay model.
//!
//! Credentials carry a `DecayConfig` from birth that defines how they age and expire.
//! All mechanisms are optional — omit a field to not use that mechanism.
//!
//! Supported mechanisms:
//! - **TTL**: Hard expiration after N seconds from issuance
//! - **Use count**: Max total presentations before exhaustion
//! - **Rate limit**: Max presentations per time window with optional grace
//! - **Multi-phasic**: Ordered phase transitions that tighten or terminate based on age or usage
//!
//! Decay is checked at presentation time via `check_decay()`. Exhausted credentials
//! auto-transition to Expired or Revoked.

use crate::error::{CredError, CredErrorDetail, CredResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DecayConfig — composable, all-optional
// ---------------------------------------------------------------------------

/// Composable decay configuration. All fields are optional.
/// Omit a mechanism to not use it. Combine freely.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecayConfig {
    /// Hard TTL: credential dies after this many seconds from issued_at.
    pub ttl: Option<TtlDecay>,
    /// Max total uses across the credential's lifetime.
    pub use_count: Option<UseCountDecay>,
    /// Rate limiting: max presentations per time window.
    pub rate_limit: Option<RateLimitDecay>,
    /// Ordered phase transitions. Evaluated in sequence by trigger condition.
    #[serde(default)]
    pub phases: Vec<DecayPhase>,
}

/// Hard TTL decay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TtlDecay {
    /// Seconds from issued_at until the credential expires.
    pub expires_after_seconds: u64,
}

/// Use count decay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UseCountDecay {
    /// Maximum total presentations before exhaustion.
    pub max_uses: u64,
}

/// Rate limit decay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RateLimitDecay {
    /// Maximum presentations per window.
    pub max_per_window: u64,
    /// Window duration in seconds.
    pub window_seconds: u64,
    /// Grace uses beyond max_per_window before auto-revoke.
    /// e.g., max_per_window=5, grace=2 means uses 6 and 7 are warnings,
    /// use 8 triggers revocation.
    pub grace: u64,
}

/// A phase transition triggered by age or cumulative usage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecayPhase {
    /// When this phase activates.
    pub trigger: PhaseTrigger,
    /// What happens when the phase activates.
    pub effect: PhaseEffect,
}

/// What triggers a phase transition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PhaseTrigger {
    /// Activates when credential age exceeds this many seconds.
    AgeSeconds(u64),
    /// Activates when total uses exceed this count.
    TotalUses(u64),
}

/// What happens when a phase triggers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PhaseEffect {
    /// Override the current rate limit with tighter parameters.
    TightenRateLimit {
        max_per_window: u64,
        window_seconds: u64,
        grace: u64,
    },
    /// Expire the credential (terminal).
    Expire,
    /// Revoke the credential (terminal).
    Revoke,
}

// ---------------------------------------------------------------------------
// DecayState — runtime state tracked per credential
// ---------------------------------------------------------------------------

/// Runtime decay state, stored alongside the credential record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecayState {
    /// Total presentations across the credential's lifetime.
    pub total_uses: u64,
    /// Presentations in the current rate-limit window.
    pub window_uses: u64,
    /// Start of the current rate-limit window (RFC 3339).
    pub window_start: String,
    /// Index of the highest activated phase (0 = no phase activated yet).
    pub current_phase_index: usize,
}

impl DecayState {
    /// Create initial decay state.
    pub fn new(now: &str) -> Self {
        Self {
            total_uses: 0,
            window_uses: 0,
            window_start: now.to_string(),
            current_phase_index: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DecayVerdict — result of checking decay
// ---------------------------------------------------------------------------

/// Result of checking a credential's decay status.
#[derive(Debug, Clone, PartialEq)]
pub enum DecayVerdict {
    /// Credential is alive, proceed with presentation.
    Alive,
    /// Credential is exhausted (terminal).
    Exhausted(ExhaustionReason),
    /// A phase transition occurred, tightening limits. Credential is still alive.
    PhaseTransition {
        new_phase: usize,
    },
}

/// Why a credential was exhausted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExhaustionReason {
    TtlExpired,
    UsesExhausted,
    RateLimitExceeded,
    PhaseTerminal,
}

impl std::fmt::Display for ExhaustionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TtlExpired => write!(f, "TTL expired"),
            Self::UsesExhausted => write!(f, "use count exhausted"),
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::PhaseTerminal => write!(f, "terminal phase reached"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Parse an RFC 3339 timestamp, returning a CredResult.
fn parse_timestamp(s: &str) -> CredResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| {
            CredErrorDetail::new(
                CredError::DecodingFailed,
                format!("invalid RFC 3339 timestamp: {}", s),
            )
        })
}

/// Check whether a credential has decayed past its limits.
///
/// Call this before each presentation. If the verdict is `Exhausted`,
/// the credential should transition to a terminal state.
pub fn check_decay(
    config: &DecayConfig,
    state: &DecayState,
    issued_at: &str,
    now: &str,
) -> CredResult<DecayVerdict> {
    let issued = parse_timestamp(issued_at)?;
    let current = parse_timestamp(now)?;
    let age_seconds = (current - issued).num_seconds().max(0) as u64;

    // 1. Check TTL
    if let Some(ref ttl) = config.ttl {
        if age_seconds >= ttl.expires_after_seconds {
            return Ok(DecayVerdict::Exhausted(ExhaustionReason::TtlExpired));
        }
    }

    // 2. Check use count
    if let Some(ref use_count) = config.use_count {
        if state.total_uses >= use_count.max_uses {
            return Ok(DecayVerdict::Exhausted(ExhaustionReason::UsesExhausted));
        }
    }

    // 3. Evaluate phases (in order) to find the current active phase
    let mut active_phase_idx = 0;
    for (i, phase) in config.phases.iter().enumerate() {
        let triggered = match phase.trigger {
            PhaseTrigger::AgeSeconds(threshold) => age_seconds >= threshold,
            PhaseTrigger::TotalUses(threshold) => state.total_uses >= threshold,
        };
        if triggered {
            active_phase_idx = i + 1; // 1-indexed so 0 means "no phase"
        }
    }

    // Check if a newly activated phase is terminal
    if active_phase_idx > state.current_phase_index {
        let phase = &config.phases[active_phase_idx - 1];
        match &phase.effect {
            PhaseEffect::Expire | PhaseEffect::Revoke => {
                return Ok(DecayVerdict::Exhausted(ExhaustionReason::PhaseTerminal));
            }
            PhaseEffect::TightenRateLimit { .. } => {
                return Ok(DecayVerdict::PhaseTransition {
                    new_phase: active_phase_idx,
                });
            }
        }
    }

    // 4. Check rate limit (using effective rate limit from current phase or config default)
    let effective_rate_limit = get_effective_rate_limit(config, state);
    if let Some(rl) = effective_rate_limit {
        let window_start = parse_timestamp(&state.window_start)?;
        let window_elapsed = (current - window_start).num_seconds().max(0) as u64;

        // If we're still in the current window
        if window_elapsed < rl.window_seconds {
            let total_allowed = rl.max_per_window + rl.grace;
            if state.window_uses >= total_allowed {
                return Ok(DecayVerdict::Exhausted(ExhaustionReason::RateLimitExceeded));
            }
        }
        // If window has elapsed, the window resets in record_use — allow the presentation
    }

    Ok(DecayVerdict::Alive)
}

/// Get the effective rate limit, considering phase overrides.
fn get_effective_rate_limit(
    config: &DecayConfig,
    state: &DecayState,
) -> Option<RateLimitDecay> {
    // Check if the current phase overrides rate limiting
    if state.current_phase_index > 0 {
        let phase = &config.phases[state.current_phase_index - 1];
        if let PhaseEffect::TightenRateLimit {
            max_per_window,
            window_seconds,
            grace,
        } = &phase.effect
        {
            return Some(RateLimitDecay {
                max_per_window: *max_per_window,
                window_seconds: *window_seconds,
                grace: *grace,
            });
        }
    }
    config.rate_limit.clone()
}

/// Record a credential use, updating the decay state.
///
/// Call this after a successful presentation. Updates total_uses,
/// window_uses, and resets the window if it has elapsed.
pub fn record_use(
    state: &mut DecayState,
    config: &DecayConfig,
    now: &str,
) -> CredResult<()> {
    let current = parse_timestamp(now)?;

    state.total_uses += 1;

    // Update rate limit window
    let effective_rl = get_effective_rate_limit(config, state);
    if let Some(rl) = effective_rl {
        let window_start = parse_timestamp(&state.window_start)?;
        let window_elapsed = (current - window_start).num_seconds().max(0) as u64;

        if window_elapsed >= rl.window_seconds {
            // Window has elapsed, start a new one
            state.window_uses = 1;
            state.window_start = now.to_string();
        } else {
            state.window_uses += 1;
        }
    } else {
        // No rate limit, just track uses
        state.window_uses += 1;
    }

    Ok(())
}

/// Apply a phase transition to the decay state.
pub fn apply_phase_transition(state: &mut DecayState, new_phase: usize, now: &str) {
    state.current_phase_index = new_phase;
    // Reset window on phase transition so the new rate limit starts fresh
    state.window_uses = 0;
    state.window_start = now.to_string();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(offset_seconds: i64) -> String {
        let base = DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let dt = base + chrono::Duration::seconds(offset_seconds);
        dt.to_rfc3339()
    }

    // --- TTL tests ---

    #[test]
    fn test_ttl_alive_before_expiry() {
        let config = DecayConfig {
            ttl: Some(TtlDecay {
                expires_after_seconds: 3600,
            }),
            use_count: None,
            rate_limit: None,
            phases: vec![],
        };
        let state = DecayState::new(&ts(0));
        let verdict = check_decay(&config, &state, &ts(0), &ts(3599)).unwrap();
        assert_eq!(verdict, DecayVerdict::Alive);
    }

    #[test]
    fn test_ttl_expired_at_boundary() {
        let config = DecayConfig {
            ttl: Some(TtlDecay {
                expires_after_seconds: 3600,
            }),
            use_count: None,
            rate_limit: None,
            phases: vec![],
        };
        let state = DecayState::new(&ts(0));
        let verdict = check_decay(&config, &state, &ts(0), &ts(3600)).unwrap();
        assert_eq!(
            verdict,
            DecayVerdict::Exhausted(ExhaustionReason::TtlExpired)
        );
    }

    #[test]
    fn test_ttl_expired_after_boundary() {
        let config = DecayConfig {
            ttl: Some(TtlDecay {
                expires_after_seconds: 3600,
            }),
            use_count: None,
            rate_limit: None,
            phases: vec![],
        };
        let state = DecayState::new(&ts(0));
        let verdict = check_decay(&config, &state, &ts(0), &ts(3601)).unwrap();
        assert_eq!(
            verdict,
            DecayVerdict::Exhausted(ExhaustionReason::TtlExpired)
        );
    }

    // --- Use count tests ---

    #[test]
    fn test_use_count_alive_under_limit() {
        let config = DecayConfig {
            ttl: None,
            use_count: Some(UseCountDecay { max_uses: 5 }),
            rate_limit: None,
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.total_uses = 4;
        let verdict = check_decay(&config, &state, &ts(0), &ts(100)).unwrap();
        assert_eq!(verdict, DecayVerdict::Alive);
    }

    #[test]
    fn test_use_count_exhausted_at_limit() {
        let config = DecayConfig {
            ttl: None,
            use_count: Some(UseCountDecay { max_uses: 5 }),
            rate_limit: None,
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.total_uses = 5;
        let verdict = check_decay(&config, &state, &ts(0), &ts(100)).unwrap();
        assert_eq!(
            verdict,
            DecayVerdict::Exhausted(ExhaustionReason::UsesExhausted)
        );
    }

    // --- Rate limit tests ---

    #[test]
    fn test_rate_limit_within_window() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: Some(RateLimitDecay {
                max_per_window: 5,
                window_seconds: 86400,
                grace: 0,
            }),
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.window_uses = 4;
        let verdict = check_decay(&config, &state, &ts(0), &ts(100)).unwrap();
        assert_eq!(verdict, DecayVerdict::Alive);
    }

    #[test]
    fn test_rate_limit_exceeded_no_grace() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: Some(RateLimitDecay {
                max_per_window: 5,
                window_seconds: 86400,
                grace: 0,
            }),
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.window_uses = 5;
        let verdict = check_decay(&config, &state, &ts(0), &ts(100)).unwrap();
        assert_eq!(
            verdict,
            DecayVerdict::Exhausted(ExhaustionReason::RateLimitExceeded)
        );
    }

    #[test]
    fn test_rate_limit_within_grace() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: Some(RateLimitDecay {
                max_per_window: 5,
                window_seconds: 86400,
                grace: 2,
            }),
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.window_uses = 6; // max(5) + 1 grace use
        let verdict = check_decay(&config, &state, &ts(0), &ts(100)).unwrap();
        assert_eq!(verdict, DecayVerdict::Alive);
    }

    #[test]
    fn test_rate_limit_grace_exceeded() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: Some(RateLimitDecay {
                max_per_window: 5,
                window_seconds: 86400,
                grace: 2,
            }),
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.window_uses = 7; // max(5) + grace(2) = 7 allowed, 7 = exceeded
        let verdict = check_decay(&config, &state, &ts(0), &ts(100)).unwrap();
        assert_eq!(
            verdict,
            DecayVerdict::Exhausted(ExhaustionReason::RateLimitExceeded)
        );
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: Some(RateLimitDecay {
                max_per_window: 5,
                window_seconds: 86400,
                grace: 0,
            }),
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.window_uses = 10; // way over limit
        // But the window has elapsed (86400 seconds later)
        let verdict = check_decay(&config, &state, &ts(0), &ts(86400)).unwrap();
        assert_eq!(verdict, DecayVerdict::Alive);
    }

    // --- Multi-phasic tests ---

    #[test]
    fn test_phase_transition_tightens_limits() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: None,
            phases: vec![DecayPhase {
                trigger: PhaseTrigger::AgeSeconds(10 * 86400), // day 10
                effect: PhaseEffect::TightenRateLimit {
                    max_per_window: 5,
                    window_seconds: 86400,
                    grace: 2,
                },
            }],
        };
        let state = DecayState::new(&ts(0));
        // At day 10
        let verdict = check_decay(&config, &state, &ts(0), &ts(10 * 86400)).unwrap();
        assert_eq!(verdict, DecayVerdict::PhaseTransition { new_phase: 1 });
    }

    #[test]
    fn test_phase_transition_terminal_expire() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: None,
            phases: vec![DecayPhase {
                trigger: PhaseTrigger::AgeSeconds(120 * 86400),
                effect: PhaseEffect::Expire,
            }],
        };
        let state = DecayState::new(&ts(0));
        let verdict = check_decay(&config, &state, &ts(0), &ts(120 * 86400)).unwrap();
        assert_eq!(
            verdict,
            DecayVerdict::Exhausted(ExhaustionReason::PhaseTerminal)
        );
    }

    #[test]
    fn test_phase_transition_terminal_revoke() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: None,
            phases: vec![DecayPhase {
                trigger: PhaseTrigger::TotalUses(100),
                effect: PhaseEffect::Revoke,
            }],
        };
        let mut state = DecayState::new(&ts(0));
        state.total_uses = 100;
        let verdict = check_decay(&config, &state, &ts(0), &ts(1000)).unwrap();
        assert_eq!(
            verdict,
            DecayVerdict::Exhausted(ExhaustionReason::PhaseTerminal)
        );
    }

    #[test]
    fn test_phase_already_activated_no_repeat() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: None,
            phases: vec![DecayPhase {
                trigger: PhaseTrigger::AgeSeconds(10 * 86400),
                effect: PhaseEffect::TightenRateLimit {
                    max_per_window: 5,
                    window_seconds: 86400,
                    grace: 2,
                },
            }],
        };
        let mut state = DecayState::new(&ts(0));
        state.current_phase_index = 1; // already in phase 1
        let verdict = check_decay(&config, &state, &ts(0), &ts(15 * 86400)).unwrap();
        assert_eq!(verdict, DecayVerdict::Alive);
    }

    // --- Empty config ---

    #[test]
    fn test_empty_config_always_alive() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: None,
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.total_uses = 1_000_000;
        let verdict = check_decay(&config, &state, &ts(0), &ts(999_999_999)).unwrap();
        assert_eq!(verdict, DecayVerdict::Alive);
    }

    // --- record_use tests ---

    #[test]
    fn test_record_use_increments_total() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: None,
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        record_use(&mut state, &config, &ts(100)).unwrap();
        assert_eq!(state.total_uses, 1);
        record_use(&mut state, &config, &ts(200)).unwrap();
        assert_eq!(state.total_uses, 2);
    }

    #[test]
    fn test_record_use_resets_window() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: Some(RateLimitDecay {
                max_per_window: 5,
                window_seconds: 3600,
                grace: 0,
            }),
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        state.window_uses = 4;
        // After window elapsed
        record_use(&mut state, &config, &ts(3600)).unwrap();
        assert_eq!(state.window_uses, 1); // reset + 1 new use
        assert_eq!(state.total_uses, 1);
    }

    #[test]
    fn test_record_use_within_window() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: Some(RateLimitDecay {
                max_per_window: 5,
                window_seconds: 3600,
                grace: 0,
            }),
            phases: vec![],
        };
        let mut state = DecayState::new(&ts(0));
        record_use(&mut state, &config, &ts(100)).unwrap();
        assert_eq!(state.window_uses, 1);
        record_use(&mut state, &config, &ts(200)).unwrap();
        assert_eq!(state.window_uses, 2);
    }

    // --- apply_phase_transition ---

    #[test]
    fn test_apply_phase_transition() {
        let mut state = DecayState::new(&ts(0));
        state.window_uses = 5;
        apply_phase_transition(&mut state, 1, &ts(86400));
        assert_eq!(state.current_phase_index, 1);
        assert_eq!(state.window_uses, 0);
    }

    // --- DecayState serde ---

    #[test]
    fn test_decay_state_serde_roundtrip() {
        let state = DecayState {
            total_uses: 42,
            window_uses: 3,
            window_start: ts(1000),
            current_phase_index: 2,
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: DecayState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }

    // --- DecayConfig serde ---

    #[test]
    fn test_decay_config_serde_roundtrip() {
        let config = DecayConfig {
            ttl: Some(TtlDecay {
                expires_after_seconds: 180 * 86400,
            }),
            use_count: Some(UseCountDecay { max_uses: 1000 }),
            rate_limit: Some(RateLimitDecay {
                max_per_window: 5,
                window_seconds: 86400,
                grace: 2,
            }),
            phases: vec![
                DecayPhase {
                    trigger: PhaseTrigger::AgeSeconds(10 * 86400),
                    effect: PhaseEffect::TightenRateLimit {
                        max_per_window: 5,
                        window_seconds: 86400,
                        grace: 2,
                    },
                },
                DecayPhase {
                    trigger: PhaseTrigger::AgeSeconds(90 * 86400),
                    effect: PhaseEffect::TightenRateLimit {
                        max_per_window: 3,
                        window_seconds: 86400,
                        grace: 0,
                    },
                },
                DecayPhase {
                    trigger: PhaseTrigger::AgeSeconds(120 * 86400),
                    effect: PhaseEffect::Expire,
                },
            ],
        };
        let json = serde_json::to_string(&config).unwrap();
        let restored: DecayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    // --- Multi-phasic integration test (user's example) ---

    #[test]
    fn test_user_multiphase_example() {
        // "Freshly minted, use freely for 10 days. After that, 5/day with 2 grace.
        //  Over that, auto-revoke. At 90 days, tighter. Expire at 120 days."
        let config = DecayConfig {
            ttl: Some(TtlDecay {
                expires_after_seconds: 180 * 86400,
            }),
            use_count: None,
            rate_limit: None, // no rate limit in phase 0
            phases: vec![
                DecayPhase {
                    trigger: PhaseTrigger::AgeSeconds(10 * 86400),
                    effect: PhaseEffect::TightenRateLimit {
                        max_per_window: 5,
                        window_seconds: 86400,
                        grace: 2,
                    },
                },
                DecayPhase {
                    trigger: PhaseTrigger::AgeSeconds(90 * 86400),
                    effect: PhaseEffect::TightenRateLimit {
                        max_per_window: 3,
                        window_seconds: 86400,
                        grace: 0,
                    },
                },
                DecayPhase {
                    trigger: PhaseTrigger::AgeSeconds(120 * 86400),
                    effect: PhaseEffect::Expire,
                },
            ],
        };

        // Day 1: freely usable
        let state = DecayState::new(&ts(0));
        let v = check_decay(&config, &state, &ts(0), &ts(86400)).unwrap();
        assert_eq!(v, DecayVerdict::Alive);

        // Day 10: phase transition to rate-limited
        let v = check_decay(&config, &state, &ts(0), &ts(10 * 86400)).unwrap();
        assert_eq!(v, DecayVerdict::PhaseTransition { new_phase: 1 });

        // Day 15 in phase 1, under limit
        let mut state_p1 = DecayState::new(&ts(0));
        state_p1.current_phase_index = 1;
        state_p1.window_start = ts(15 * 86400);
        state_p1.window_uses = 4;
        let v = check_decay(&config, &state_p1, &ts(0), &ts(15 * 86400 + 100)).unwrap();
        assert_eq!(v, DecayVerdict::Alive);

        // Day 15 in phase 1, grace exceeded (5 + 2 = 7)
        state_p1.window_uses = 7;
        let v = check_decay(&config, &state_p1, &ts(0), &ts(15 * 86400 + 100)).unwrap();
        assert_eq!(
            v,
            DecayVerdict::Exhausted(ExhaustionReason::RateLimitExceeded)
        );

        // Day 90: phase transition to tighter limits
        let mut state_p1_d90 = DecayState::new(&ts(0));
        state_p1_d90.current_phase_index = 1;
        let v = check_decay(&config, &state_p1_d90, &ts(0), &ts(90 * 86400)).unwrap();
        assert_eq!(v, DecayVerdict::PhaseTransition { new_phase: 2 });

        // Day 120: terminal expire
        let mut state_p2 = DecayState::new(&ts(0));
        state_p2.current_phase_index = 2;
        let v = check_decay(&config, &state_p2, &ts(0), &ts(120 * 86400)).unwrap();
        assert_eq!(
            v,
            DecayVerdict::Exhausted(ExhaustionReason::PhaseTerminal)
        );
    }

    // --- ExhaustionReason display ---

    #[test]
    fn test_exhaustion_reason_display() {
        assert_eq!(ExhaustionReason::TtlExpired.to_string(), "TTL expired");
        assert_eq!(
            ExhaustionReason::UsesExhausted.to_string(),
            "use count exhausted"
        );
        assert_eq!(
            ExhaustionReason::RateLimitExceeded.to_string(),
            "rate limit exceeded"
        );
        assert_eq!(
            ExhaustionReason::PhaseTerminal.to_string(),
            "terminal phase reached"
        );
    }

    // --- Combined mechanisms ---

    #[test]
    fn test_ttl_takes_priority_over_alive_use_count() {
        let config = DecayConfig {
            ttl: Some(TtlDecay {
                expires_after_seconds: 100,
            }),
            use_count: Some(UseCountDecay { max_uses: 1000 }),
            rate_limit: None,
            phases: vec![],
        };
        let state = DecayState::new(&ts(0));
        // Uses are fine, but TTL expired
        let verdict = check_decay(&config, &state, &ts(0), &ts(200)).unwrap();
        assert_eq!(
            verdict,
            DecayVerdict::Exhausted(ExhaustionReason::TtlExpired)
        );
    }

    #[test]
    fn test_invalid_timestamp_returns_error() {
        let config = DecayConfig {
            ttl: None,
            use_count: None,
            rate_limit: None,
            phases: vec![],
        };
        let state = DecayState::new("not-a-timestamp");
        let result = check_decay(&config, &state, "also-bad", "still-bad");
        assert!(result.is_err());
    }
}
