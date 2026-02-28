use hmac::{Hmac, Mac};
use sha2::Sha256;
use signet_core::{ActorId, ConfidenceLevel, PredicateId, Timestamp};
use std::collections::HashMap;

use crate::engine::AuditSink;
use crate::error::{PolicyError, PolicyResult};
use crate::types::{
    PatternDecision, PatternRecord, PolicyAuditEvent, PolicyAuditEventKind, PolicyRule,
    PolicyRuleKind, PolicySuggestion, SensitivityTier, SuggestionThresholds,
};

type HmacSha256 = Hmac<Sha256>;

/// MAC key length required for HMAC-SHA-256.
const MAC_KEY_LEN: usize = 32;

/// In-memory pattern tracker that stores MAC-protected pattern records.
///
/// All entries are MAC-protected using HMAC-SHA-256 with a vault-derived key.
/// Suggestions are suggest-only and never auto-applied.
#[derive(Debug, Default)]
pub struct PatternTracker {
    records: HashMap<(String, String), PatternRecord>,
}

impl PatternTracker {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Record a user's approve/deny decision for an actor+predicate pair.
    ///
    /// Creates a new PatternRecord if none exists, or updates an existing one.
    /// Computes HMAC-SHA-256 MAC over all record fields.
    pub fn record_pattern(
        &mut self,
        actor_id: &ActorId,
        predicate_id: &PredicateId,
        decision: PatternDecision,
        decided_at: Timestamp,
        mac_key: &[u8],
        audit_sink: &dyn AuditSink,
    ) -> PolicyResult<PatternRecord> {
        if mac_key.len() != MAC_KEY_LEN {
            return Err(PolicyError::PatternError(format!(
                "MAC key must be exactly {} bytes, got {}",
                MAC_KEY_LEN,
                mac_key.len()
            )));
        }

        let key = (
            actor_id.as_str().to_string(),
            predicate_id.as_str().to_string(),
        );

        let record = if let Some(existing) = self.records.get(&key) {
            // Verify existing record MAC
            if !verify_mac(existing, mac_key) {
                return Err(PolicyError::MacVerificationFailed);
            }

            let mut updated = existing.clone();
            match decision {
                PatternDecision::Approved => {
                    updated.approve_count = updated.approve_count.saturating_add(1);
                }
                PatternDecision::Denied => {
                    updated.deny_count = updated.deny_count.saturating_add(1);
                }
            }
            updated.last_seen = decided_at;
            updated.mac = compute_mac(&updated, mac_key);
            updated
        } else {
            let (approve_count, deny_count) = match decision {
                PatternDecision::Approved => (1, 0),
                PatternDecision::Denied => (0, 1),
            };
            let mut record = PatternRecord {
                actor_id: actor_id.clone(),
                predicate_id: predicate_id.clone(),
                approve_count,
                deny_count,
                first_seen: decided_at,
                last_seen: decided_at,
                mac: Vec::new(),
            };
            record.mac = compute_mac(&record, mac_key);
            record
        };

        self.records.insert(key, record.clone());

        // Emit audit event
        let audit_event = PolicyAuditEvent {
            event_kind: PolicyAuditEventKind::PatternRecorded,
            timestamp: decided_at,
            actor_id: Some(actor_id.clone()),
            predicate_id: Some(predicate_id.clone()),
            domain_id: None,
            decision_summary: Some(format!(
                "recorded {:?} decision (approvals: {}, denials: {})",
                decision, record.approve_count, record.deny_count
            )),
            policy_version: None,
        };
        audit_sink.emit(&audit_event).map_err(|e| {
            PolicyError::AuditSinkError(format!("failed to emit pattern audit: {}", e))
        })?;

        Ok(record)
    }

    /// Analyze all pattern records and generate policy rule suggestions.
    ///
    /// Returns suggestions for any actor+predicate pairs that exceed the
    /// configured occurrence and ratio thresholds. Verifies MAC on each record.
    pub fn suggest_rules(
        &self,
        thresholds: &SuggestionThresholds,
        mac_key: &[u8],
        audit_sink: &dyn AuditSink,
    ) -> PolicyResult<Vec<PolicySuggestion>> {
        if mac_key.len() != MAC_KEY_LEN {
            return Err(PolicyError::PatternError(format!(
                "MAC key must be exactly {} bytes, got {}",
                MAC_KEY_LEN,
                mac_key.len()
            )));
        }

        let mut suggestions = Vec::new();

        for record in self.records.values() {
            // Verify MAC; skip tampered records
            if !verify_mac(record, mac_key) {
                tracing::warn!(
                    actor_id = record.actor_id.as_str(),
                    predicate_id = record.predicate_id.as_str(),
                    "skipping pattern record with invalid MAC"
                );
                continue;
            }

            let total = record.approve_count + record.deny_count;
            if total < thresholds.min_occurrences {
                continue;
            }

            let approval_pct = if total > 0 {
                (record.approve_count * 100) / total
            } else {
                0
            };
            let denial_pct = if total > 0 {
                (record.deny_count * 100) / total
            } else {
                0
            };

            let suggestion = if approval_pct >= thresholds.approval_ratio_permit as u64 {
                // Suggest an auto-permit rule
                Some(PolicySuggestion {
                    suggested_rule: PolicyRule {
                        rule_id: format!(
                            "auto-permit-{}-{}",
                            record.actor_id.as_str(),
                            record.predicate_id.as_str()
                        ),
                        kind: PolicyRuleKind::ExplicitGrant,
                        actor_pattern: record.actor_id.as_str().to_string(),
                        predicate_pattern: record.predicate_id.as_str().to_string(),
                        minimum_tier: SensitivityTier::Public,
                        domain_constraint: None,
                        valid_from: None,
                        valid_until: None,
                        priority: 0,
                        enabled: true,
                    },
                    based_on_record: record.clone(),
                    rationale: format!(
                        "User approved {}/{} requests ({:.0}%) for actor '{}' predicate '{}'",
                        record.approve_count,
                        total,
                        approval_pct,
                        record.actor_id.as_str(),
                        record.predicate_id.as_str()
                    ),
                    confidence: suggestion_confidence(total, approval_pct),
                })
            } else if denial_pct >= thresholds.denial_ratio_deny as u64 {
                // Suggest an auto-deny rule
                Some(PolicySuggestion {
                    suggested_rule: PolicyRule {
                        rule_id: format!(
                            "auto-deny-{}-{}",
                            record.actor_id.as_str(),
                            record.predicate_id.as_str()
                        ),
                        kind: PolicyRuleKind::ExplicitDeny,
                        actor_pattern: record.actor_id.as_str().to_string(),
                        predicate_pattern: record.predicate_id.as_str().to_string(),
                        minimum_tier: SensitivityTier::Public,
                        domain_constraint: None,
                        valid_from: None,
                        valid_until: None,
                        priority: 0,
                        enabled: true,
                    },
                    based_on_record: record.clone(),
                    rationale: format!(
                        "User denied {}/{} requests ({:.0}%) for actor '{}' predicate '{}'",
                        record.deny_count,
                        total,
                        denial_pct,
                        record.actor_id.as_str(),
                        record.predicate_id.as_str()
                    ),
                    confidence: suggestion_confidence(total, denial_pct),
                })
            } else {
                None
            };

            if let Some(s) = suggestion {
                // Emit audit event
                let audit_event = PolicyAuditEvent {
                    event_kind: PolicyAuditEventKind::SuggestionGenerated,
                    timestamp: Timestamp::now(),
                    actor_id: Some(record.actor_id.clone()),
                    predicate_id: Some(record.predicate_id.clone()),
                    domain_id: None,
                    decision_summary: Some(s.rationale.clone()),
                    policy_version: None,
                };
                audit_sink.emit(&audit_event).map_err(|e| {
                    PolicyError::AuditSinkError(format!("failed to emit suggestion audit: {}", e))
                })?;
                suggestions.push(s);
            }
        }

        Ok(suggestions)
    }

    /// Get all stored records (for testing/inspection).
    pub fn records(&self) -> Vec<&PatternRecord> {
        self.records.values().collect()
    }
}

/// Compute HMAC-SHA-256 over the record's fields (excluding the mac field itself).
fn compute_mac(record: &PatternRecord, key: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can accept any key length, 32 bytes is always valid");
    mac.update(record.actor_id.as_str().as_bytes());
    mac.update(record.predicate_id.as_str().as_bytes());
    mac.update(&record.approve_count.to_le_bytes());
    mac.update(&record.deny_count.to_le_bytes());
    mac.update(&record.first_seen.seconds_since_epoch.to_le_bytes());
    mac.update(&record.first_seen.nanoseconds.to_le_bytes());
    mac.update(&record.last_seen.seconds_since_epoch.to_le_bytes());
    mac.update(&record.last_seen.nanoseconds.to_le_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Verify the MAC on a PatternRecord.
fn verify_mac(record: &PatternRecord, key: &[u8]) -> bool {
    // Constant-time comparison via hmac crate
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can accept any key length, 32 bytes is always valid");
    mac.update(record.actor_id.as_str().as_bytes());
    mac.update(record.predicate_id.as_str().as_bytes());
    mac.update(&record.approve_count.to_le_bytes());
    mac.update(&record.deny_count.to_le_bytes());
    mac.update(&record.first_seen.seconds_since_epoch.to_le_bytes());
    mac.update(&record.first_seen.nanoseconds.to_le_bytes());
    mac.update(&record.last_seen.seconds_since_epoch.to_le_bytes());
    mac.update(&record.last_seen.nanoseconds.to_le_bytes());
    mac.verify_slice(&record.mac).is_ok()
}

/// Determine suggestion confidence based on total occurrences and ratio.
fn suggestion_confidence(total: u64, ratio: u64) -> ConfidenceLevel {
    if total >= 20 && ratio >= 95 {
        ConfidenceLevel::Verified
    } else if total >= 10 && ratio >= 90 {
        ConfidenceLevel::High
    } else if total >= 5 && ratio >= 80 {
        ConfidenceLevel::Medium
    } else {
        ConfidenceLevel::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::InMemoryAuditSink;

    fn make_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn make_timestamp(secs: u64) -> Timestamp {
        Timestamp::from_seconds(secs)
    }

    #[test]
    fn test_record_pattern_new() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("amazon");
        let pred = PredicateId::new("shipping_address");
        let key = make_key();
        let ts = make_timestamp(1_000_000);

        let record = tracker
            .record_pattern(&actor, &pred, PatternDecision::Approved, ts, &key, &sink)
            .unwrap();

        assert_eq!(record.actor_id.as_str(), "amazon");
        assert_eq!(record.predicate_id.as_str(), "shipping_address");
        assert_eq!(record.approve_count, 1);
        assert_eq!(record.deny_count, 0);
        assert_eq!(record.first_seen, ts);
        assert_eq!(record.last_seen, ts);
        assert!(!record.mac.is_empty());
    }

    #[test]
    fn test_record_pattern_update() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("amazon");
        let pred = PredicateId::new("shipping_address");
        let key = make_key();
        let ts1 = make_timestamp(1_000_000);
        let ts2 = make_timestamp(1_000_100);

        tracker
            .record_pattern(&actor, &pred, PatternDecision::Approved, ts1, &key, &sink)
            .unwrap();

        let record = tracker
            .record_pattern(&actor, &pred, PatternDecision::Denied, ts2, &key, &sink)
            .unwrap();

        assert_eq!(record.approve_count, 1);
        assert_eq!(record.deny_count, 1);
        assert_eq!(record.first_seen, ts1);
        assert_eq!(record.last_seen, ts2);
    }

    #[test]
    fn test_record_pattern_invalid_key_length() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("test");
        let pred = PredicateId::new("test");
        let short_key = [0u8; 16]; // Wrong length

        let result = tracker.record_pattern(
            &actor,
            &pred,
            PatternDecision::Approved,
            make_timestamp(1000),
            &short_key,
            &sink,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::PatternError(_)));
    }

    #[test]
    fn test_record_pattern_tampered_mac() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("actor");
        let pred = PredicateId::new("pred");
        let key = make_key();
        let ts = make_timestamp(1_000_000);

        tracker
            .record_pattern(&actor, &pred, PatternDecision::Approved, ts, &key, &sink)
            .unwrap();

        // Tamper with the stored record's MAC
        let internal_key = (actor.as_str().to_string(), pred.as_str().to_string());
        if let Some(record) = tracker.records.get_mut(&internal_key) {
            record.mac[0] ^= 0xFF; // Corrupt the MAC
        }

        let result = tracker.record_pattern(
            &actor,
            &pred,
            PatternDecision::Denied,
            make_timestamp(1_000_100),
            &key,
            &sink,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyError::MacVerificationFailed
        ));
    }

    #[test]
    fn test_record_pattern_emits_audit() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("actor");
        let pred = PredicateId::new("pred");
        let key = make_key();

        tracker
            .record_pattern(
                &actor,
                &pred,
                PatternDecision::Approved,
                make_timestamp(1000),
                &key,
                &sink,
            )
            .unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_kind, PolicyAuditEventKind::PatternRecorded);
    }

    #[test]
    fn test_suggest_rules_no_records() {
        let sink = InMemoryAuditSink::new();
        let tracker = PatternTracker::new();
        let key = make_key();
        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };

        let suggestions = tracker.suggest_rules(&thresholds, &key, &sink).unwrap();
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_suggest_rules_below_threshold() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("actor");
        let pred = PredicateId::new("pred");
        let key = make_key();

        // Only 2 occurrences, threshold is 5
        for i in 0..2 {
            tracker
                .record_pattern(
                    &actor,
                    &pred,
                    PatternDecision::Approved,
                    make_timestamp(1000 + i),
                    &key,
                    &sink,
                )
                .unwrap();
        }

        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };
        let suggestions = tracker.suggest_rules(&thresholds, &key, &sink).unwrap();
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_suggest_rules_permit_suggestion() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("amazon");
        let pred = PredicateId::new("shipping_address");
        let key = make_key();

        // 10 approvals, 0 denials => 100% approval rate
        for i in 0..10 {
            tracker
                .record_pattern(
                    &actor,
                    &pred,
                    PatternDecision::Approved,
                    make_timestamp(1000 + i),
                    &key,
                    &sink,
                )
                .unwrap();
        }

        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };
        let suggestions = tracker.suggest_rules(&thresholds, &key, &sink).unwrap();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(
            suggestions[0].suggested_rule.kind,
            PolicyRuleKind::ExplicitGrant
        );
        assert!(suggestions[0].rationale.contains("amazon"));
    }

    #[test]
    fn test_suggest_rules_deny_suggestion() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("sketchy-service");
        let pred = PredicateId::new("social_security_number");
        let key = make_key();

        // 10 denials, 0 approvals => 100% denial rate
        for i in 0..10 {
            tracker
                .record_pattern(
                    &actor,
                    &pred,
                    PatternDecision::Denied,
                    make_timestamp(1000 + i),
                    &key,
                    &sink,
                )
                .unwrap();
        }

        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };
        let suggestions = tracker.suggest_rules(&thresholds, &key, &sink).unwrap();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(
            suggestions[0].suggested_rule.kind,
            PolicyRuleKind::ExplicitDeny
        );
    }

    #[test]
    fn test_suggest_rules_mixed_no_suggestion() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("mixed");
        let pred = PredicateId::new("data");
        let key = make_key();

        // 5 approvals, 5 denials => 50% each, below both thresholds
        for i in 0..5 {
            tracker
                .record_pattern(
                    &actor,
                    &pred,
                    PatternDecision::Approved,
                    make_timestamp(1000 + i),
                    &key,
                    &sink,
                )
                .unwrap();
        }
        for i in 0..5 {
            tracker
                .record_pattern(
                    &actor,
                    &pred,
                    PatternDecision::Denied,
                    make_timestamp(2000 + i),
                    &key,
                    &sink,
                )
                .unwrap();
        }

        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };
        let suggestions = tracker.suggest_rules(&thresholds, &key, &sink).unwrap();
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_suggest_rules_invalid_key() {
        let sink = InMemoryAuditSink::new();
        let tracker = PatternTracker::new();
        let short_key = [0u8; 16];
        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };
        let result = tracker.suggest_rules(&thresholds, &short_key, &sink);
        assert!(result.is_err());
    }

    #[test]
    fn test_suggest_rules_skips_tampered_records() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("tampered");
        let pred = PredicateId::new("data");
        let key = make_key();

        for i in 0..10 {
            tracker
                .record_pattern(
                    &actor,
                    &pred,
                    PatternDecision::Approved,
                    make_timestamp(1000 + i),
                    &key,
                    &sink,
                )
                .unwrap();
        }

        // Tamper with the record
        let internal_key = (actor.as_str().to_string(), pred.as_str().to_string());
        if let Some(record) = tracker.records.get_mut(&internal_key) {
            record.approve_count = 999; // Tamper with count
        }

        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };
        let suggestions = tracker.suggest_rules(&thresholds, &key, &sink).unwrap();
        // Tampered record should be skipped
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_suggest_rules_emits_audit() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let actor = ActorId::new("actor");
        let pred = PredicateId::new("pred");
        let key = make_key();

        for i in 0..10 {
            tracker
                .record_pattern(
                    &actor,
                    &pred,
                    PatternDecision::Approved,
                    make_timestamp(1000 + i),
                    &key,
                    &sink,
                )
                .unwrap();
        }

        // Clear audit events from recording
        sink.clear();

        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };
        tracker.suggest_rules(&thresholds, &key, &sink).unwrap();

        let events = sink.events();
        assert!(events
            .iter()
            .any(|e| e.event_kind == PolicyAuditEventKind::SuggestionGenerated));
    }

    #[test]
    fn test_suggestion_confidence_levels() {
        assert_eq!(suggestion_confidence(25, 96), ConfidenceLevel::Verified);
        assert_eq!(suggestion_confidence(15, 92), ConfidenceLevel::High);
        assert_eq!(suggestion_confidence(7, 85), ConfidenceLevel::Medium);
        assert_eq!(suggestion_confidence(3, 70), ConfidenceLevel::Low);
    }

    #[test]
    fn test_compute_and_verify_mac() {
        let key = make_key();
        let record = PatternRecord {
            actor_id: ActorId::new("test"),
            predicate_id: PredicateId::new("pred"),
            approve_count: 5,
            deny_count: 2,
            first_seen: make_timestamp(1000),
            last_seen: make_timestamp(2000),
            mac: Vec::new(),
        };
        let mut record_with_mac = record.clone();
        record_with_mac.mac = compute_mac(&record_with_mac, &key);

        assert!(verify_mac(&record_with_mac, &key));

        // Wrong key should fail
        let wrong_key = [0x99u8; 32];
        assert!(!verify_mac(&record_with_mac, &wrong_key));
    }

    #[test]
    fn test_mac_deterministic() {
        let key = make_key();
        let record = PatternRecord {
            actor_id: ActorId::new("actor"),
            predicate_id: PredicateId::new("pred"),
            approve_count: 1,
            deny_count: 0,
            first_seen: make_timestamp(1000),
            last_seen: make_timestamp(1000),
            mac: Vec::new(),
        };
        let mac1 = compute_mac(&record, &key);
        let mac2 = compute_mac(&record, &key);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_tracker_records_accessor() {
        let sink = InMemoryAuditSink::new();
        let mut tracker = PatternTracker::new();
        let key = make_key();

        tracker
            .record_pattern(
                &ActorId::new("a"),
                &PredicateId::new("p"),
                PatternDecision::Approved,
                make_timestamp(1000),
                &key,
                &sink,
            )
            .unwrap();
        tracker
            .record_pattern(
                &ActorId::new("b"),
                &PredicateId::new("q"),
                PatternDecision::Denied,
                make_timestamp(1001),
                &key,
                &sink,
            )
            .unwrap();

        assert_eq!(tracker.records().len(), 2);
    }
}
