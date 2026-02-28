//! Signet Policy Engine
//!
//! XACML-for-individuals policy evaluation engine. Every data request is
//! evaluated as Actor + Predicate + Context = Legitimacy, producing a
//! three-way decision: PERMIT, DENY, or ANOMALY.
//!
//! Key features:
//! - Six-level sensitivity tier hierarchy (Public < Commerce < Financial < Medical < Identity < TrustedAgent)
//! - Four actor classification methods with discrete confidence levels
//! - Deny-overrides policy combining algorithm
//! - Fail-secure timeout semantics (pipeline timeout = DENY, not error)
//! - Structured ANOMALY escalation (who/what/why/options -- never silently resolved)
//! - MAC-protected pattern tracker for learning from user decisions
//! - TOCTOU-safe policy snapshots via PolicyVersion

pub mod actor;
pub mod engine;
pub mod error;
pub mod pattern;
pub mod predicate;
pub mod rule;
pub mod types;

// Re-export primary types for convenience
pub use engine::{AuditSink, InMemoryAuditSink, PolicyEngine};
pub use error::{PolicyError, PolicyErrorDetail, PolicyErrorKind, PolicyResult};
pub use pattern::PatternTracker;
pub use types::{
    compare_tiers, ActorClassification, AnomalyDecision, AnomalyOption, AnomalyReport,
    ClassificationEvidence, Decision, DenyDecision, EvaluationRequest, PatternDecision,
    PatternRecord, PermitDecision, PolicyAuditEvent, PolicyAuditEventKind, PolicyRule,
    PolicyRuleKind, PolicySet, PolicySnapshot, PolicySuggestion, Provenance, RequestContext,
    SensitivityTier, SuggestionThresholds, TimeoutConfig,
};
