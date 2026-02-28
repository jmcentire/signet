//! Five-state credential status machine with valid transitions.
//!
//! States: Active, Presented, Consumed, Expired, Revoked
//! Terminal states: Consumed, Expired, Revoked (no outbound transitions)
//!
//! Valid transitions:
//!   Active -> Presented
//!   Active -> Consumed (one-time only, atomic)
//!   Active -> Expired (TTL)
//!   Active -> Revoked
//!   Presented -> Consumed (one-time only)
//!   Presented -> Expired
//!   Presented -> Revoked

use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::types::{CredentialStatus, RevocationInfo, RevokedBy};

/// Check whether a status transition is valid.
pub fn is_valid_transition(from: CredentialStatus, to: CredentialStatus) -> bool {
    matches!(
        (from, to),
        (CredentialStatus::Active, CredentialStatus::Presented)
            | (CredentialStatus::Active, CredentialStatus::Consumed)
            | (CredentialStatus::Active, CredentialStatus::Expired)
            | (CredentialStatus::Active, CredentialStatus::Revoked)
            | (CredentialStatus::Presented, CredentialStatus::Presented)
            | (CredentialStatus::Presented, CredentialStatus::Consumed)
            | (CredentialStatus::Presented, CredentialStatus::Expired)
            | (CredentialStatus::Presented, CredentialStatus::Revoked)
    )
}

/// Attempt a status transition, returning the new status or an error.
pub fn transition(from: CredentialStatus, to: CredentialStatus) -> CredResult<CredentialStatus> {
    if is_valid_transition(from, to) {
        Ok(to)
    } else {
        Err(CredErrorDetail::new(
            CredError::StatusTransitionDenied(format!("{} -> {}", from, to)),
            format!("transition from {} to {} is not allowed", from, to),
        ))
    }
}

/// Check if a credential can be presented (must be Active or Presented).
pub fn can_present(status: CredentialStatus) -> bool {
    matches!(
        status,
        CredentialStatus::Active | CredentialStatus::Presented
    )
}

/// Check if a credential can be revoked (must not be in a terminal state,
/// though Expired can technically still be revoked — here we allow from non-Consumed/non-Revoked).
pub fn can_revoke(status: CredentialStatus) -> bool {
    matches!(
        status,
        CredentialStatus::Active | CredentialStatus::Presented | CredentialStatus::Expired
    )
}

/// Get the appropriate next status for a presentation event.
/// One-time credentials go to Consumed; reusable go to Presented.
pub fn status_after_presentation(
    current: CredentialStatus,
    one_time: bool,
) -> CredResult<CredentialStatus> {
    if !can_present(current) {
        return Err(CredErrorDetail::new(
            CredError::StatusTransitionDenied(format!("cannot present from {}", current)),
            format!("credential in {} state cannot be presented", current),
        ));
    }
    if one_time {
        transition(current, CredentialStatus::Consumed)
    } else {
        transition(current, CredentialStatus::Presented)
    }
}

/// Transition to Expired if the credential is in a valid state.
pub fn transition_to_expired(current: CredentialStatus) -> CredResult<CredentialStatus> {
    transition(current, CredentialStatus::Expired)
}

/// Transition to Revoked if the credential is in a valid state.
pub fn transition_to_revoked(current: CredentialStatus) -> CredResult<CredentialStatus> {
    if !can_revoke(current) {
        return Err(CredErrorDetail::new(
            CredError::StatusTransitionDenied(format!("cannot revoke from {}", current)),
            format!("credential in {} state cannot be revoked", current),
        ));
    }
    transition(current, CredentialStatus::Revoked)
}

/// Revoke a credential by the user. Returns the RevocationInfo and new status.
/// Idempotent: if already Revoked, returns Ok with existing info.
pub fn revoke_by_user(
    current: CredentialStatus,
    reason: Option<String>,
) -> CredResult<(CredentialStatus, RevocationInfo)> {
    if current == CredentialStatus::Revoked {
        // Idempotent: already revoked
        let info = RevocationInfo {
            revoked_by: RevokedBy::User,
            revoked_at: chrono::Utc::now().to_rfc3339(),
            reason,
        };
        return Ok((CredentialStatus::Revoked, info));
    }
    let new_status = transition_to_revoked(current)?;
    let info = RevocationInfo {
        revoked_by: RevokedBy::User,
        revoked_at: chrono::Utc::now().to_rfc3339(),
        reason,
    };
    Ok((new_status, info))
}

/// Revoke a credential by an authority. Returns the RevocationInfo and new status.
/// Idempotent: if already Revoked, returns Ok with existing info.
pub fn revoke_by_authority(
    current: CredentialStatus,
    authority_pubkey: String,
    reason: Option<String>,
) -> CredResult<(CredentialStatus, RevocationInfo)> {
    if current == CredentialStatus::Revoked {
        let info = RevocationInfo {
            revoked_by: RevokedBy::Authority(authority_pubkey),
            revoked_at: chrono::Utc::now().to_rfc3339(),
            reason,
        };
        return Ok((CredentialStatus::Revoked, info));
    }
    let new_status = transition_to_revoked(current)?;
    let info = RevocationInfo {
        revoked_by: RevokedBy::Authority(authority_pubkey),
        revoked_at: chrono::Utc::now().to_rfc3339(),
        reason,
    };
    Ok((new_status, info))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Valid transitions ---

    #[test]
    fn test_active_to_presented() {
        assert!(is_valid_transition(
            CredentialStatus::Active,
            CredentialStatus::Presented
        ));
        assert!(transition(CredentialStatus::Active, CredentialStatus::Presented).is_ok());
    }

    #[test]
    fn test_active_to_consumed() {
        assert!(is_valid_transition(
            CredentialStatus::Active,
            CredentialStatus::Consumed
        ));
    }

    #[test]
    fn test_active_to_expired() {
        assert!(is_valid_transition(
            CredentialStatus::Active,
            CredentialStatus::Expired
        ));
    }

    #[test]
    fn test_active_to_revoked() {
        assert!(is_valid_transition(
            CredentialStatus::Active,
            CredentialStatus::Revoked
        ));
    }

    #[test]
    fn test_presented_to_consumed() {
        assert!(is_valid_transition(
            CredentialStatus::Presented,
            CredentialStatus::Consumed
        ));
    }

    #[test]
    fn test_presented_to_expired() {
        assert!(is_valid_transition(
            CredentialStatus::Presented,
            CredentialStatus::Expired
        ));
    }

    #[test]
    fn test_presented_to_revoked() {
        assert!(is_valid_transition(
            CredentialStatus::Presented,
            CredentialStatus::Revoked
        ));
    }

    // --- Invalid transitions (terminal states) ---

    #[test]
    fn test_consumed_no_outbound() {
        assert!(!is_valid_transition(
            CredentialStatus::Consumed,
            CredentialStatus::Active
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Consumed,
            CredentialStatus::Presented
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Consumed,
            CredentialStatus::Expired
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Consumed,
            CredentialStatus::Revoked
        ));
    }

    #[test]
    fn test_expired_no_outbound_except_none() {
        assert!(!is_valid_transition(
            CredentialStatus::Expired,
            CredentialStatus::Active
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Expired,
            CredentialStatus::Presented
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Expired,
            CredentialStatus::Consumed
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Expired,
            CredentialStatus::Revoked
        ));
    }

    #[test]
    fn test_revoked_no_outbound() {
        assert!(!is_valid_transition(
            CredentialStatus::Revoked,
            CredentialStatus::Active
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Revoked,
            CredentialStatus::Presented
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Revoked,
            CredentialStatus::Consumed
        ));
        assert!(!is_valid_transition(
            CredentialStatus::Revoked,
            CredentialStatus::Expired
        ));
    }

    // --- Self transitions are not allowed ---

    #[test]
    fn test_no_self_transitions_except_presented() {
        assert!(!is_valid_transition(
            CredentialStatus::Active,
            CredentialStatus::Active
        ));
        // Presented -> Presented IS valid (reusable credential presented again)
        assert!(is_valid_transition(
            CredentialStatus::Presented,
            CredentialStatus::Presented
        ));
    }

    // --- Invalid non-terminal transitions ---

    #[test]
    fn test_presented_to_active() {
        assert!(!is_valid_transition(
            CredentialStatus::Presented,
            CredentialStatus::Active
        ));
    }

    // --- Transition error details ---

    #[test]
    fn test_transition_error_message() {
        let result = transition(CredentialStatus::Consumed, CredentialStatus::Active);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.kind, CredError::StatusTransitionDenied(_)));
        assert!(err.message.contains("Consumed"));
        assert!(err.message.contains("Active"));
    }

    // --- can_present ---

    #[test]
    fn test_can_present() {
        assert!(can_present(CredentialStatus::Active));
        assert!(can_present(CredentialStatus::Presented));
        assert!(!can_present(CredentialStatus::Consumed));
        assert!(!can_present(CredentialStatus::Expired));
        assert!(!can_present(CredentialStatus::Revoked));
    }

    // --- can_revoke ---

    #[test]
    fn test_can_revoke() {
        assert!(can_revoke(CredentialStatus::Active));
        assert!(can_revoke(CredentialStatus::Presented));
        assert!(can_revoke(CredentialStatus::Expired));
        assert!(!can_revoke(CredentialStatus::Consumed));
        assert!(!can_revoke(CredentialStatus::Revoked));
    }

    // --- status_after_presentation ---

    #[test]
    fn test_presentation_one_time_active() {
        let result = status_after_presentation(CredentialStatus::Active, true).unwrap();
        assert_eq!(result, CredentialStatus::Consumed);
    }

    #[test]
    fn test_presentation_reusable_active() {
        let result = status_after_presentation(CredentialStatus::Active, false).unwrap();
        assert_eq!(result, CredentialStatus::Presented);
    }

    #[test]
    fn test_presentation_one_time_presented() {
        let result = status_after_presentation(CredentialStatus::Presented, true).unwrap();
        assert_eq!(result, CredentialStatus::Consumed);
    }

    #[test]
    fn test_presentation_reusable_presented() {
        let result = status_after_presentation(CredentialStatus::Presented, false).unwrap();
        assert_eq!(result, CredentialStatus::Presented);
    }

    #[test]
    fn test_presentation_consumed_fails() {
        let result = status_after_presentation(CredentialStatus::Consumed, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_presentation_expired_fails() {
        let result = status_after_presentation(CredentialStatus::Expired, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_presentation_revoked_fails() {
        let result = status_after_presentation(CredentialStatus::Revoked, true);
        assert!(result.is_err());
    }

    // --- transition_to_expired ---

    #[test]
    fn test_transition_to_expired_active() {
        let result = transition_to_expired(CredentialStatus::Active).unwrap();
        assert_eq!(result, CredentialStatus::Expired);
    }

    #[test]
    fn test_transition_to_expired_presented() {
        let result = transition_to_expired(CredentialStatus::Presented).unwrap();
        assert_eq!(result, CredentialStatus::Expired);
    }

    #[test]
    fn test_transition_to_expired_consumed_fails() {
        let result = transition_to_expired(CredentialStatus::Consumed);
        assert!(result.is_err());
    }

    // --- transition_to_revoked ---

    #[test]
    fn test_transition_to_revoked_active() {
        let result = transition_to_revoked(CredentialStatus::Active).unwrap();
        assert_eq!(result, CredentialStatus::Revoked);
    }

    #[test]
    fn test_transition_to_revoked_consumed_fails() {
        let result = transition_to_revoked(CredentialStatus::Consumed);
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_to_revoked_already_revoked_fails() {
        let result = transition_to_revoked(CredentialStatus::Revoked);
        assert!(result.is_err());
    }

    // --- revoke_by_user ---

    #[test]
    fn test_revoke_by_user_active() {
        let (status, info) =
            revoke_by_user(CredentialStatus::Active, Some("no longer needed".into())).unwrap();
        assert_eq!(status, CredentialStatus::Revoked);
        assert_eq!(info.revoked_by, RevokedBy::User);
        assert_eq!(info.reason.as_deref(), Some("no longer needed"));
    }

    #[test]
    fn test_revoke_by_user_presented() {
        let (status, _info) = revoke_by_user(CredentialStatus::Presented, None).unwrap();
        assert_eq!(status, CredentialStatus::Revoked);
    }

    #[test]
    fn test_revoke_by_user_consumed_fails() {
        let result = revoke_by_user(CredentialStatus::Consumed, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_by_user_already_revoked_idempotent() {
        let (status, info) = revoke_by_user(CredentialStatus::Revoked, None).unwrap();
        assert_eq!(status, CredentialStatus::Revoked);
        assert_eq!(info.revoked_by, RevokedBy::User);
    }

    // --- revoke_by_authority ---

    #[test]
    fn test_revoke_by_authority_active() {
        let (status, info) = revoke_by_authority(
            CredentialStatus::Active,
            "abcd1234".into(),
            Some("credential superseded".into()),
        )
        .unwrap();
        assert_eq!(status, CredentialStatus::Revoked);
        assert_eq!(
            info.revoked_by,
            RevokedBy::Authority("abcd1234".into())
        );
        assert_eq!(info.reason.as_deref(), Some("credential superseded"));
    }

    #[test]
    fn test_revoke_by_authority_consumed_fails() {
        let result = revoke_by_authority(CredentialStatus::Consumed, "pk".into(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_by_authority_already_revoked_idempotent() {
        let (status, info) =
            revoke_by_authority(CredentialStatus::Revoked, "pk".into(), None).unwrap();
        assert_eq!(status, CredentialStatus::Revoked);
        assert_eq!(info.revoked_by, RevokedBy::Authority("pk".into()));
    }

    #[test]
    fn test_revoked_credential_cannot_be_presented() {
        assert!(!can_present(CredentialStatus::Revoked));
    }
}
