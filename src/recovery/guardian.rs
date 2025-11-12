//! Guardian System for Social Recovery
//!
//! Implements a guardian-based recovery system where users can designate
//! trusted contacts to help recover their identity if seed phrases are lost.
//!
//! Security features:
//! - Threshold-based recovery (M-of-N guardians required)
//! - Time-locked recovery requests (prevents immediate takeover)
//! - Guardian verification codes
//! - Expiring approval tokens

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Guardian threshold requirements
pub const MIN_GUARDIANS: usize = 3;
pub const MAX_GUARDIANS: usize = 10;
pub const DEFAULT_THRESHOLD: usize = 2; // 2-of-3 minimum

/// Recovery request timelock (24 hours in seconds)
pub const RECOVERY_TIMELOCK_SECONDS: u64 = 86400;

/// Guardian approval expiration (7 days in seconds)
pub const APPROVAL_EXPIRATION_SECONDS: u64 = 604800;

/// Guardian contact information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Guardian {
    /// Unique guardian ID
    pub guardian_id: String,
    /// Guardian's display name
    pub display_name: String,
    /// Contact method (email or phone)
    pub contact_method: ContactMethod,
    /// Guardian's identity ID (if they're also a user)
    pub identity_id: Option<String>,
    /// When this guardian was added
    pub added_at: u64,
    /// Guardian status
    pub status: GuardianStatus,
    /// Verification code for this guardian
    pub verification_code: String,
}

/// Guardian contact method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContactMethod {
    Email(String),
    Phone(String),
    IdentityId(String),
}

/// Guardian status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GuardianStatus {
    /// Guardian invitation sent, awaiting acceptance
    Pending,
    /// Guardian has accepted and is active
    Active,
    /// Guardian has declined
    Declined,
    /// Guardian has been revoked by the user
    Revoked,
}

/// Recovery request tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// Unique request ID
    pub request_id: String,
    /// Identity being recovered
    pub identity_id: String,
    /// When the request was created
    pub created_at: u64,
    /// When the timelock expires (created_at + RECOVERY_TIMELOCK_SECONDS)
    pub timelock_expires_at: u64,
    /// Required number of approvals
    pub threshold: usize,
    /// Guardian approvals received
    pub approvals: HashMap<String, GuardianApproval>,
    /// Request status
    pub status: RecoveryRequestStatus,
    /// New password hash (once approved)
    pub new_password_hash: Option<String>,
}

/// Guardian approval for recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianApproval {
    /// Guardian who approved
    pub guardian_id: String,
    /// When they approved
    pub approved_at: u64,
    /// Approval verification code
    pub verification_code: String,
    /// Approval token (expires)
    pub approval_token: String,
}

/// Recovery request status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecoveryRequestStatus {
    /// Waiting for timelock to expire
    Pending,
    /// Timelock expired, waiting for guardian approvals
    AwaitingApprovals,
    /// Threshold met, recovery can proceed
    Approved,
    /// Request was cancelled
    Cancelled,
    /// Request expired without enough approvals
    Expired,
    /// Recovery completed successfully
    Completed,
}

/// Guardian configuration for an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianConfig {
    /// Identity this config belongs to
    pub identity_id: String,
    /// List of guardians
    pub guardians: Vec<Guardian>,
    /// Required threshold (M-of-N)
    pub threshold: usize,
    /// When this config was last updated
    pub updated_at: u64,
}

impl GuardianConfig {
    /// Create a new guardian configuration
    pub fn new(identity_id: String, threshold: usize) -> Result<Self> {
        if threshold < DEFAULT_THRESHOLD {
            return Err(anyhow!(
                "Threshold must be at least {}",
                DEFAULT_THRESHOLD
            ));
        }

        Ok(Self {
            identity_id,
            guardians: Vec::new(),
            threshold,
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Add a new guardian
    pub fn add_guardian(&mut self, guardian: Guardian) -> Result<()> {
        // Check maximum guardians
        if self.guardians.len() >= MAX_GUARDIANS {
            return Err(anyhow!(
                "Maximum number of guardians ({}) reached",
                MAX_GUARDIANS
            ));
        }

        // Check for duplicate guardian ID
        if self.guardians.iter().any(|g| g.guardian_id == guardian.guardian_id) {
            return Err(anyhow!("Guardian already exists"));
        }

        // Check for duplicate contact method
        if self.guardians.iter().any(|g| g.contact_method == guardian.contact_method) {
            return Err(anyhow!("Contact method already used by another guardian"));
        }

        self.guardians.push(guardian);
        self.update_timestamp();

        Ok(())
    }

    /// Remove a guardian
    pub fn remove_guardian(&mut self, guardian_id: &str) -> Result<()> {
        let initial_len = self.guardians.len();
        self.guardians.retain(|g| g.guardian_id != guardian_id);

        if self.guardians.len() == initial_len {
            return Err(anyhow!("Guardian not found"));
        }

        // Ensure we still have minimum guardians
        if self.guardians.len() < MIN_GUARDIANS {
            return Err(anyhow!(
                "Cannot remove guardian: minimum {} guardians required",
                MIN_GUARDIANS
            ));
        }

        // Ensure threshold is still valid
        if self.threshold > self.guardians.len() {
            self.threshold = self.guardians.len();
        }

        self.update_timestamp();

        Ok(())
    }

    /// Get active guardians
    pub fn active_guardians(&self) -> Vec<&Guardian> {
        self.guardians
            .iter()
            .filter(|g| g.status == GuardianStatus::Active)
            .collect()
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        let active_count = self.active_guardians().len();

        if active_count < MIN_GUARDIANS {
            return Err(anyhow!(
                "Need at least {} active guardians, have {}",
                MIN_GUARDIANS,
                active_count
            ));
        }

        if self.threshold > active_count {
            return Err(anyhow!(
                "Threshold ({}) exceeds active guardians ({})",
                self.threshold,
                active_count
            ));
        }

        if self.threshold < DEFAULT_THRESHOLD {
            return Err(anyhow!(
                "Threshold ({}) below minimum ({})",
                self.threshold,
                DEFAULT_THRESHOLD
            ));
        }

        Ok(())
    }

    /// Update timestamp
    pub(crate) fn update_timestamp(&mut self) {
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

impl RecoveryRequest {
    /// Create a new recovery request
    pub fn new(
        identity_id: String,
        threshold: usize,
        new_password_hash: Option<String>,
    ) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let request_id = format!(
            "recovery_{}_{}",
            identity_id,
            created_at
        );

        Self {
            request_id,
            identity_id,
            created_at,
            timelock_expires_at: created_at + RECOVERY_TIMELOCK_SECONDS,
            threshold,
            approvals: HashMap::new(),
            status: RecoveryRequestStatus::Pending,
            new_password_hash,
        }
    }

    /// Add guardian approval
    pub fn add_approval(&mut self, approval: GuardianApproval) -> Result<()> {
        // Check if already approved by this guardian
        if self.approvals.contains_key(&approval.guardian_id) {
            return Err(anyhow!("Guardian has already approved this request"));
        }

        self.approvals.insert(approval.guardian_id.clone(), approval);

        // Update status if threshold met
        if self.approvals.len() >= self.threshold {
            self.status = RecoveryRequestStatus::Approved;
        }

        Ok(())
    }

    /// Check if timelock has expired
    pub fn is_timelock_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now >= self.timelock_expires_at
    }

    /// Check if request can proceed
    pub fn can_proceed(&self) -> bool {
        self.is_timelock_expired()
            && self.approvals.len() >= self.threshold
            && self.status == RecoveryRequestStatus::Approved
    }

    /// Check if request has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Request expires 7 days after creation
        now > self.created_at + APPROVAL_EXPIRATION_SECONDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guardian_config_creation() {
        let config = GuardianConfig::new("identity_123".to_string(), 2).unwrap();
        assert_eq!(config.identity_id, "identity_123");
        assert_eq!(config.threshold, 2);
        assert_eq!(config.guardians.len(), 0);
    }

    #[test]
    fn test_guardian_config_minimum_threshold() {
        let result = GuardianConfig::new("identity_123".to_string(), 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_guardian() {
        let mut config = GuardianConfig::new("identity_123".to_string(), 2).unwrap();

        let guardian = Guardian {
            guardian_id: "guardian_1".to_string(),
            display_name: "Alice".to_string(),
            contact_method: ContactMethod::Email("alice@example.com".to_string()),
            identity_id: None,
            added_at: 1700000000,
            status: GuardianStatus::Active,
            verification_code: "CODE123".to_string(),
        };

        config.add_guardian(guardian).unwrap();
        assert_eq!(config.guardians.len(), 1);
    }

    #[test]
    fn test_duplicate_guardian() {
        let mut config = GuardianConfig::new("identity_123".to_string(), 2).unwrap();

        let guardian1 = Guardian {
            guardian_id: "guardian_1".to_string(),
            display_name: "Alice".to_string(),
            contact_method: ContactMethod::Email("alice@example.com".to_string()),
            identity_id: None,
            added_at: 1700000000,
            status: GuardianStatus::Active,
            verification_code: "CODE123".to_string(),
        };

        let guardian2 = Guardian {
            guardian_id: "guardian_1".to_string(),
            display_name: "Alice Again".to_string(),
            contact_method: ContactMethod::Email("alice2@example.com".to_string()),
            identity_id: None,
            added_at: 1700000000,
            status: GuardianStatus::Active,
            verification_code: "CODE456".to_string(),
        };

        config.add_guardian(guardian1).unwrap();
        let result = config.add_guardian(guardian2);
        assert!(result.is_err());
    }

    #[test]
    fn test_recovery_request_creation() {
        let request = RecoveryRequest::new(
            "identity_123".to_string(),
            2,
            Some("new_password_hash".to_string()),
        );

        assert_eq!(request.identity_id, "identity_123");
        assert_eq!(request.threshold, 2);
        assert_eq!(request.approvals.len(), 0);
        assert_eq!(request.status, RecoveryRequestStatus::Pending);
    }

    #[test]
    fn test_add_approval() {
        let mut request = RecoveryRequest::new(
            "identity_123".to_string(),
            2,
            None,
        );

        let approval = GuardianApproval {
            guardian_id: "guardian_1".to_string(),
            approved_at: 1700000000,
            verification_code: "CODE123".to_string(),
            approval_token: "TOKEN123".to_string(),
        };

        request.add_approval(approval).unwrap();
        assert_eq!(request.approvals.len(), 1);
        assert_eq!(request.status, RecoveryRequestStatus::Pending);
    }

    #[test]
    fn test_threshold_met() {
        let mut request = RecoveryRequest::new(
            "identity_123".to_string(),
            2,
            None,
        );

        let approval1 = GuardianApproval {
            guardian_id: "guardian_1".to_string(),
            approved_at: 1700000000,
            verification_code: "CODE123".to_string(),
            approval_token: "TOKEN123".to_string(),
        };

        let approval2 = GuardianApproval {
            guardian_id: "guardian_2".to_string(),
            approved_at: 1700000001,
            verification_code: "CODE456".to_string(),
            approval_token: "TOKEN456".to_string(),
        };

        request.add_approval(approval1).unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Pending);

        request.add_approval(approval2).unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Approved);
    }
}
