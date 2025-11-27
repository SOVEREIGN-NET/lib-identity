//! Guardian Manager
//!
//! Manages guardians and recovery requests for social recovery

use anyhow::{anyhow, Result};
use std::collections::HashMap;

use super::guardian::*;

/// Guardian Manager - handles guardian operations
pub struct GuardianManager {
    /// Guardian configurations by identity ID
    configs: HashMap<String, GuardianConfig>,
    /// Active recovery requests
    recovery_requests: HashMap<String, RecoveryRequest>,
}

impl GuardianManager {
    /// Create new guardian manager
    pub fn new() -> Self {
        Self {
            configs: HashMap::new(),
            recovery_requests: HashMap::new(),
        }
    }

    /// Initialize guardian configuration for an identity
    pub fn initialize_config(
        &mut self,
        identity_id: String,
        threshold: usize,
    ) -> Result<()> {
        if self.configs.contains_key(&identity_id) {
            return Err(anyhow!("Guardian config already exists for this identity"));
        }

        let config = GuardianConfig::new(identity_id.clone(), threshold)?;
        self.configs.insert(identity_id, config);

        Ok(())
    }

    /// Add a guardian to an identity
    pub fn add_guardian(
        &mut self,
        identity_id: &str,
        guardian: Guardian,
    ) -> Result<()> {
        let config = self.configs.get_mut(identity_id)
            .ok_or_else(|| anyhow!("No guardian config found for identity"))?;

        config.add_guardian(guardian)?;

        Ok(())
    }

    /// Remove a guardian
    pub fn remove_guardian(
        &mut self,
        identity_id: &str,
        guardian_id: &str,
    ) -> Result<()> {
        let config = self.configs.get_mut(identity_id)
            .ok_or_else(|| anyhow!("No guardian config found for identity"))?;

        config.remove_guardian(guardian_id)?;

        Ok(())
    }

    /// Update guardian status
    pub fn update_guardian_status(
        &mut self,
        identity_id: &str,
        guardian_id: &str,
        status: GuardianStatus,
    ) -> Result<()> {
        let config = self.configs.get_mut(identity_id)
            .ok_or_else(|| anyhow!("No guardian config found for identity"))?;

        let guardian = config.guardians.iter_mut()
            .find(|g| g.guardian_id == guardian_id)
            .ok_or_else(|| anyhow!("Guardian not found"))?;

        guardian.status = status;
        config.update_timestamp();

        Ok(())
    }

    /// Get guardian configuration for an identity
    pub fn get_config(&self, identity_id: &str) -> Option<&GuardianConfig> {
        self.configs.get(identity_id)
    }

    /// Initiate a recovery request
    pub fn initiate_recovery(
        &mut self,
        identity_id: String,
        new_password_hash: Option<String>,
    ) -> Result<String> {
        // Get guardian config
        let config = self.configs.get(&identity_id)
            .ok_or_else(|| anyhow!("No guardian config found for identity"))?;

        // Validate config
        config.validate()?;

        // Check for existing active recovery requests
        if let Some(existing) = self.recovery_requests.values()
            .find(|r| r.identity_id == identity_id &&
                     r.status != RecoveryRequestStatus::Completed &&
                     r.status != RecoveryRequestStatus::Cancelled &&
                     r.status != RecoveryRequestStatus::Expired)
        {
            return Err(anyhow!(
                "Active recovery request already exists: {}",
                existing.request_id
            ));
        }

        // Create recovery request
        let request = RecoveryRequest::new(
            identity_id,
            config.threshold,
            new_password_hash,
        );

        let request_id = request.request_id.clone();
        self.recovery_requests.insert(request_id.clone(), request);

        Ok(request_id)
    }

    /// Submit guardian approval
    pub fn submit_approval(
        &mut self,
        request_id: &str,
        approval: GuardianApproval,
    ) -> Result<()> {
        let request = self.recovery_requests.get_mut(request_id)
            .ok_or_else(|| anyhow!("Recovery request not found"))?;

        // Verify guardian exists
        let config = self.configs.get(&request.identity_id)
            .ok_or_else(|| anyhow!("Guardian config not found"))?;

        let guardian = config.guardians.iter()
            .find(|g| g.guardian_id == approval.guardian_id)
            .ok_or_else(|| anyhow!("Guardian not found in config"))?;

        // Verify guardian is active
        if guardian.status != GuardianStatus::Active {
            return Err(anyhow!("Guardian is not active"));
        }

        // Verify verification code
        if guardian.verification_code != approval.verification_code {
            return Err(anyhow!("Invalid verification code"));
        }

        // Add approval
        request.add_approval(approval)?;

        Ok(())
    }

    /// Get recovery request status
    pub fn get_recovery_request(&self, request_id: &str) -> Option<&RecoveryRequest> {
        self.recovery_requests.get(request_id)
    }

    /// Cancel a recovery request
    pub fn cancel_recovery(&mut self, request_id: &str) -> Result<()> {
        let request = self.recovery_requests.get_mut(request_id)
            .ok_or_else(|| anyhow!("Recovery request not found"))?;

        if request.status == RecoveryRequestStatus::Completed {
            return Err(anyhow!("Cannot cancel completed recovery"));
        }

        request.status = RecoveryRequestStatus::Cancelled;

        Ok(())
    }

    /// Complete a recovery request
    pub fn complete_recovery(&mut self, request_id: &str) -> Result<()> {
        let request = self.recovery_requests.get_mut(request_id)
            .ok_or_else(|| anyhow!("Recovery request not found"))?;

        if !request.can_proceed() {
            return Err(anyhow!("Recovery request cannot proceed yet"));
        }

        request.status = RecoveryRequestStatus::Completed;

        Ok(())
    }

    /// Clean up expired recovery requests
    pub fn cleanup_expired_requests(&mut self) {
        let expired_ids: Vec<String> = self.recovery_requests
            .iter()
            .filter(|(_, req)| req.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired_ids {
            if let Some(request) = self.recovery_requests.get_mut(&id) {
                request.status = RecoveryRequestStatus::Expired;
            }
        }
    }
}

impl Default for GuardianManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_guardian(id: &str, name: &str, email: &str) -> Guardian {
        Guardian {
            guardian_id: id.to_string(),
            display_name: name.to_string(),
            contact_method: ContactMethod::Email(email.to_string()),
            identity_id: None,
            added_at: 1700000000,
            status: GuardianStatus::Active,
            verification_code: format!("CODE{}", id),
        }
    }

    #[test]
    fn test_guardian_manager_creation() {
        let manager = GuardianManager::new();
        assert_eq!(manager.configs.len(), 0);
        assert_eq!(manager.recovery_requests.len(), 0);
    }

    #[test]
    fn test_initialize_config() {
        let mut manager = GuardianManager::new();
        manager.initialize_config("identity_123".to_string(), 2).unwrap();

        assert!(manager.get_config("identity_123").is_some());
    }

    #[test]
    fn test_add_guardian() {
        let mut manager = GuardianManager::new();
        manager.initialize_config("identity_123".to_string(), 2).unwrap();

        let guardian = create_test_guardian("g1", "Alice", "alice@example.com");
        manager.add_guardian("identity_123", guardian).unwrap();

        let config = manager.get_config("identity_123").unwrap();
        assert_eq!(config.guardians.len(), 1);
    }

    #[test]
    fn test_remove_guardian() {
        let mut manager = GuardianManager::new();
        manager.initialize_config("identity_123".to_string(), 2).unwrap();

        // Add 3 guardians (minimum)
        manager.add_guardian("identity_123", create_test_guardian("g1", "Alice", "alice@example.com")).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g2", "Bob", "bob@example.com")).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g3", "Charlie", "charlie@example.com")).unwrap();

        // Should be able to remove one
        manager.remove_guardian("identity_123", "g1").unwrap();

        let config = manager.get_config("identity_123").unwrap();
        assert_eq!(config.guardians.len(), 2);
    }

    #[test]
    fn test_cannot_remove_below_minimum() {
        let mut manager = GuardianManager::new();
        manager.initialize_config("identity_123".to_string(), 2).unwrap();

        // Add minimum 3 guardians
        manager.add_guardian("identity_123", create_test_guardian("g1", "Alice", "alice@example.com")).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g2", "Bob", "bob@example.com")).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g3", "Charlie", "charlie@example.com")).unwrap();

        // Remove one guardian
        manager.remove_guardian("identity_123", "g1").unwrap();

        // Cannot remove another (would go below minimum)
        let result = manager.remove_guardian("identity_123", "g2");
        assert!(result.is_err());
    }

    #[test]
    fn test_initiate_recovery() {
        let mut manager = GuardianManager::new();
        manager.initialize_config("identity_123".to_string(), 2).unwrap();

        // Add guardians
        manager.add_guardian("identity_123", create_test_guardian("g1", "Alice", "alice@example.com")).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g2", "Bob", "bob@example.com")).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g3", "Charlie", "charlie@example.com")).unwrap();

        let request_id = manager.initiate_recovery(
            "identity_123".to_string(),
            Some("new_password_hash".to_string()),
        ).unwrap();

        assert!(manager.get_recovery_request(&request_id).is_some());
    }

    #[test]
    fn test_submit_approval() {
        let mut manager = GuardianManager::new();
        manager.initialize_config("identity_123".to_string(), 2).unwrap();

        let g1 = create_test_guardian("g1", "Alice", "alice@example.com");
        let g1_code = g1.verification_code.clone();

        manager.add_guardian("identity_123", g1).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g2", "Bob", "bob@example.com")).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g3", "Charlie", "charlie@example.com")).unwrap();

        let request_id = manager.initiate_recovery(
            "identity_123".to_string(),
            None,
        ).unwrap();

        let approval = GuardianApproval {
            guardian_id: "g1".to_string(),
            approved_at: 1700000000,
            verification_code: g1_code,
            approval_token: "TOKEN123".to_string(),
        };

        manager.submit_approval(&request_id, approval).unwrap();

        let request = manager.get_recovery_request(&request_id).unwrap();
        assert_eq!(request.approvals.len(), 1);
    }

    #[test]
    fn test_recovery_threshold() {
        let mut manager = GuardianManager::new();
        manager.initialize_config("identity_123".to_string(), 2).unwrap();

        let g1 = create_test_guardian("g1", "Alice", "alice@example.com");
        let g1_code = g1.verification_code.clone();
        let g2 = create_test_guardian("g2", "Bob", "bob@example.com");
        let g2_code = g2.verification_code.clone();

        manager.add_guardian("identity_123", g1).unwrap();
        manager.add_guardian("identity_123", g2).unwrap();
        manager.add_guardian("identity_123", create_test_guardian("g3", "Charlie", "charlie@example.com")).unwrap();

        let request_id = manager.initiate_recovery(
            "identity_123".to_string(),
            None,
        ).unwrap();

        // First approval
        let approval1 = GuardianApproval {
            guardian_id: "g1".to_string(),
            approved_at: 1700000000,
            verification_code: g1_code,
            approval_token: "TOKEN123".to_string(),
        };
        manager.submit_approval(&request_id, approval1).unwrap();

        let request = manager.get_recovery_request(&request_id).unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Pending);

        // Second approval - should meet threshold
        let approval2 = GuardianApproval {
            guardian_id: "g2".to_string(),
            approved_at: 1700000001,
            verification_code: g2_code,
            approval_token: "TOKEN456".to_string(),
        };
        manager.submit_approval(&request_id, approval2).unwrap();

        let request = manager.get_recovery_request(&request_id).unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Approved);
    }
}
