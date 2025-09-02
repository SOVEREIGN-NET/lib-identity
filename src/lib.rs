//! ZHTP Identity Management Package
//! 
//! Zero-knowledge identity system with quantum-resistant cryptography and privacy-preserving
//! identity verification. Supports complete citizen onboarding with automatic UBI, DAO governance,
//! and Web4 service access.

// Core modules
pub mod types;
pub mod identity;
pub mod credentials;
pub mod citizenship;
pub mod wallets;
pub mod did;
pub mod reputation;
pub mod recovery;
pub mod privacy;
pub mod cryptography;
pub mod economics;
pub mod integration;
pub mod verification;

// Re-exports for external use
pub use types::*;
pub use identity::{ZhtpIdentity, PrivateIdentityData, IdentityManager};
pub use credentials::{ZkCredential, IdentityAttestation, CredentialType, AttestationType};
pub use citizenship::{CitizenshipResult, DaoRegistration, UbiRegistration, Web4Access, WelcomeBonus};
pub use types::{AccessLevel, IdentityProofParams};
pub use types::IdentityVerification;

// External dependencies re-exports
pub use lib_crypto as crypto;
pub use lib_proofs::{ZeroKnowledgeProof, ZkProof};

// Utility functions
use anyhow::Result;

/// Initialize the identity system with proper configuration
pub async fn initialize_identity_system() -> Result<IdentityManager> {
    tracing::info!("🆔 Initializing ZHTP Identity Management System");
    Ok(IdentityManager::new())
}

/// Create a new citizen identity with complete onboarding
pub async fn create_citizen_identity(
    manager: &mut IdentityManager,
    recovery_options: Vec<String>,
    economic_model: &mut crate::economics::EconomicModel,
) -> Result<CitizenshipResult> {
    manager.create_citizen_identity(recovery_options, economic_model).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_identity_system_initialization() {
        let manager = initialize_identity_system().await.unwrap();
        assert_eq!(manager.list_identities().len(), 0);
    }
}
