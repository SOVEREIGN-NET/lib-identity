//! ZHTP Identity Management Package
//! 
//! Zero-knowledge identity system with quantum-resistant cryptography and privacy-preserving
//! identity verification. Supports complete citizen onboarding with automatic UBI, DAO governance,
//! and Web4 service access.
//! 
//! ## Primary API
//! 
//! Use `IdentityManager::create_citizen_identity()` for complete citizen onboarding with:
//! - Soulbound ZK-DID (1:1 per human)
//! - Quantum-resistant wallets with 20-word seed phrases  
//! - DAO governance registration
//! - UBI payout registration
//! - Web4 service access
//! - Privacy-preserving credentials

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
pub mod auth;
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
pub use did::{
    DidDocument, ServiceEndpoint, VerificationMethod
};
pub use recovery::{RecoveryPhraseManager, RecoveryPhrase, PhraseGenerationOptions, EntropySource};
pub use wallets::{WalletManager, QuantumWallet, WalletType, WalletId, WalletSummary};
pub use auth::{PasswordManager, PasswordError, PasswordValidation, SessionToken};

// External dependencies re-exports
pub use lib_crypto as crypto;
pub use lib_proofs::{ZeroKnowledgeProof, ZkProof};

// Utility functions
use anyhow::Result;
use rand;

/// Initialize the identity system with proper configuration
pub async fn initialize_identity_system() -> Result<IdentityManager> {
    tracing::info!("Initializing ZHTP Identity Management System");
    Ok(IdentityManager::new())
}













/// Create a standalone wallet without requiring a full identity (for network nodes)
pub async fn create_standalone_wallet(
    wallet_name: String,
    alias: Option<String>,
) -> Result<(WalletId, String)> {
    use crate::wallets::{WalletManager, WalletType};
    use lib_crypto::Hash;
    
    // Create a temporary identity ID for the standalone wallet
    let temp_identity_id = Hash::from_bytes(&rand::random::<[u8; 32]>());
    let mut wallet_manager = WalletManager::new(temp_identity_id);
    
    // Create wallet with seed phrase
    let (wallet_id, seed_phrase_struct) = wallet_manager.create_wallet_with_seed_phrase(
        WalletType::Standard,
        wallet_name,
        alias,
    ).await?;
    
    // Convert RecoveryPhrase to string (20 words joined by spaces)
    let seed_phrase_string = seed_phrase_struct.words.join(" ");
    
    Ok((wallet_id, seed_phrase_string))
}

/// Demonstrate hierarchical DAO wallet functionality
/// This showcases advanced DAO-to-DAO ownership and control structures
pub async fn demonstrate_hierarchical_dao_system() -> Result<String> {
    use crate::wallets::dao_hierarchy_demo;
    
    tracing::info!(" Starting hierarchical DAO system demonstration");
    
    dao_hierarchy_demo::demonstrate_dao_hierarchy()?;
    
    Ok("Hierarchical DAO system demonstration completed successfully. Check logs for detailed output.".to_string())
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
