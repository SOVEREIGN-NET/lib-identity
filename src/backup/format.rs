//! Backup Format Definition
//!
//! JSON structure for encrypted identity backups

use serde::{Deserialize, Serialize};
use crate::recovery::RecoveryPhrase;

/// Complete backup file structure (JSON)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFormat {
    /// File format version (e.g., "1.0")
    pub version: String,

    /// Metadata (unencrypted)
    pub metadata: BackupMetadata,

    /// Encrypted backup data (base64-encoded)
    pub encrypted_data: String,

    /// Encryption salt (base64-encoded)
    pub salt: String,

    /// Nonce for AES-GCM (base64-encoded)
    pub nonce: String,
}

/// Backup metadata (stored in plaintext for verification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Timestamp when backup was created (Unix epoch)
    pub created_at: u64,

    /// Application version that created backup
    pub app_version: String,

    /// Backup format version
    pub format_version: String,

    /// Identity ID (for verification, non-sensitive)
    pub identity_id: String,

    /// Optional description/label
    pub description: Option<String>,

    /// Checksum of encrypted data (for integrity verification)
    pub checksum: String,
}

/// Backup data (encrypted, JSON-serialized before encryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupData {
    /// Identity information
    pub identity: IdentityBackup,

    /// Wallet seed phrases (most sensitive data)
    pub seed_phrases: SeedPhrasesBackup,

    /// DAO registration data
    pub dao_registration: DaoBackup,

    /// UBI registration data
    pub ubi_registration: UbiBackup,

    /// Web4 access tokens
    pub web4_access: Web4Backup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBackup {
    pub identity_id: String,
    pub display_name: String,
    pub identity_type: String,
    pub access_level: String,
    pub created_at: u64,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedPhrasesBackup {
    pub primary_wallet: SeedPhraseData,
    pub ubi_wallet: SeedPhraseData,
    pub savings_wallet: SeedPhraseData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedPhraseData {
    pub words: Vec<String>,
    pub wallet_id: String,
    pub wallet_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoBackup {
    pub voting_power: u64,
    pub proposals_voted: Vec<String>,
    pub delegated_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiBackup {
    pub daily_amount: u64,
    pub last_claim: u64,
    pub total_claimed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4Backup {
    pub service_tokens: std::collections::HashMap<String, String>,
    pub active_sessions: Vec<String>,
}

impl BackupFormat {
    /// Create new backup format structure
    pub fn new(
        metadata: BackupMetadata,
        encrypted_data: String,
        salt: String,
        nonce: String,
    ) -> Self {
        Self {
            version: super::BACKUP_VERSION.to_string(),
            metadata,
            encrypted_data,
            salt,
            nonce,
        }
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Verify backup file integrity
    pub fn verify_integrity(&self) -> bool {
        // Verify checksum matches encrypted data
        let calculated_checksum = lib_crypto::hash_blake3(self.encrypted_data.as_bytes());
        let calculated_hex = hex::encode(&calculated_checksum);

        calculated_hex == self.metadata.checksum
    }
}

impl BackupData {
    /// Serialize to JSON for encryption
    pub fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize from decrypted JSON
    pub fn from_json(data: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(data)?)
    }
}
