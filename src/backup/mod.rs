//! Identity Backup Module
//!
//! Provides encrypted backup and restore functionality for complete citizen identities.
//!
//! Features:
//! - AES-256-GCM encryption
//! - Argon2id key derivation
//! - JSON backup format v1.0
//! - Password-protected export/import
//! - Integrity verification

pub mod manager;
pub mod format;
pub mod crypto;

pub use manager::BackupManager;
pub use format::{BackupFormat, BackupMetadata, BackupData};
pub use crypto::{BackupCrypto, EncryptedBackup};

use anyhow::Result;

/// Backup file version
pub const BACKUP_VERSION: &str = "1.0";

/// Backup file magic bytes (for file type detection)
pub const BACKUP_MAGIC: &[u8; 4] = b"ZHTP";

/// Argon2id parameters
pub const ARGON2_MEMORY_SIZE: u32 = 65536; // 64 MB
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const ARGON2_SALT_LENGTH: usize = 32;

/// AES-256-GCM parameters
pub const AES_KEY_LENGTH: usize = 32; // 256 bits
pub const AES_NONCE_LENGTH: usize = 12; // 96 bits (recommended for GCM)
pub const AES_TAG_LENGTH: usize = 16; // 128 bits

/// Backup verification result
#[derive(Debug, Clone)]
pub struct BackupVerification {
    pub valid: bool,
    pub version: String,
    pub created_at: u64,
    pub identity_id: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl BackupVerification {
    pub fn valid(version: String, created_at: u64, identity_id: String) -> Self {
        Self {
            valid: true,
            version,
            created_at,
            identity_id: Some(identity_id),
            errors: vec![],
            warnings: vec![],
        }
    }

    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            version: String::new(),
            created_at: 0,
            identity_id: None,
            errors,
            warnings: vec![],
        }
    }
}
