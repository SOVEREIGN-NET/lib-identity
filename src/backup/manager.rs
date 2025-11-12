//! Backup Manager
//!
//! Coordinates backup export, import, and verification operations

use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};

use super::format::{
    BackupFormat, BackupMetadata, BackupData,
};
use super::crypto::{BackupCrypto};
use super::BackupVerification;

/// Backup Manager - handles encrypted backup operations
pub struct BackupManager;

impl BackupManager {
    /// Create new backup manager
    pub fn new() -> Self {
        Self
    }

    /// Export data to encrypted backup
    pub fn export_backup(
        &self,
        data: &BackupData,
        password: &str,
        identity_id: String,
        description: Option<String>,
    ) -> Result<String> {
        tracing::info!("📦 Exporting backup for identity {}", identity_id);

        // Serialize backup data to JSON
        let plaintext_json = data.to_json()?;

        // Encrypt backup data
        let encrypted = BackupCrypto::encrypt(&plaintext_json, password)?;

        // Calculate checksum
        let encrypted_b64 = general_purpose::STANDARD.encode(&encrypted.ciphertext);
        let checksum_bytes = lib_crypto::hash_blake3(encrypted_b64.as_bytes());
        let checksum = hex::encode(&checksum_bytes);

        // Create metadata
        let metadata = BackupMetadata {
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            format_version: super::BACKUP_VERSION.to_string(),
            identity_id,
            description,
            checksum,
        };

        // Create backup format
        let backup = BackupFormat::new(
            metadata,
            encrypted_b64,
            general_purpose::STANDARD.encode(&encrypted.salt),
            general_purpose::STANDARD.encode(&encrypted.nonce),
        );

        // Serialize to JSON
        let json = backup.to_json()?;

        tracing::info!("✓ Backup exported successfully ({} bytes)", json.len());

        Ok(json)
    }

    /// Import data from encrypted backup
    pub fn import_backup(&self, backup_json: &str, password: &str) -> Result<BackupData> {
        tracing::info!("📥 Importing backup");

        // Parse backup JSON
        let backup = BackupFormat::from_json(backup_json)?;

        // Verify integrity
        if !backup.verify_integrity() {
            return Err(anyhow!("Backup integrity check failed: checksum mismatch"));
        }

        tracing::debug!("✓ Backup integrity verified");

        // Decode base64 encrypted data, salt, and nonce
        let ciphertext = general_purpose::STANDARD.decode(&backup.encrypted_data)
            .map_err(|e| anyhow!("Invalid encrypted data encoding: {}", e))?;
        let salt = general_purpose::STANDARD.decode(&backup.salt)
            .map_err(|e| anyhow!("Invalid salt encoding: {}", e))?;
        let nonce = general_purpose::STANDARD.decode(&backup.nonce)
            .map_err(|e| anyhow!("Invalid nonce encoding: {}", e))?;

        // Decrypt backup data
        let plaintext = BackupCrypto::decrypt(&ciphertext, password, &salt, &nonce)?;

        tracing::debug!("✓ Backup decrypted successfully");

        // Parse decrypted JSON
        let backup_data = BackupData::from_json(&plaintext)?;

        tracing::info!("✓ Backup imported successfully");

        Ok(backup_data)
    }

    /// Verify backup without decrypting
    pub fn verify_backup(&self, backup_json: &str) -> Result<BackupVerification> {
        // Parse backup JSON
        let backup = match BackupFormat::from_json(backup_json) {
            Ok(b) => b,
            Err(e) => {
                return Ok(BackupVerification::invalid(vec![
                    format!("Invalid JSON format: {}", e)
                ]));
            }
        };

        // Verify integrity
        if !backup.verify_integrity() {
            return Ok(BackupVerification::invalid(vec![
                "Checksum mismatch: backup may be corrupted".to_string()
            ]));
        }

        // Verify version
        let mut warnings = Vec::new();
        if backup.version != super::BACKUP_VERSION {
            warnings.push(format!(
                "Version mismatch: backup is v{}, current version is v{}",
                backup.version,
                super::BACKUP_VERSION
            ));
        }

        Ok(BackupVerification {
            valid: true,
            version: backup.version,
            created_at: backup.metadata.created_at,
            identity_id: Some(backup.metadata.identity_id),
            errors: vec![],
            warnings,
        })
    }
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}
