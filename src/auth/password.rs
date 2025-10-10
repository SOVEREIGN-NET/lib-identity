//! Password management using lib-crypto hashing and key derivation
//! 
//! Only allows password authentication for identities that have been imported
//! using 20-word seed phrases. Passwords are derived from identity seeds.

use anyhow::Result;
use lib_crypto::{hash_blake3, derive_keys};
use crate::types::IdentityId;
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub enum PasswordError {
    IdentityNotImported,
    InvalidPassword,
    PasswordNotSet,
    WeakPassword,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::IdentityNotImported => write!(f, "Identity must be imported via 20-word phrase before setting password"),
            PasswordError::InvalidPassword => write!(f, "Invalid password"),
            PasswordError::PasswordNotSet => write!(f, "No password set for this identity"),
            PasswordError::WeakPassword => write!(f, "Password too weak - minimum 8 characters"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Password validation result
#[derive(Debug, Clone)]
pub struct PasswordValidation {
    pub valid: bool,
    pub identity_id: IdentityId,
    pub validated_at: u64,
}

/// Secure password hash with salt
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct PasswordHash {
    pub hash: [u8; 32],
    pub salt: [u8; 32],
    pub created_at: u64,
}

/// Password manager for identities
pub struct PasswordManager {
    /// Password hashes for imported identities only
    password_hashes: HashMap<IdentityId, PasswordHash>,
    /// Track which identities have been imported (from seed phrases)
    imported_identities: HashMap<IdentityId, u64>, // identity_id -> import_timestamp
}

impl PasswordManager {
    pub fn new() -> Self {
        Self {
            password_hashes: HashMap::new(),
            imported_identities: HashMap::new(),
        }
    }

    /// Mark an identity as imported (can set password after this)
    pub fn mark_identity_imported(&mut self, identity_id: &IdentityId) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.imported_identities.insert(identity_id.clone(), timestamp);
        
        tracing::info!(
            " Identity {} marked as imported - can now set password",
            hex::encode(&identity_id.0[..8])
        );
    }

    /// Check if identity has been imported
    pub fn is_identity_imported(&self, identity_id: &IdentityId) -> bool {
        self.imported_identities.contains_key(identity_id)
    }

    /// Set password for an imported identity
    pub fn set_password(&mut self, identity_id: &IdentityId, password: &str, identity_seed: &[u8]) -> Result<(), PasswordError> {
        // Check if identity is imported
        if !self.is_identity_imported(identity_id) {
            return Err(PasswordError::IdentityNotImported);
        }

        // Validate password strength
        if password.len() < 8 {
            return Err(PasswordError::WeakPassword);
        }

        // Generate salt using identity seed for consistency
        let salt_material = [
            identity_seed,
            identity_id.0.as_slice(),
            b"password_salt"
        ].concat();
        let salt = hash_blake3(&salt_material);

        // Derive password hash using HKDF with salt and identity context
        let password_key_material = [
            password.as_bytes(),
            &salt,
            identity_seed,
            identity_id.0.as_slice()
        ].concat();
        
        // Use HKDF to derive secure password hash
        let derived_key = derive_keys(
            &password_key_material,
            b"ZHTP_password_derivation_v1",
            32
        ).map_err(|_| PasswordError::WeakPassword)?;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&derived_key[..32]);

        let password_hash = PasswordHash {
            hash,
            salt,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.password_hashes.insert(identity_id.clone(), password_hash);

        tracing::info!(
            " Password set for identity {}",
            hex::encode(&identity_id.0[..8])
        );

        Ok(())
    }

    /// Validate password for an identity
    pub fn validate_password(&self, identity_id: &IdentityId, password: &str, identity_seed: &[u8]) -> Result<PasswordValidation, PasswordError> {
        // Check if identity is imported
        if !self.is_identity_imported(identity_id) {
            return Err(PasswordError::IdentityNotImported);
        }

        // Get stored password hash
        let stored_hash = self.password_hashes.get(identity_id)
            .ok_or(PasswordError::PasswordNotSet)?;

        // Recreate password hash using same process
        let password_key_material = [
            password.as_bytes(),
            &stored_hash.salt,
            identity_seed,
            identity_id.0.as_slice()
        ].concat();

        // Derive hash using same method
        let derived_key = derive_keys(
            &password_key_material,
            b"ZHTP_password_derivation_v1",
            32
        ).map_err(|_| PasswordError::InvalidPassword)?;

        let mut test_hash = [0u8; 32];
        test_hash.copy_from_slice(&derived_key[..32]);

        // Constant-time comparison
        let valid = constant_time_eq(&test_hash, &stored_hash.hash);

        if valid {
            tracing::info!(
                " Password validation successful for identity {}",
                hex::encode(&identity_id.0[..8])
            );
        } else {
            tracing::warn!(
                " Password validation failed for identity {}",
                hex::encode(&identity_id.0[..8])
            );
        }

        Ok(PasswordValidation {
            valid,
            identity_id: identity_id.clone(),
            validated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Check if password is set for an identity
    pub fn has_password(&self, identity_id: &IdentityId) -> bool {
        self.password_hashes.contains_key(identity_id)
    }

    /// Remove password for an identity
    pub fn remove_password(&mut self, identity_id: &IdentityId) -> bool {
        if let Some(mut hash) = self.password_hashes.remove(identity_id) {
            hash.zeroize();
            tracing::info!(
                "🗑️ Password removed for identity {}",
                hex::encode(&identity_id.0[..8])
            );
            true
        } else {
            false
        }
    }

    /// Get list of identities with passwords set
    pub fn list_identities_with_passwords(&self) -> Vec<&IdentityId> {
        self.password_hashes.keys().collect()
    }

    /// Get list of imported identities
    pub fn list_imported_identities(&self) -> Vec<&IdentityId> {
        self.imported_identities.keys().collect()
    }
}

/// Constant-time equality comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

impl Default for PasswordManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[test]
    fn test_password_manager_import_required() {
        let mut pm = PasswordManager::new();
        let identity_id = Hash::from_bytes(&[1u8; 32]);
        let seed = [42u8; 32];
        
        // Should fail before import
        assert!(pm.set_password(&identity_id, "password123", &seed).is_err());
        
        // Mark as imported
        pm.mark_identity_imported(&identity_id);
        
        // Should work after import
        assert!(pm.set_password(&identity_id, "password123", &seed).is_ok());
    }

    #[test]
    fn test_password_validation() {
        let mut pm = PasswordManager::new();
        let identity_id = Hash::from_bytes(&[2u8; 32]);
        let seed = [84u8; 32];
        let password = "test_password_123";
        
        pm.mark_identity_imported(&identity_id);
        pm.set_password(&identity_id, password, &seed).unwrap();
        
        // Correct password
        let validation = pm.validate_password(&identity_id, password, &seed).unwrap();
        assert!(validation.valid);
        
        // Wrong password
        let validation = pm.validate_password(&identity_id, "wrong", &seed).unwrap();
        assert!(!validation.valid);
    }
}