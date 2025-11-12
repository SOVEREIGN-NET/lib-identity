//! Backup Cryptography
//!
//! AES-256-GCM encryption and Argon2id key derivation for identity backups

use anyhow::{anyhow, Result};
use rand::Rng;

/// Encrypted backup container
#[derive(Debug, Clone)]
pub struct EncryptedBackup {
    /// Encrypted data
    pub ciphertext: Vec<u8>,

    /// Salt for key derivation
    pub salt: Vec<u8>,

    /// Nonce for AES-GCM
    pub nonce: Vec<u8>,
}

/// Backup encryption/decryption handler
pub struct BackupCrypto;

impl BackupCrypto {
    /// Derive encryption key from password using Argon2id
    pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; super::AES_KEY_LENGTH]> {
        use argon2::Argon2;
        use base64::{Engine as _, engine::general_purpose};

        // Configure Argon2id with our parameters
        let params = argon2::Params::new(
            super::ARGON2_MEMORY_SIZE,
            super::ARGON2_ITERATIONS,
            super::ARGON2_PARALLELISM,
            Some(super::AES_KEY_LENGTH),
        )
        .map_err(|e| anyhow!("Failed to create Argon2 params: {}", e))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        // Derive key directly into buffer
        let mut key = [0u8; super::AES_KEY_LENGTH];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

        Ok(key)
    }

    /// Generate random salt for key derivation
    pub fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; super::ARGON2_SALT_LENGTH];
        rand::thread_rng().fill(&mut salt[..]);
        salt
    }

    /// Generate random nonce for AES-GCM
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; super::AES_NONCE_LENGTH];
        rand::thread_rng().fill(&mut nonce[..]);
        nonce
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(plaintext: &[u8], password: &str) -> Result<EncryptedBackup> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // Generate salt and nonce
        let salt = Self::generate_salt();
        let nonce_bytes = Self::generate_nonce();

        // Derive encryption key from password
        let key_bytes = Self::derive_key(password, &salt)?;

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // Create nonce
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedBackup {
            ciphertext,
            salt,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(
        ciphertext: &[u8],
        password: &str,
        salt: &[u8],
        nonce_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // Derive decryption key from password
        let key_bytes = Self::derive_key(password, salt)?;

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // Create nonce
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed: invalid password or corrupted data"))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() {
        let password = "test_password_123";
        let salt = vec![42u8; 32];

        let key1 = BackupCrypto::derive_key(password, &salt).unwrap();
        let key2 = BackupCrypto::derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2, "Same password and salt should produce same key");
    }

    #[test]
    fn test_key_derivation_different_passwords() {
        let salt = vec![42u8; 32];

        let key1 = BackupCrypto::derive_key("password1", &salt).unwrap();
        let key2 = BackupCrypto::derive_key("password2", &salt).unwrap();

        assert_ne!(key1, key2, "Different passwords should produce different keys");
    }

    #[test]
    fn test_key_derivation_different_salts() {
        let password = "test_password";
        let salt1 = vec![1u8; 32];
        let salt2 = vec![2u8; 32];

        let key1 = BackupCrypto::derive_key(password, &salt1).unwrap();
        let key2 = BackupCrypto::derive_key(password, &salt2).unwrap();

        assert_ne!(key1, key2, "Different salts should produce different keys");
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let plaintext = b"Hello, World! This is a test message.";
        let password = "SecurePassword123";

        // Encrypt
        let encrypted = BackupCrypto::encrypt(plaintext, password).unwrap();

        // Decrypt
        let decrypted = BackupCrypto::decrypt(
            &encrypted.ciphertext,
            password,
            &encrypted.salt,
            &encrypted.nonce,
        )
        .unwrap();

        assert_eq!(plaintext, &decrypted[..], "Decrypted data should match original");
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let plaintext = b"Secret data";
        let password = "CorrectPassword";
        let wrong_password = "WrongPassword";

        // Encrypt
        let encrypted = BackupCrypto::encrypt(plaintext, password).unwrap();

        // Try to decrypt with wrong password
        let result = BackupCrypto::decrypt(
            &encrypted.ciphertext,
            wrong_password,
            &encrypted.salt,
            &encrypted.nonce,
        );

        assert!(result.is_err(), "Decryption with wrong password should fail");
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let plaintext = b"Test data";
        let password = "Password123";

        // Encrypt
        let mut encrypted = BackupCrypto::encrypt(plaintext, password).unwrap();

        // Corrupt ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        // Try to decrypt corrupted data
        let result = BackupCrypto::decrypt(
            &encrypted.ciphertext,
            password,
            &encrypted.salt,
            &encrypted.nonce,
        );

        assert!(result.is_err(), "Decryption of corrupted data should fail");
    }

    #[test]
    fn test_salt_generation_unique() {
        let salt1 = BackupCrypto::generate_salt();
        let salt2 = BackupCrypto::generate_salt();

        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2, "Generated salts should be unique");
    }

    #[test]
    fn test_nonce_generation_unique() {
        let nonce1 = BackupCrypto::generate_nonce();
        let nonce2 = BackupCrypto::generate_nonce();

        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2, "Generated nonces should be unique");
    }
}
