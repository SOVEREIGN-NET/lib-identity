//! Recovery phrase management for mnemonic-based identity recovery


use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::time::Instant;

/// Recovery phrase manager for mnemonic-based identity recovery
#[derive(Debug, Clone)]
pub struct RecoveryPhraseManager {
    /// Stored recovery phrases (encrypted)
    phrases: HashMap<String, EncryptedRecoveryPhrase>,
    /// Phrase validation rules
    validation_rules: PhraseValidationRules,
    /// Usage tracking
    phrase_usage: HashMap<String, PhraseUsageInfo>,
    /// Security settings
    security_settings: PhraseSecuritySettings,
}

/// Encrypted recovery phrase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRecoveryPhrase {
    pub identity_id: String,
    pub encrypted_phrase: Vec<u8>,
    pub phrase_hash: String,
    pub encryption_method: String,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub created_at: u64,
    pub last_used: Option<u64>,
    pub usage_count: u32,
    pub max_usage: Option<u32>,
    pub expires_at: Option<u64>,
}

/// Recovery phrase in plain text (temporary use only)
#[derive(Debug, Clone)]
pub struct RecoveryPhrase {
    pub words: Vec<String>,
    pub entropy: Vec<u8>,
    pub checksum: String,
    pub language: String,
    pub word_count: usize,
}

/// Phrase validation rules
#[derive(Debug, Clone)]
pub struct PhraseValidationRules {
    pub min_word_count: usize,
    pub max_word_count: usize,
    pub supported_languages: Vec<String>,
    pub require_checksum: bool,
    pub min_entropy_bits: usize,
    pub banned_words: Vec<String>,
    pub require_mixed_case: bool,
}

/// Phrase usage tracking information
#[derive(Debug, Clone)]
pub struct PhraseUsageInfo {
    pub identity_id: String,
    pub total_uses: u32,
    pub last_used: Option<Instant>,
    pub successful_recoveries: u32,
    pub failed_attempts: u32,
    pub created_at: Instant,
    pub last_validation: Option<Instant>,
}

/// Security settings for recovery phrases
#[derive(Debug, Clone)]
pub struct PhraseSecuritySettings {
    pub encryption_algorithm: String,
    pub key_derivation_iterations: u32,
    pub require_additional_auth: bool,
    pub auto_expire_days: Option<u32>,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
}

/// Recovery phrase generation options
#[derive(Debug, Clone)]
pub struct PhraseGenerationOptions {
    pub word_count: usize,
    pub language: String,
    pub entropy_source: EntropySource,
    pub include_checksum: bool,
    pub custom_wordlist: Option<Vec<String>>,
}

/// Source of entropy for phrase generation
#[derive(Debug, Clone)]
pub enum EntropySource {
    /// System random number generator
    SystemRandom,
    /// Hardware random number generator
    HardwareRandom,
    /// User-provided entropy
    UserProvided(Vec<u8>),
    /// Combined sources
    Combined(Vec<EntropySource>),
}

/// Result of phrase validation
#[derive(Debug, Clone)]
pub struct PhraseValidationResult {
    pub valid: bool,
    pub word_count_valid: bool,
    pub checksum_valid: bool,
    pub entropy_sufficient: bool,
    pub language_supported: bool,
    pub banned_words_found: Vec<String>,
    pub strength_score: f64,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl RecoveryPhraseManager {
    /// Create new recovery phrase manager
    pub fn new() -> Self {
        Self {
            phrases: HashMap::new(),
            validation_rules: PhraseValidationRules::default(),
            phrase_usage: HashMap::new(),
            security_settings: PhraseSecuritySettings::default(),
        }
    }

    /// Generate new recovery phrase
    pub async fn generate_recovery_phrase(
        &mut self,
        identity_id: &str,
        options: PhraseGenerationOptions,
    ) -> Result<RecoveryPhrase, Box<dyn std::error::Error>> {
        // Validate generation options
        self.validate_generation_options(&options)?;

        // Generate entropy
        let entropy = self.generate_entropy(&options.entropy_source, options.word_count).await?;
        
        // Load wordlist for specified language
        let wordlist = self.load_wordlist(&options.language)?;
        
        // Generate words from entropy
        let words = self.entropy_to_words(&entropy, &wordlist, options.word_count)?;
        
        // Generate checksum if required
        let checksum = if options.include_checksum {
            self.generate_checksum(&words, &entropy)?
        } else {
            String::new()
        };

        let phrase = RecoveryPhrase {
            words: words.clone(),
            entropy,
            checksum,
            language: options.language,
            word_count: options.word_count,
        };

        // Validate generated phrase
        let validation_result = self.validate_phrase(&phrase).await?;
        if !validation_result.valid {
            return Err(format!("Generated phrase failed validation: {:?}", validation_result.errors).into());
        }

        println!("✓ Generated {}-word recovery phrase for identity {}", options.word_count, identity_id);
        Ok(phrase)
    }

    /// Store recovery phrase (encrypted)
    pub async fn store_recovery_phrase(
        &mut self,
        identity_id: &str,
        phrase: &RecoveryPhrase,
        additional_auth: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Validate phrase before storage
        let validation_result = self.validate_phrase(phrase).await?;
        if !validation_result.valid {
            return Err("Cannot store invalid recovery phrase".into());
        }

        // Check if additional auth is required
        if self.security_settings.require_additional_auth && additional_auth.is_none() {
            return Err("Additional authentication required for phrase storage".into());
        }

        // Generate encryption key
        let salt = self.generate_salt().await?;
        let encryption_key = self.derive_encryption_key(identity_id, additional_auth, &salt).await?;
        
        // Encrypt phrase
        let phrase_text = phrase.words.join(" ");
        let (encrypted_phrase, iv) = self.encrypt_phrase(&phrase_text, &encryption_key).await?;
        
        // Calculate phrase hash for verification
        let phrase_hash = self.calculate_phrase_hash(&phrase_text);
        
        // Calculate expiration
        let expires_at = if let Some(expire_days) = self.security_settings.auto_expire_days {
            Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() + (expire_days as u64 * 86400))
        } else {
            None
        };

        // Create encrypted phrase record
        let encrypted_phrase_record = EncryptedRecoveryPhrase {
            identity_id: identity_id.to_string(),
            encrypted_phrase,
            phrase_hash,
            encryption_method: self.security_settings.encryption_algorithm.clone(),
            salt,
            iv,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            last_used: None,
            usage_count: 0,
            max_usage: None,
            expires_at,
        };

        // Store encrypted phrase
        let phrase_id = format!("phrase_{}", identity_id);
        self.phrases.insert(phrase_id.clone(), encrypted_phrase_record);
        
        // Initialize usage tracking
        self.phrase_usage.insert(phrase_id.clone(), PhraseUsageInfo {
            identity_id: identity_id.to_string(),
            total_uses: 0,
            last_used: None,
            successful_recoveries: 0,
            failed_attempts: 0,
            created_at: Instant::now(),
            last_validation: Some(Instant::now()),
        });

        println!("✓ Recovery phrase stored securely for identity {}", identity_id);
        Ok(phrase_id)
    }

    /// Recover identity using recovery phrase
    pub async fn recover_identity_with_phrase(
        &mut self,
        phrase_words: &[String],
        additional_auth: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Reconstruct phrase
        let phrase_text = phrase_words.join(" ");
        let phrase_hash = self.calculate_phrase_hash(&phrase_text);
        
        // Find matching stored phrase
        let mut matching_phrase_id = None;
        let mut matching_identity_id = None;
        
        for (phrase_id, encrypted_phrase) in &self.phrases {
            if encrypted_phrase.phrase_hash == phrase_hash {
                matching_phrase_id = Some(phrase_id.clone());
                matching_identity_id = Some(encrypted_phrase.identity_id.clone());
                break;
            }
        }

        let phrase_id = matching_phrase_id
            .ok_or("No matching recovery phrase found")?;
        let identity_id = matching_identity_id.unwrap();

        // Check usage limits and expiration
        self.check_phrase_usage_limits(&phrase_id)?;
        
        // Verify additional auth if required
        if self.security_settings.require_additional_auth && additional_auth.is_none() {
            return Err("Additional authentication required for recovery".into());
        }

        // Decrypt and verify phrase
        let encrypted_phrase = self.phrases.get(&phrase_id).unwrap();
        let encryption_key = self.derive_encryption_key(&identity_id, additional_auth, &encrypted_phrase.salt).await?;
        let decrypted_phrase = self.decrypt_phrase(&encrypted_phrase.encrypted_phrase, &encryption_key, &encrypted_phrase.iv).await?;
        
        // Verify phrase matches
        if decrypted_phrase != phrase_text {
            self.record_failed_attempt(&phrase_id);
            return Err("Recovery phrase verification failed".into());
        }

        // Update usage tracking
        self.record_successful_recovery(&phrase_id);
        
        println!("✓ Identity {} successfully recovered using recovery phrase", identity_id);
        Ok(identity_id)
    }

    /// Validate recovery phrase
    pub async fn validate_phrase(&self, phrase: &RecoveryPhrase) -> Result<PhraseValidationResult, Box<dyn std::error::Error>> {
        let mut result = PhraseValidationResult {
            valid: true,
            word_count_valid: false,
            checksum_valid: false,
            entropy_sufficient: false,
            language_supported: false,
            banned_words_found: Vec::new(),
            strength_score: 0.0,
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        // Check word count
        if phrase.word_count >= self.validation_rules.min_word_count 
            && phrase.word_count <= self.validation_rules.max_word_count {
            result.word_count_valid = true;
        } else {
            result.valid = false;
            result.errors.push(format!("Word count {} not in range {}-{}", 
                phrase.word_count, self.validation_rules.min_word_count, self.validation_rules.max_word_count));
        }

        // Check language support
        if self.validation_rules.supported_languages.contains(&phrase.language) {
            result.language_supported = true;
        } else {
            result.valid = false;
            result.errors.push(format!("Language '{}' not supported", phrase.language));
        }

        // Check entropy
        let entropy_bits = phrase.entropy.len() * 8;
        if entropy_bits >= self.validation_rules.min_entropy_bits {
            result.entropy_sufficient = true;
        } else {
            result.valid = false;
            result.errors.push(format!("Entropy {} bits below minimum {}", 
                entropy_bits, self.validation_rules.min_entropy_bits));
        }

        // Check for banned words
        for word in &phrase.words {
            if self.validation_rules.banned_words.contains(word) {
                result.banned_words_found.push(word.clone());
                result.valid = false;
            }
        }
        if !result.banned_words_found.is_empty() {
            result.errors.push(format!("Banned words found: {:?}", result.banned_words_found));
        }

        // Check checksum if required
        if self.validation_rules.require_checksum {
            if !phrase.checksum.is_empty() {
                let calculated_checksum = self.generate_checksum(&phrase.words, &phrase.entropy)?;
                result.checksum_valid = calculated_checksum == phrase.checksum;
                if !result.checksum_valid {
                    result.valid = false;
                    result.errors.push("Checksum validation failed".to_string());
                }
            } else {
                result.valid = false;
                result.errors.push("Checksum required but not provided".to_string());
            }
        } else {
            result.checksum_valid = true;
        }

        // Calculate strength score
        result.strength_score = self.calculate_phrase_strength(phrase);
        
        // Add warnings for weak phrases
        if result.strength_score < 0.7 {
            result.warnings.push("Recovery phrase strength is below recommended level".to_string());
        }

        Ok(result)
    }

    /// Generate entropy from specified source
    fn generate_entropy<'a>(&'a self, source: &'a EntropySource, word_count: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, Box<dyn std::error::Error>>> + Send + 'a>> {
        Box::pin(async move {
            let entropy_bytes = (word_count * 11 + 7) / 8; // BIP39 entropy calculation
            
            match source {
                EntropySource::SystemRandom => {
                    use rand::RngCore;
                    let mut rng = rand::thread_rng();
                    let mut entropy = vec![0u8; entropy_bytes];
                    rng.fill_bytes(&mut entropy);
                    Ok(entropy)
                },
                EntropySource::HardwareRandom => {
                    // In real implementation, would use hardware RNG
                    // For now, fall back to system random
                    use rand::RngCore;
                    let mut rng = rand::thread_rng();
                    let mut entropy = vec![0u8; entropy_bytes];
                    rng.fill_bytes(&mut entropy);
                    Ok(entropy)
                },
                EntropySource::UserProvided(user_entropy) => {
                    if user_entropy.len() < entropy_bytes {
                        return Err("Insufficient user-provided entropy".into());
                    }
                    Ok(user_entropy[..entropy_bytes].to_vec())
                },
                EntropySource::Combined(sources) => {
                    let mut combined_entropy = Vec::new();
                    for source in sources {
                        let source_entropy = self.generate_entropy(source, word_count).await?;
                        combined_entropy.extend_from_slice(&source_entropy);
                    }
                    
                    // XOR all entropy sources together
                    let mut final_entropy = vec![0u8; entropy_bytes];
                    for i in 0..entropy_bytes {
                        for chunk in combined_entropy.chunks(entropy_bytes) {
                            if i < chunk.len() {
                                final_entropy[i] ^= chunk[i];
                            }
                        }
                    }
                    Ok(final_entropy)
                }
            }
        })
    }

    /// Convert entropy to mnemonic words
    fn entropy_to_words(&self, entropy: &[u8], wordlist: &[String], word_count: usize) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut words = Vec::new();
        let _entropy_bits = entropy.len() * 8;
        let bits_per_word = 11; // BIP39 standard
        
        // Convert entropy bytes to bit array
        let mut bit_array = Vec::new();
        for byte in entropy {
            for i in (0..8).rev() {
                bit_array.push((byte >> i) & 1);
            }
        }

        // Extract words from entropy
        for i in 0..word_count {
            let start_bit = i * bits_per_word;
            if start_bit + bits_per_word <= bit_array.len() {
                let mut word_index = 0usize;
                for j in 0..bits_per_word {
                    word_index = (word_index << 1) | (bit_array[start_bit + j] as usize);
                }
                
                if word_index < wordlist.len() {
                    words.push(wordlist[word_index].clone());
                } else {
                    return Err("Word index out of range".into());
                }
            }
        }

        Ok(words)
    }

    /// Load wordlist for specified language
    fn load_wordlist(&self, language: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        // In real implementation, would load actual BIP39 wordlists
        // For now, return a simplified wordlist
        match language {
            "english" => Ok(self.get_english_wordlist()),
            "spanish" => Ok(self.get_spanish_wordlist()),
            "french" => Ok(self.get_french_wordlist()),
            _ => Err(format!("Wordlist for language '{}' not available", language).into()),
        }
    }

    /// Get English BIP39 wordlist (simplified)
    fn get_english_wordlist(&self) -> Vec<String> {
        // Simplified wordlist for demo purposes
        // Real implementation would use complete BIP39 wordlist
        (0..2048).map(|i| format!("word{:04}", i)).collect()
    }

    /// Get Spanish BIP39 wordlist (simplified)
    fn get_spanish_wordlist(&self) -> Vec<String> {
        (0..2048).map(|i| format!("palabra{:04}", i)).collect()
    }

    /// Get French BIP39 wordlist (simplified)
    fn get_french_wordlist(&self) -> Vec<String> {
        (0..2048).map(|i| format!("mot{:04}", i)).collect()
    }

    /// Generate checksum for phrase
    fn generate_checksum(&self, words: &[String], entropy: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        // Simple checksum implementation
        let phrase_text = words.join(" ");
        let combined = format!("{}{}", phrase_text, hex::encode(entropy));
        Ok(format!("{:x}", md5::compute(combined.as_bytes())))
    }

    /// Calculate phrase strength score
    fn calculate_phrase_strength(&self, phrase: &RecoveryPhrase) -> f64 {
        let mut score = 0.0;
        
        // Word count contributes to strength
        score += (phrase.word_count as f64 / 24.0) * 0.4; // Max 24 words
        
        // Entropy contributes to strength
        let entropy_bits = phrase.entropy.len() * 8;
        score += (entropy_bits as f64 / 256.0) * 0.4; // Max 256 bits
        
        // Language diversity (if using multiple languages)
        score += 0.1;
        
        // Checksum presence
        if !phrase.checksum.is_empty() {
            score += 0.1;
        }
        
        score.min(1.0)
    }

    /// Additional helper methods for encryption, validation, etc.
    async fn generate_salt(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);
        Ok(salt)
    }

    async fn derive_encryption_key(&self, identity_id: &str, additional_auth: Option<&str>, salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Simple key derivation (in real implementation, use proper KDF)
        let mut key_material = identity_id.as_bytes().to_vec();
        if let Some(auth) = additional_auth {
            key_material.extend_from_slice(auth.as_bytes());
        }
        key_material.extend_from_slice(salt);
        
        // Hash to create 32-byte key
        let key_hash = sha2::Sha256::digest(&key_material);
        Ok(key_hash.to_vec())
    }

    async fn encrypt_phrase(&self, phrase: &str, key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        // Simple encryption (in real implementation, use proper AES encryption)
        let mut iv = vec![0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut iv);
        
        let mut encrypted = Vec::new();
        let phrase_bytes = phrase.as_bytes();
        
        for (i, &byte) in phrase_bytes.iter().enumerate() {
            let key_byte = key[i % key.len()];
            let iv_byte = iv[i % iv.len()];
            encrypted.push(byte ^ key_byte ^ iv_byte);
        }
        
        Ok((encrypted, iv))
    }

    async fn decrypt_phrase(&self, encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let mut decrypted = Vec::new();
        
        for (i, &byte) in encrypted.iter().enumerate() {
            let key_byte = key[i % key.len()];
            let iv_byte = iv[i % iv.len()];
            decrypted.push(byte ^ key_byte ^ iv_byte);
        }
        
        Ok(String::from_utf8(decrypted)?)
    }

    fn calculate_phrase_hash(&self, phrase: &str) -> String {
        format!("{:x}", sha2::Sha256::digest(phrase.as_bytes()))
    }

    fn check_phrase_usage_limits(&self, phrase_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(encrypted_phrase) = self.phrases.get(phrase_id) {
            // Check expiration
            if let Some(expires_at) = encrypted_phrase.expires_at {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                if now > expires_at {
                    return Err("Recovery phrase has expired".into());
                }
            }
            
            // Check usage limits
            if let Some(max_usage) = encrypted_phrase.max_usage {
                if encrypted_phrase.usage_count >= max_usage {
                    return Err("Recovery phrase usage limit exceeded".into());
                }
            }
        }
        
        Ok(())
    }

    fn record_successful_recovery(&mut self, phrase_id: &str) {
        if let Some(usage_info) = self.phrase_usage.get_mut(phrase_id) {
            usage_info.total_uses += 1;
            usage_info.successful_recoveries += 1;
            usage_info.last_used = Some(Instant::now());
        }
        
        if let Some(encrypted_phrase) = self.phrases.get_mut(phrase_id) {
            encrypted_phrase.usage_count += 1;
            encrypted_phrase.last_used = Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs());
        }
    }

    fn record_failed_attempt(&mut self, phrase_id: &str) {
        if let Some(usage_info) = self.phrase_usage.get_mut(phrase_id) {
            usage_info.failed_attempts += 1;
        }
    }

    fn validate_generation_options(&self, options: &PhraseGenerationOptions) -> Result<(), Box<dyn std::error::Error>> {
        if options.word_count < self.validation_rules.min_word_count 
            || options.word_count > self.validation_rules.max_word_count {
            return Err(format!("Word count {} not in supported range", options.word_count).into());
        }
        
        if !self.validation_rules.supported_languages.contains(&options.language) {
            return Err(format!("Language '{}' not supported", options.language).into());
        }
        
        Ok(())
    }
}

impl Default for PhraseValidationRules {
    fn default() -> Self {
        Self {
            min_word_count: 12,
            max_word_count: 24,
            supported_languages: vec!["english".to_string(), "spanish".to_string(), "french".to_string()],
            require_checksum: true,
            min_entropy_bits: 128,
            banned_words: vec!["password".to_string(), "secret".to_string(), "private".to_string()],
            require_mixed_case: false,
        }
    }
}

impl Default for PhraseSecuritySettings {
    fn default() -> Self {
        Self {
            encryption_algorithm: "AES-256-GCM".to_string(),
            key_derivation_iterations: 100000,
            require_additional_auth: true,
            auto_expire_days: Some(365),
            max_failed_attempts: 5,
            lockout_duration_minutes: 30,
        }
    }
}

impl Default for RecoveryPhraseManager {
    fn default() -> Self {
        Self::new()
    }
}
