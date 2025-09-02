//! Wallet types from the original identity.rs

use serde::{Deserialize, Serialize};
use lib_crypto::Hash;
use crate::types::IdentityId;

/// Wallet identifier
pub type WalletId = Hash;

/// Wallet types for different purposes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WalletType {
    /// Standard wallet for general use
    Standard,
    /// Primary wallet for daily transactions
    Primary,
    /// UBI wallet for automatic Universal Basic Income payouts
    UBI,
    /// Savings wallet for long-term storage
    Savings,
    /// Business wallet for commercial transactions
    Business,
    /// Stealth wallet for privacy-enhanced transactions
    Stealth,
}

/// Quantum-resistant wallet implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumWallet {
    /// Unique wallet identifier
    pub id: WalletId,
    /// Wallet type
    pub wallet_type: WalletType,
    /// Human-readable name
    pub name: String,
    /// Optional alias for quick access
    pub alias: Option<String>,
    /// Current balance in ZHTP tokens
    pub balance: u64,
    /// Staked balance for rewards
    pub staked_balance: u64,
    /// Pending rewards from staking
    pub pending_rewards: u64,
    /// Owner identity
    pub owner_id: IdentityId,
    /// Quantum-resistant public key
    pub public_key: Vec<u8>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last transaction timestamp
    pub last_transaction: Option<u64>,
    /// Transaction history (limited for performance)
    pub recent_transactions: Vec<Hash>,
    /// Wallet status
    pub is_active: bool,
}

/// Wallet summary for listing operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSummary {
    /// Wallet identifier
    pub id: WalletId,
    /// Wallet type
    pub wallet_type: WalletType,
    /// Human-readable name
    pub name: String,
    /// Optional alias
    pub alias: Option<String>,
    /// Current balance
    pub balance: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Last transaction timestamp
    pub last_transaction: Option<u64>,
    /// Number of recent transactions
    pub transaction_count: usize,
    /// Wallet status
    pub is_active: bool,
}

impl QuantumWallet {
    /// Create a new quantum wallet
    pub fn new(
        wallet_type: WalletType,
        name: String,
        alias: Option<String>,
        owner_id: IdentityId,
        public_key: Vec<u8>,
    ) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Generate wallet ID from owner ID and timestamp
        let wallet_data = [
            owner_id.as_bytes(),
            name.as_bytes(),
            &current_time.to_le_bytes(),
        ].concat();
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(&wallet_data));
        
        Self {
            id,
            wallet_type,
            name,
            alias,
            balance: 0,
            staked_balance: 0,
            pending_rewards: 0,
            owner_id,
            public_key,
            created_at: current_time,
            last_transaction: None,
            recent_transactions: Vec::new(),
            is_active: true,
        }
    }
    
    /// Add funds to the wallet
    pub fn add_funds(&mut self, amount: u64) {
        self.balance += amount;
        self.update_last_transaction();
    }
    
    /// Remove funds from the wallet (if sufficient balance)
    pub fn remove_funds(&mut self, amount: u64) -> Result<(), &'static str> {
        if self.balance >= amount {
            self.balance -= amount;
            self.update_last_transaction();
            Ok(())
        } else {
            Err("Insufficient balance")
        }
    }
    
    /// Update last transaction timestamp
    fn update_last_transaction(&mut self) {
        self.last_transaction = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }
    
    /// Add a transaction to recent history
    pub fn add_transaction(&mut self, tx_hash: Hash) {
        self.recent_transactions.push(tx_hash);
        // Keep only last 100 transactions for performance
        if self.recent_transactions.len() > 100 {
            self.recent_transactions.remove(0);
        }
        self.update_last_transaction();
    }
    
    /// Convert to summary for listing
    pub fn to_summary(&self) -> WalletSummary {
        WalletSummary {
            id: self.id.clone(),
            wallet_type: self.wallet_type.clone(),
            name: self.name.clone(),
            alias: self.alias.clone(),
            balance: self.balance,
            created_at: self.created_at,
            last_transaction: self.last_transaction,
            transaction_count: self.recent_transactions.len(),
            is_active: self.is_active,
        }
    }
    
    /// Check if wallet matches alias
    pub fn matches_alias(&self, alias: &str) -> bool {
        self.alias.as_ref().map_or(false, |a| a == alias)
    }
    
    /// Deactivate wallet
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
    
    /// Reactivate wallet
    pub fn activate(&mut self) {
        self.is_active = true;
    }

    /// Deduct funds from wallet (with proper error handling)
    pub fn deduct_funds(&mut self, amount: u64) -> Result<(), &'static str> {
        if self.balance >= amount {
            self.balance -= amount;
            self.update_last_transaction();
            Ok(())
        } else {
            Err("Insufficient balance")
        }
    }

    /// Add rewards to pending rewards
    pub fn add_rewards(&mut self, amount: u64) {
        self.pending_rewards += amount;
        self.update_last_transaction();
    }

    /// Check if wallet is healthy (basic health check)
    pub fn is_healthy(&self) -> bool {
        self.is_active && self.balance >= 0 // Balance is u64, so always >= 0, but this is for future extensibility
    }
}
