//! Wallet manager integration from the original identity.rs
//! 
//! This provides the WalletManager that was integrated into ZhtpIdentity

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use lib_crypto::Hash;
use crate::types::IdentityId;
use super::wallet_types::{WalletType, WalletId, QuantumWallet, WalletSummary};

/// Integrated wallet manager for identity-based wallet management
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletManager {
    /// Owner identity ID
    pub owner_id: IdentityId,
    /// Map of wallet ID to wallet
    pub wallets: HashMap<WalletId, QuantumWallet>,
    /// Map of alias to wallet ID for quick lookup
    pub alias_map: HashMap<String, WalletId>,
    /// Total balance across all wallets
    pub total_balance: u64,
    /// Creation timestamp
    pub created_at: u64,
}

impl WalletManager {
    /// Create a new wallet manager for an identity
    pub fn new(owner_id: IdentityId) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            owner_id,
            wallets: HashMap::new(),
            alias_map: HashMap::new(),
            total_balance: 0,
            created_at: current_time,
        }
    }
    
    /// Create a new wallet
    pub fn create_wallet(
        &mut self,
        wallet_type: WalletType,
        name: String,
        alias: Option<String>,
    ) -> Result<WalletId> {
        // Check if alias already exists
        if let Some(ref alias) = alias {
            if self.alias_map.contains_key(alias) {
                return Err(anyhow!("Wallet alias '{}' already exists", alias));
            }
        }
        
        // Generate quantum-resistant public key (simplified for now)
        let mut public_key = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut public_key);
        
        // Create the wallet
        let wallet = QuantumWallet::new(
            wallet_type,
            name,
            alias.clone(),
            self.owner_id.clone(),
            public_key,
        );
        
        let wallet_id = wallet.id.clone();
        
        // Store wallet
        self.wallets.insert(wallet_id.clone(), wallet);
        
        // Store alias mapping if provided
        if let Some(alias) = alias {
            self.alias_map.insert(alias, wallet_id.clone());
        }
        
        tracing::info!(
            "Created wallet {} for identity {}",
            hex::encode(&wallet_id.0[..8]),
            hex::encode(&self.owner_id.0[..8])
        );
        
        Ok(wallet_id)
    }
    
    /// Get wallet by ID
    pub fn get_wallet(&self, wallet_id: &WalletId) -> Option<&QuantumWallet> {
        self.wallets.get(wallet_id)
    }
    
    /// Get mutable wallet by ID
    pub fn get_wallet_mut(&mut self, wallet_id: &WalletId) -> Option<&mut QuantumWallet> {
        self.wallets.get_mut(wallet_id)
    }
    
    /// Get wallet by alias
    pub fn get_wallet_by_alias(&self, alias: &str) -> Option<&QuantumWallet> {
        self.alias_map.get(alias)
            .and_then(|wallet_id| self.wallets.get(wallet_id))
    }
    
    /// Get mutable wallet by alias
    pub fn get_wallet_by_alias_mut(&mut self, alias: &str) -> Option<&mut QuantumWallet> {
        let wallet_id = self.alias_map.get(alias).cloned();
        wallet_id.and_then(move |id| self.wallets.get_mut(&id))
    }
    
    /// List all wallets
    pub fn list_wallets(&self) -> Vec<WalletSummary> {
        self.wallets.values()
            .map(|wallet| wallet.to_summary())
            .collect()
    }
    
    /// Transfer funds between wallets
    pub fn transfer_between_wallets(
        &mut self,
        from_wallet: &WalletId,
        to_wallet: &WalletId,
        amount: u64,
        purpose: String,
    ) -> Result<Hash> {
        // Verify both wallets exist and belong to this identity
        if !self.wallets.contains_key(from_wallet) {
            return Err(anyhow!("Source wallet not found"));
        }
        if !self.wallets.contains_key(to_wallet) {
            return Err(anyhow!("Destination wallet not found"));
        }
        
        // Check source wallet has sufficient funds
        let source_balance = self.wallets[from_wallet].balance;
        if source_balance < amount {
            return Err(anyhow!("Insufficient funds in source wallet"));
        }
        
        // Generate transaction hash
        let tx_data = [
            from_wallet.as_bytes(),
            to_wallet.as_bytes(),
            &amount.to_le_bytes(),
            purpose.as_bytes(),
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_le_bytes(),
        ].concat();
        let tx_hash = Hash::from_bytes(&lib_crypto::hash_blake3(&tx_data));
        
        // Perform the transfer
        self.wallets.get_mut(from_wallet).unwrap().remove_funds(amount).map_err(|e| anyhow!(e))?;
        self.wallets.get_mut(to_wallet).unwrap().add_funds(amount);
        
        // Add transaction to both wallets' history
        self.wallets.get_mut(from_wallet).unwrap().add_transaction(tx_hash.clone());
        self.wallets.get_mut(to_wallet).unwrap().add_transaction(tx_hash.clone());
        
        tracing::info!(
            "Transferred {} ZHTP from wallet {} to wallet {} (purpose: {})",
            amount,
            hex::encode(&from_wallet.0[..8]),
            hex::encode(&to_wallet.0[..8]),
            purpose
        );
        
        Ok(tx_hash)
    }    /// Remove wallet (only if balance is zero)
    pub fn remove_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        if let Some(wallet) = self.wallets.get(wallet_id) {
            if wallet.balance > 0 {
                return Err(anyhow!("Cannot remove wallet with non-zero balance"));
            }
            
            // Remove alias mapping if exists
            if let Some(ref alias) = wallet.alias {
                self.alias_map.remove(alias);
            }
        }
        
        // Remove wallet
        self.wallets.remove(wallet_id);
        self.calculate_total_balance(); // Recalculate total
        
        Ok(())
    }
    
    /// Deactivate wallet
    pub fn deactivate_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        if let Some(wallet) = self.wallets.get_mut(wallet_id) {
            wallet.deactivate();
            Ok(())
        } else {
            Err(anyhow!("Wallet not found"))
        }
    }
    
    /// Reactivate wallet
    pub fn reactivate_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        if let Some(wallet) = self.wallets.get_mut(wallet_id) {
            wallet.activate();
            Ok(())
        } else {
            Err(anyhow!("Wallet not found"))
        }
    }
}
