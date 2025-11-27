//! Recovery mechanisms for ZHTP Identity

pub mod recovery_phrases;
pub mod biometric_recovery;
pub mod guardian;
pub mod guardian_manager;

// Re-exports
pub use recovery_phrases::*;
pub use biometric_recovery::*;
pub use guardian::*;
pub use guardian_manager::*;

// RecoveryKey now integrated into IdentityManager
pub use crate::identity::manager::RecoveryKey;
