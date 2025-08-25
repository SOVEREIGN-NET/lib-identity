//! Integration and verification modules for ZHTP Identity

pub mod cross_package_integration;
pub mod requirements_verification;
pub mod proof_generation;
pub mod trusted_issuers;
pub mod verification_cache;

// Re-exports
pub use cross_package_integration::*;
pub use requirements_verification::*;
pub use proof_generation::*;
pub use trusted_issuers::*;
pub use verification_cache::*;
