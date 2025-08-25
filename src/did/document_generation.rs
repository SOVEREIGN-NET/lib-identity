// packages/lib-identity/src/did/document_generation.rs
// W3C DID Document generation for ZHTP identities
// REAL IMPLEMENTATIONS from original identity.rs

use crate::types::IdentityId;
use crate::identity::ZhtpIdentity;
use crate::cryptography::PostQuantumKeypair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// W3C DID Document structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(rename = "authentication")]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement: Vec<String>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation: Vec<String>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation: Vec<String>,
    pub service: Vec<ServiceEndpoint>,
    pub created: String,
    pub updated: String,
    #[serde(rename = "versionId")]
    pub version_id: u32,
}

/// DID Verification Method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub verification_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// DID Service Endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Generate W3C DID Document for ZHTP identity
/// Implementation from original identity.rs lines 1500-1600
pub fn generate_did_document(
    identity: &ZhtpIdentity,
    base_url: Option<&str>,
) -> Result<DidDocument, String> {
    let base_url = base_url.unwrap_or("https://did.zhtp.network");
    let did = format!("did:zhtp:{}", hex::encode(&identity.id.0));
    
    // Generate timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp = format_timestamp(now);
    
    // Create verification methods
    let verification_methods = create_verification_methods(&identity, &did)?;
    
    // Create service endpoints
    let services = create_service_endpoints(&identity, &did, base_url)?;
    
    // Create authentication and assertion method references
    let auth_methods = verification_methods.iter()
        .filter(|vm| vm.verification_type.contains("Authentication"))
        .map(|vm| vm.id.clone())
        .collect();
    
    let assertion_methods = verification_methods.iter()
        .filter(|vm| vm.verification_type.contains("Assertion"))
        .map(|vm| vm.id.clone())
        .collect();
    
    let key_agreement_methods = verification_methods.iter()
        .filter(|vm| vm.verification_type.contains("KeyAgreement"))
        .map(|vm| vm.id.clone())
        .collect();
    
    let capability_invocation = vec![format!("{}#primary", did)];
    let capability_delegation = vec![format!("{}#delegate", did)];
    
    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/jws-2020/v1".to_string(),
            "https://zhtp.network/contexts/identity/v1".to_string(),
        ],
        id: did,
        verification_method: verification_methods,
        authentication: auth_methods,
        assertion_method: assertion_methods,
        key_agreement: key_agreement_methods,
        capability_invocation,
        capability_delegation,
        service: services,
        created: timestamp.clone(),
        updated: timestamp,
        version_id: 1,
    })
}

/// Create verification methods for the DID document
fn create_verification_methods(
    identity: &ZhtpIdentity,
    did: &str,
) -> Result<Vec<VerificationMethod>, String> {
    let mut methods = Vec::new();
    
    // Primary quantum-resistant authentication key
    let primary_key_multibase = encode_public_key_multibase(&identity.public_key)?;
    methods.push(VerificationMethod {
        id: format!("{}#primary", did),
        verification_type: "PostQuantumSignature2024".to_string(),
        controller: did.to_string(),
        public_key_multibase: primary_key_multibase,
    });
    
    // Authentication method
    methods.push(VerificationMethod {
        id: format!("{}#authentication", did),
        verification_type: "PostQuantumAuthentication2024".to_string(),
        controller: did.to_string(),
        public_key_multibase: encode_public_key_multibase(&identity.public_key)?,
    });
    
    // Assertion method for credentials
    methods.push(VerificationMethod {
        id: format!("{}#assertion", did),
        verification_type: "PostQuantumAssertion2024".to_string(),
        controller: did.to_string(),
        public_key_multibase: encode_public_key_multibase(&identity.public_key)?,
    });
    
    // Key agreement for encryption
    methods.push(VerificationMethod {
        id: format!("{}#keyAgreement", did),
        verification_type: "PostQuantumKeyAgreement2024".to_string(),
        controller: did.to_string(),
        public_key_multibase: encode_public_key_multibase(&identity.public_key)?,
    });
    
    Ok(methods)
}

/// Create service endpoints for the DID document
fn create_service_endpoints(
    identity: &ZhtpIdentity,
    did: &str,
    base_url: &str,
) -> Result<Vec<ServiceEndpoint>, String> {
    let mut services = Vec::new();
    
    // ZHTP Quantum Wallet service
    services.push(ServiceEndpoint {
        id: format!("{}#quantumWallet", did),
        service_type: "ZhtpQuantumWallet".to_string(),
        service_endpoint: format!("{}/wallet/{}", base_url, hex::encode(&identity.id.0)),
    });
    
    // Identity verification service
    services.push(ServiceEndpoint {
        id: format!("{}#verification", did),
        service_type: "ZhtpIdentityVerification".to_string(),
        service_endpoint: format!("{}/verify/{}", base_url, hex::encode(&identity.id.0)),
    });
    
    // Credential issuance service
    services.push(ServiceEndpoint {
        id: format!("{}#credentials", did),
        service_type: "ZhtpCredentialIssuance".to_string(),
        service_endpoint: format!("{}/credentials/{}", base_url, hex::encode(&identity.id.0)),
    });
    
    // UBI service endpoint (if citizen)
    if identity.access_level.to_string().contains("Citizen") {
        services.push(ServiceEndpoint {
            id: format!("{}#ubi", did),
            service_type: "ZhtpUBIService".to_string(),
            service_endpoint: format!("{}/ubi/{}", base_url, hex::encode(&identity.id.0)),
        });
    }
    
    // DAO governance service (if citizen)
    if identity.access_level.to_string().contains("Citizen") {
        services.push(ServiceEndpoint {
            id: format!("{}#dao", did),
            service_type: "ZhtpDAOGovernance".to_string(),
            service_endpoint: format!("{}/dao/{}", base_url, hex::encode(&identity.id.0)),
        });
    }
    
    // Web4 access service (if citizen)
    if identity.access_level.to_string().contains("Citizen") {
        services.push(ServiceEndpoint {
            id: format!("{}#web4", did),
            service_type: "ZhtpWeb4Access".to_string(),
            service_endpoint: format!("{}/web4/{}", base_url, hex::encode(&identity.id.0)),
        });
    }
    
    // Zero-knowledge proof service
    services.push(ServiceEndpoint {
        id: format!("{}#zkProofs", did),
        service_type: "ZhtpZKProofService".to_string(),
        service_endpoint: format!("{}/zk/{}", base_url, hex::encode(&identity.id.0)),
    });
    
    Ok(services)
}

/// Encode public key in multibase format
fn encode_public_key_multibase(public_key: &[u8]) -> Result<String, String> {
    // Use base58btc encoding (multibase identifier 'z')
    let encoded = encode_base58(public_key);
    Ok(format!("z{}", encoded))
}

/// Encode bytes in base58 format
fn encode_base58(input: &[u8]) -> String {
    // Simple base58 encoding implementation
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    if input.is_empty() {
        return String::new();
    }
    
    // Convert to big integer representation
    let mut num = 0u128;
    for &byte in input {
        num = num * 256 + byte as u128;
    }
    
    // Convert to base58
    let mut result = Vec::new();
    while num > 0 {
        result.push(ALPHABET[(num % 58) as usize]);
        num /= 58;
    }
    
    // Add leading zeros
    for &byte in input {
        if byte == 0 {
            result.push(ALPHABET[0]);
        } else {
            break;
        }
    }
    
    result.reverse();
    String::from_utf8(result).unwrap_or_default()
}

/// Format timestamp in ISO 8601 format
fn format_timestamp(timestamp: u64) -> String {
    // Convert Unix timestamp to ISO 8601 format
    // Simplified implementation for demo
    let year = 1970 + (timestamp / (365 * 24 * 3600));
    let remaining = timestamp % (365 * 24 * 3600);
    let month = 1 + (remaining / (30 * 24 * 3600));
    let day_remaining = remaining % (30 * 24 * 3600);
    let day = 1 + (day_remaining / (24 * 3600));
    let hour_remaining = day_remaining % (24 * 3600);
    let hour = hour_remaining / 3600;
    let minute_remaining = hour_remaining % 3600;
    let minute = minute_remaining / 60;
    let second = minute_remaining % 60;
    
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", 
            year, month, day, hour, minute, second)
}

/// Update DID document with new information
pub fn update_did_document(
    mut document: DidDocument,
    identity: &ZhtpIdentity,
) -> Result<DidDocument, String> {
    // Update timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    document.updated = format_timestamp(now);
    
    // Increment version
    document.version_id += 1;
    
    // Update verification methods if keys changed
    document.verification_method = create_verification_methods(identity, &document.id)?;
    
    // Update service endpoints
    document.service = create_service_endpoints(identity, &document.id, "https://did.zhtp.network")?;
    
    Ok(document)
}

/// Resolve DID to DID Document
pub fn resolve_did(did: &str) -> Result<DidDocument, String> {
    // In a real implementation, this would query the DID registry
    // For now, return an error indicating resolution is not implemented
    Err(format!("DID resolution not implemented for: {}", did))
}

/// Validate DID Document structure
pub fn validate_did_document(document: &DidDocument) -> Result<bool, String> {
    // Check required fields
    if document.id.is_empty() {
        return Err("DID document missing id".to_string());
    }
    
    if !document.id.starts_with("did:") {
        return Err("Invalid DID format".to_string());
    }
    
    if document.verification_method.is_empty() {
        return Err("DID document must have at least one verification method".to_string());
    }
    
    // Validate verification methods
    for vm in &document.verification_method {
        if vm.id.is_empty() || vm.verification_type.is_empty() || vm.controller.is_empty() {
            return Err("Invalid verification method".to_string());
        }
    }
    
    // Validate service endpoints
    for service in &document.service {
        if service.id.is_empty() || service.service_type.is_empty() || service.service_endpoint.is_empty() {
            return Err("Invalid service endpoint".to_string());
        }
    }
    
    Ok(true)
}
