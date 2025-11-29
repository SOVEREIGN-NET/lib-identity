// P1-5: Add new identity fields to ZhtpIdentity struct
// Acceptance Criteria Tests

use lib_identity::identity::ZhtpIdentity;
use lib_identity::types::{IdentityType, NodeId, IdentityId, AccessLevel};
use lib_identity::wallets::WalletManager;
use lib_crypto::{PublicKey, PrivateKey};
use lib_proofs::ZeroKnowledgeProof;
use std::collections::HashMap;

// AC1: New fields added to ZhtpIdentity
// Given: ZhtpIdentity struct in lib_identity.rs
// When: new fields are added
// Then: struct includes did, node_id, device_node_ids, primary_device,
//       zk_identity_secret, zk_credential_hash, wallet_master_seed,
//       dao_member_id, dao_voting_power, citizenship_verified, jurisdiction
#[test]
fn test_zhtp_identity_has_required_fields() {
    let node_id = NodeId::from_did_device("did:zhtp:test123", "laptop")
        .expect("Valid NodeId");

    let mut device_node_ids = HashMap::new();
    device_node_ids.insert("laptop".to_string(), node_id);

    let identity = create_test_identity();

    // Verify all new fields are accessible
    assert_eq!(identity.did, "did:zhtp:test123");
    assert_eq!(identity.primary_device, "laptop");
    assert_eq!(identity.dao_voting_power, 100);
    assert_eq!(identity.citizenship_verified, true);
    assert_eq!(identity.jurisdiction, Some("US".to_string()));
    assert_eq!(identity.device_node_ids.len(), 1);
    assert_eq!(identity.zk_identity_secret.len(), 32);
    assert_eq!(identity.zk_credential_hash.len(), 32);
    assert_eq!(identity.wallet_master_seed.len(), 64);
}

// AC2: Correct types from lib-crypto
// Given: lib-crypto PublicKey/PrivateKey types
// When: fields are added
// Then: public_key is lib_crypto::PublicKey, private_key is Option<lib_crypto::PrivateKey>
#[test]
fn test_zhtp_identity_uses_lib_crypto_types() {
    let identity = create_test_identity();

    // Verify types at compile time - this test passes if it compiles
    let _pk: &PublicKey = &identity.public_key;
    let _sk: &Option<PrivateKey> = &identity.private_key;
}

// AC3: private_key uses serde(skip)
// Given: new fields with sensitive data
// When: Serialize trait is implemented
// Then: private_key uses serde(skip) to exclude private key
#[test]
fn test_private_key_not_serialized() {
    use serde_json;

    let mut identity = create_test_identity();
    // PrivateKey doesn't have Default, skip setting it for test

    let json = serde_json::to_string(&identity)
        .expect("Serialization should succeed");

    // Verify private_key is not in JSON
    assert!(!json.contains("private_key"),
            "private_key should be skipped in serialization");

    // Verify did IS in JSON (sanity check)
    assert!(json.contains("did:zhtp:test123"),
            "did should be present in serialization");
}

// AC4: Type corrections for existing fields
// Given: existing type inconsistencies
// When: fields are corrected
// Then: age: Option<u8> → Option<u64>, reputation: u32 → u64
#[test]
fn test_field_type_corrections() {
    let identity = create_test_identity();

    // Verify age is Option<u64>
    let _age: Option<u64> = identity.age;
    assert_eq!(identity.age, Some(30u64));

    // Verify reputation is u64
    let _reputation: u64 = identity.reputation;
    assert_eq!(identity.reputation, 1000u64);
}

// AC5: HashMap for device_node_ids
// Given: multi-device support requirement
// When: device_node_ids field is added
// Then: it maps device names (String) to NodeId
#[test]
fn test_device_node_ids_mapping() {
    let laptop_id = NodeId::from_did_device("did:zhtp:test123", "laptop")
        .expect("Valid NodeId");
    let phone_id = NodeId::from_did_device("did:zhtp:test123", "phone")
        .expect("Valid NodeId");

    let mut device_node_ids = HashMap::new();
    device_node_ids.insert("laptop".to_string(), laptop_id);
    device_node_ids.insert("phone".to_string(), phone_id);

    let mut identity = create_test_identity();
    identity.device_node_ids = device_node_ids;
    identity.primary_device = "laptop".to_string();

    // Verify mapping
    assert_eq!(identity.device_node_ids.len(), 2);
    assert!(identity.device_node_ids.contains_key("laptop"));
    assert!(identity.device_node_ids.contains_key("phone"));
    assert_eq!(identity.primary_device, "laptop");
}

// AC6: Fixed-size arrays for secrets
// Given: cryptographic secret fields
// When: fields are added
// Then: zk_identity_secret is [u8; 32], zk_credential_hash is [u8; 32],
//       wallet_master_seed is [u8; 64]
#[test]
fn test_secret_fields_fixed_sizes() {
    let mut identity = create_test_identity();

    // Verify compile-time sizes
    let _zk_secret: [u8; 32] = identity.zk_identity_secret;
    let _zk_hash: [u8; 32] = identity.zk_credential_hash;
    let _wallet_seed: [u8; 64] = identity.wallet_master_seed;

    // Set some test values
    identity.zk_identity_secret = [1u8; 32];
    identity.zk_credential_hash = [2u8; 32];
    identity.wallet_master_seed = [3u8; 64];

    assert_eq!(identity.zk_identity_secret.len(), 32);
    assert_eq!(identity.zk_credential_hash.len(), 32);
    assert_eq!(identity.wallet_master_seed.len(), 64);
}

// AC7: DAO fields present and correct types
// Given: DAO integration requirements
// When: DAO fields are added
// Then: dao_member_id is String, dao_voting_power is u64
#[test]
fn test_dao_fields() {
    let mut identity = create_test_identity();
    identity.dao_member_id = "dao_member_xyz".to_string();
    identity.dao_voting_power = 5000u64;

    // Verify types
    let _member_id: String = identity.dao_member_id.clone();
    let _voting_power: u64 = identity.dao_voting_power;

    assert_eq!(identity.dao_member_id, "dao_member_xyz");
    assert_eq!(identity.dao_voting_power, 5000);
}

// AC8: Citizenship fields present
// Given: jurisdiction verification requirements
// When: citizenship fields are added
// Then: citizenship_verified is bool, jurisdiction is Option<String>
#[test]
fn test_citizenship_fields() {
    let mut identity = create_test_identity();

    // Test verified citizen with jurisdiction
    identity.citizenship_verified = true;
    identity.jurisdiction = Some("US".to_string());

    assert_eq!(identity.citizenship_verified, true);
    assert_eq!(identity.jurisdiction, Some("US".to_string()));

    // Test unverified citizen
    identity.citizenship_verified = false;
    identity.jurisdiction = None;

    assert_eq!(identity.citizenship_verified, false);
    assert_eq!(identity.jurisdiction, None);
}

// Helper function to create test identity
fn create_test_identity() -> ZhtpIdentity {
    let node_id = NodeId::from_did_device("did:zhtp:test123", "laptop")
        .expect("Valid NodeId");

    let mut device_node_ids = HashMap::new();
    device_node_ids.insert("laptop".to_string(), node_id);

    ZhtpIdentity {
        id: lib_crypto::Hash::from_bytes(&[0u8; 32]),
        identity_type: IdentityType::Human,
        did: "did:zhtp:test123".to_string(),
        public_key: PublicKey::new(vec![1u8; 64]),
        private_key: None,
        node_id,
        device_node_ids,
        primary_device: "laptop".to_string(),
        zk_identity_secret: [0u8; 32],
        zk_credential_hash: [0u8; 32],
        wallet_master_seed: [0u8; 64],
        dao_member_id: "dao_member_123".to_string(),
        dao_voting_power: 100,
        citizenship_verified: true,
        jurisdiction: Some("US".to_string()),
        age: Some(30u64),
        reputation: 1000u64,
        created_at: 0,
        last_active: 0,
        recovery_keys: vec![],
        did_document_hash: None,
        owner_identity_id: None,
        reward_wallet_id: None,
        encrypted_master_seed: None,
        next_wallet_index: 0,
        password_hash: None,
        master_seed_phrase: None,
        attestations: vec![],
        wallet_manager: WalletManager::new(lib_crypto::Hash::from_bytes(&[0u8; 32])),
        ownership_proof: ZeroKnowledgeProof {
            proof_system: "test".to_string(),
            proof_data: vec![],
            public_inputs: vec![],
            verification_key: vec![],
            plonky2_proof: None,
            proof: vec![],
        },
        access_level: AccessLevel::default(),
        metadata: std::collections::HashMap::new(),
        credentials: std::collections::HashMap::new(),
        private_data_id: None,
    }
}
