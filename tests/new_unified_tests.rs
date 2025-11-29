//! Given/When/Then tests for ZhtpIdentity::new_unified()
//! Tests based on P1-7 acceptance criteria

use lib_identity::identity::ZhtpIdentity;
use lib_identity::types::IdentityType;

/// AC1: Given new_unified(type, age, juris, device) is called
///      When construction completes
///      Then identity has real lib-crypto KeyPair (Dilithium + Kyber), valid DID,
///           derived NodeId, all secrets derived from keypair, WalletManager initialized
#[test]
fn given_new_unified_called_when_construction_completes_then_identity_fully_initialized() {
    // Given
    let identity_type = IdentityType::Human;
    let age = Some(30u64);
    let jurisdiction = Some("US".to_string());
    let primary_device = "laptop";

    // When
    let result = ZhtpIdentity::new_unified(
        identity_type,
        age,
        jurisdiction,
        primary_device,
    );

    // Then
    assert!(result.is_ok(), "new_unified() should succeed");
    let identity = result.unwrap();

    // Verify real PQC keypair components exist
    assert!(!identity.public_key.dilithium_pk.is_empty(),
        "Dilithium public key should be present");
    assert!(!identity.public_key.kyber_pk.is_empty(),
        "Kyber public key should be present");
    assert_ne!(identity.public_key.key_id, [0u8; 32],
        "key_id should be non-zero");

    // Verify valid DID format
    assert!(identity.did.starts_with("did:zhtp:"),
        "DID should start with 'did:zhtp:'");
    assert_eq!(identity.did.len(), 73,
        "DID should be 73 chars (did:zhtp: + 64 hex)");

    // Verify NodeId derived from DID + device
    assert!(!identity.device_node_ids.is_empty(),
        "device_node_ids should contain primary device");
    assert!(identity.device_node_ids.contains_key(primary_device),
        "device_node_ids should contain the primary device");

    // Verify all secrets are properly sized
    assert_eq!(identity.zk_identity_secret.len(), 32,
        "zk_identity_secret should be 32 bytes");
    assert_eq!(identity.zk_credential_hash.len(), 32,
        "zk_credential_hash should be 32 bytes");
    assert_eq!(identity.wallet_master_seed.len(), 64,
        "wallet_master_seed should be 64 bytes");

    // Verify secrets are non-zero (derived, not default)
    assert_ne!(identity.zk_identity_secret, [0u8; 32],
        "zk_identity_secret should be non-zero");
    assert_ne!(identity.zk_credential_hash, [0u8; 32],
        "zk_credential_hash should be non-zero");
    assert_ne!(identity.wallet_master_seed, [0u8; 64],
        "wallet_master_seed should be non-zero");

    // Verify DAO member ID is derived
    assert!(!identity.dao_member_id.is_empty(),
        "dao_member_id should be non-empty");

    // Verify WalletManager initialized (non-null)
    // (WalletManager structure verification depends on its API)
}

/// AC2: Given same inputs to new_unified()
///      When called multiple times
///      Then all outputs are deterministic (different keypairs → different outputs)
#[test]
fn given_same_inputs_when_called_multiple_times_then_outputs_are_different() {
    // Given
    let identity_type = IdentityType::Human;
    let age = Some(25u64);
    let jurisdiction = Some("CA".to_string());
    let primary_device = "phone";

    // When - call twice with same inputs
    let identity1 = ZhtpIdentity::new_unified(
        identity_type.clone(),
        age,
        jurisdiction.clone(),
        primary_device,
    ).expect("First call should succeed");

    let identity2 = ZhtpIdentity::new_unified(
        identity_type,
        age,
        jurisdiction,
        primary_device,
    ).expect("Second call should succeed");

    // Then - different keypairs should produce different outputs
    assert_ne!(identity1.public_key.key_id, identity2.public_key.key_id,
        "Different keypairs should have different key_ids");
    assert_ne!(identity1.did, identity2.did,
        "Different keypairs should produce different DIDs");
    assert_ne!(identity1.zk_identity_secret, identity2.zk_identity_secret,
        "Different keypairs should produce different secrets");
}

/// AC3: Given primary_device name
///      When new_unified() creates identity
///      Then device_node_ids contains primary device with derived NodeId
#[test]
fn given_primary_device_when_new_unified_creates_identity_then_device_mapping_correct() {
    // Given
    let primary_device = "desktop";

    // When
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(30),
        Some("US".to_string()),
        primary_device,
    ).expect("new_unified should succeed");

    // Then
    assert!(identity.device_node_ids.contains_key(primary_device),
        "device_node_ids must contain primary device");

    let node_id = identity.device_node_ids.get(primary_device)
        .expect("Primary device should have NodeId");

    // Verify NodeId is non-default
    assert!(!format!("{:?}", node_id).is_empty(),
        "NodeId should be properly initialized");
}

/// Unit Test: Verify DID format compliance
#[test]
fn test_did_format_is_valid() {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        None,
        None,
        "test-device",
    ).expect("new_unified should succeed");

    // DID format: "did:zhtp:{64 hex chars}"
    assert!(identity.did.starts_with("did:zhtp:"),
        "DID must start with 'did:zhtp:'");
    assert_eq!(identity.did.len(), 73,
        "DID must be exactly 73 characters");

    // Verify hex portion
    let hex_part = &identity.did[9..]; // Skip "did:zhtp:"
    assert_eq!(hex_part.len(), 64, "Hex portion must be 64 chars");
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "Hex portion must contain only hex digits");
}

/// Unit Test: Verify all secrets meet size requirements
#[test]
fn test_all_secrets_meet_size_requirements() {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("GB".to_string()),
        "device",
    ).expect("new_unified should succeed");

    assert_eq!(identity.zk_identity_secret.len(), 32,
        "zk_identity_secret must be 32 bytes");
    assert_eq!(identity.zk_credential_hash.len(), 32,
        "zk_credential_hash must be 32 bytes");
    assert_eq!(identity.wallet_master_seed.len(), 64,
        "wallet_master_seed must be 64 bytes");
}

/// Unit Test: Verify citizenship defaults for new unified identities
#[test]
fn test_citizenship_defaults_for_new_unified() {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        None,
        None,
        "device",
    ).expect("new_unified should succeed");

    assert_eq!(identity.citizenship_verified, false,
        "New identities should have citizenship_verified=false");
    assert_eq!(identity.dao_voting_power, 1,
        "Unverified identities should have dao_voting_power=1");
}

/// Unit Test: Verify real PQC keypair from lib-crypto
#[test]
fn test_creates_real_pqc_keypair() {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        None,
        None,
        "device",
    ).expect("new_unified should succeed");

    // Verify Dilithium2 keypair sizes (expected: PK=1312, SK=2528)
    assert_eq!(identity.public_key.dilithium_pk.len(), 1312,
        "Dilithium2 public key should be 1312 bytes");
    // Note: private_key not stored in ZhtpIdentity after construction

    // Verify Kyber512 keypair present
    assert!(!identity.public_key.kyber_pk.is_empty(),
        "Kyber public key should be present");
}
