//! NodeId - Canonical 20-byte DHT routing address
//!
//! NodeId is derived from a DID + device name combination, ensuring:
//! - Deterministic generation (same inputs → same NodeId)
//! - DHT compatibility (20 bytes matching future lib-dht UID)
//! - Multi-device support (one DID → many NodeIds)
//! - Strict validation (prevents malformed identities)

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use lib_crypto::Hash;

/// Canonical NodeId - 20-byte DHT routing address
///
/// Matches lib-dht UID size for perfect Phase 2 compatibility.
/// Generated deterministically from DID + device name.
///
/// # Size Rationale
/// - 20 bytes = 160 bits (standard DHT size)
/// - Compatible with BitTorrent DHT, Ethereum, Kademlia
/// - 2^160 ≈ 10^48 possible addresses
///
/// # Examples
/// ```
/// use lib_identity::types::NodeId;
///
/// // Valid creation
/// let node_id = NodeId::from_did_device(
///     "did:zhtp:abc123",
///     "laptop"
/// ).expect("Valid inputs");
///
/// // Same inputs produce same NodeId
/// let node_id2 = NodeId::from_did_device(
///     "did:zhtp:abc123",
///     "laptop"
/// ).expect("Valid inputs");
/// assert_eq!(node_id, node_id2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId([u8; 20]);

impl NodeId {
    /// Create NodeId from raw 20-byte array
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let bytes = [0x42; 20];
    /// let node_id = NodeId::from_bytes(bytes);
    /// assert_eq!(node_id.as_bytes(), &bytes);
    /// ```
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Get reference to underlying 20-byte array
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let bytes = [0x42; 20];
    /// let node_id = NodeId::from_bytes(bytes);
    /// assert_eq!(node_id.as_bytes(), &bytes);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Create NodeId from DID and device name
    ///
    /// Performs strict validation on both inputs and normalizes the device name
    /// (trimmed and lowercased) before hashing.
    ///
    /// # Validation Rules
    /// - DID must start with `did:zhtp:`
    /// - Device name must be 1-64 characters after trimming
    /// - Device name must match: `^[A-Za-z0-9._-]+$`
    ///
    /// # Errors
    /// Returns `Err` if validation fails. Never panics on invalid input.
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// // Valid inputs
    /// let node_id = NodeId::from_did_device(
    ///     "did:zhtp:abc123",
    ///     "laptop"
    /// ).expect("Valid inputs");
    ///
    /// // Case-insensitive device names
    /// let upper = NodeId::from_did_device("did:zhtp:abc123", "LAPTOP").unwrap();
    /// let lower = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();
    /// assert_eq!(upper, lower); // Same NodeId (normalized)
    ///
    /// // Invalid DID
    /// assert!(NodeId::from_did_device("invalid", "laptop").is_err());
    /// ```
    pub fn from_did_device(did: &str, device: &str) -> Result<Self> {
        // TODO: Will implement validation in next step
        unimplemented!("Validation logic coming in next checkpoint")
    }

    /// Convert NodeId to hex string (40 lowercase chars)
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let bytes = [0x42; 20];
    /// let node_id = NodeId::from_bytes(bytes);
    /// let hex = node_id.to_hex();
    /// assert_eq!(hex.len(), 40);
    /// ```
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create NodeId from hex string
    pub fn from_hex(hex: &str) -> Result<Self> {
        // TODO: Will implement in next step
        unimplemented!("Hex parsing coming in next checkpoint")
    }

    /// Calculate XOR distance to another NodeId (for Kademlia routing)
    pub fn xor_distance(&self, other: &NodeId) -> [u8; 20] {
        // TODO: Will implement in next step
        unimplemented!("XOR distance coming in next checkpoint")
    }

    /// Convert to 32-byte storage Hash (zero-padded)
    pub fn to_storage_hash(&self) -> Hash {
        // TODO: Will implement in next step
        unimplemented!("Storage hash conversion coming in next checkpoint")
    }

    /// Create NodeId from 32-byte storage Hash (takes first 20 bytes)
    pub fn from_storage_hash(hash: &Hash) -> Self {
        // TODO: Will implement in next step
        unimplemented!("Storage hash conversion coming in next checkpoint")
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ============================================================================
// TESTS - Written FIRST to define the contract (TDD)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // GIVEN valid DID and device name
    // WHEN NodeId::from_did_device() is called
    // THEN a deterministic 20-byte NodeId is generated
    // ------------------------------------------------------------------------

    #[test]
    fn test_from_did_device_valid_inputs() {
        // GIVEN: Valid DID and device name
        let did = "did:zhtp:abc123def456";
        let device = "laptop";

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(did, device);

        // THEN: Success with 20-byte NodeId
        assert!(result.is_ok(), "Should succeed with valid inputs");
        let node_id = result.unwrap();
        assert_eq!(node_id.as_bytes().len(), 20, "NodeId must be 20 bytes");
    }

    #[test]
    fn test_from_did_device_deterministic() {
        // GIVEN: Same DID and device name
        let did = "did:zhtp:abc123def456";
        let device = "laptop";

        // WHEN: Creating NodeId twice
        let node_id1 = NodeId::from_did_device(did, device).unwrap();
        let node_id2 = NodeId::from_did_device(did, device).unwrap();

        // THEN: Both NodeIds are identical
        assert_eq!(node_id1, node_id2, "Same inputs must produce same NodeId");
    }

    #[test]
    fn test_from_did_device_different_devices_different_nodeids() {
        // GIVEN: Same DID, different devices
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeIds for different devices
        let laptop = NodeId::from_did_device(did, "laptop").unwrap();
        let phone = NodeId::from_did_device(did, "phone").unwrap();

        // THEN: NodeIds are different
        assert_ne!(laptop, phone, "Different devices must have different NodeIds");
    }

    #[test]
    fn test_from_did_device_different_dids_different_nodeids() {
        // GIVEN: Different DIDs, same device
        let device = "laptop";

        // WHEN: Creating NodeIds for different DIDs
        let node1 = NodeId::from_did_device("did:zhtp:abc123", device).unwrap();
        let node2 = NodeId::from_did_device("did:zhtp:def456", device).unwrap();

        // THEN: NodeIds are different (proves DID is included in derivation)
        assert_ne!(node1, node2, "Different DIDs must produce different NodeIds");
    }

    #[test]
    fn test_from_did_device_golden_vector() {
        // GIVEN: Known DID and device (golden test vector)
        let did = "did:zhtp:0123456789abcdef";
        let device = "test-device";

        // WHEN: Creating NodeId
        let node = NodeId::from_did_device(did, device).unwrap();

        // THEN: Produces expected hex output (locks derivation algorithm)
        // This is Blake3("ZHTP_NODE_V2:did:zhtp:0123456789abcdef:test-device")[0..20]
        let expected_hex = node.to_hex(); // Will compute actual value

        // Verify determinism by recreating
        let node2 = NodeId::from_did_device(did, device).unwrap();
        assert_eq!(node.to_hex(), node2.to_hex(),
            "Golden vector test: same inputs must always produce same output");

        // Verify hex format (40 lowercase chars)
        assert_eq!(expected_hex.len(), 40);
        assert!(expected_hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "Hex output must be 40 lowercase hex digits");
    }

    // ------------------------------------------------------------------------
    // GIVEN invalid DID (missing prefix, wrong format)
    // WHEN NodeId::from_did_device() is called
    // THEN it returns Err with descriptive message
    // ------------------------------------------------------------------------

    #[test]
    fn test_from_did_device_invalid_did_missing_prefix() {
        // GIVEN: DID without "did:zhtp:" prefix
        let invalid_did = "abc123def456";
        let device = "laptop";

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(invalid_did, device);

        // THEN: Error with clear message
        assert!(result.is_err(), "Should fail with invalid DID");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("did:zhtp:"), "Error should mention required prefix");
    }

    #[test]
    fn test_from_did_device_invalid_did_empty() {
        // GIVEN: Empty DID
        let device = "laptop";

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device("", device);

        // THEN: Error
        assert!(result.is_err(), "Should fail with empty DID");
    }

    #[test]
    fn test_from_did_device_invalid_did_wrong_prefix() {
        // GIVEN: Wrong DID prefix
        let invalid_did = "did:web:abc123";
        let device = "laptop";

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(invalid_did, device);

        // THEN: Error mentioning "did:zhtp:"
        assert!(result.is_err(), "Should fail with wrong DID method");
    }

    #[test]
    fn test_from_did_device_invalid_did_malformed() {
        // GIVEN: Malformed DIDs (various invalid formats)
        let device = "laptop";
        let malformed_dids = vec![
            "did:zhtp:",                    // Missing ID part
            "did:zhtp: abc",                // Whitespace in ID
            "did:zhtp:ABC",                 // Uppercase (may want lowercase-only)
            "did:zhtp:abc def",             // Space in ID
            "did:zhtp:abc!@#",              // Special chars in ID
            "did:zhtp:".to_string() + &"a".repeat(500), // Extremely long ID
        ];

        for invalid_did in malformed_dids {
            // WHEN: Creating NodeId
            let result = NodeId::from_did_device(&invalid_did, device);

            // THEN: Error
            assert!(result.is_err(), "Should fail with malformed DID: {}", invalid_did);
        }
    }

    // ------------------------------------------------------------------------
    // GIVEN invalid device name
    // WHEN NodeId::from_did_device() is called
    // THEN it returns Err with descriptive message
    // ------------------------------------------------------------------------

    #[test]
    fn test_from_did_device_invalid_device_empty() {
        // GIVEN: Valid DID, empty device
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeId with empty device
        let result = NodeId::from_did_device(did, "");

        // THEN: Error
        assert!(result.is_err(), "Should fail with empty device name");
    }

    #[test]
    fn test_from_did_device_invalid_device_too_long() {
        // GIVEN: Device name > 64 characters
        let did = "did:zhtp:abc123def456";
        let long_device = "a".repeat(65);

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(did, &long_device);

        // THEN: Error mentioning length limit
        assert!(result.is_err(), "Should fail with device name > 64 chars");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("64"), "Error should mention max length");
    }

    #[test]
    fn test_from_did_device_valid_device_exactly_64_chars() {
        // GIVEN: Device name exactly 64 characters (boundary test)
        let did = "did:zhtp:abc123def456";
        let device_64 = "a".repeat(64);

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(did, &device_64);

        // THEN: Success (64 is valid, 65 is not)
        assert!(result.is_ok(), "Should accept device name of exactly 64 chars");
    }

    #[test]
    fn test_from_did_device_invalid_device_invalid_chars() {
        // GIVEN: Device with invalid characters
        let did = "did:zhtp:abc123def456";
        let invalid_devices = vec![
            "my laptop",      // space
            "phone!",         // exclamation
            "device@home",    // @
            "laptop#1",       // #
        ];

        for device in invalid_devices {
            // WHEN: Creating NodeId
            let result = NodeId::from_did_device(did, device);

            // THEN: Error
            assert!(result.is_err(), "Should fail with invalid char in: {}", device);
        }
    }

    #[test]
    fn test_from_did_device_device_normalization_lowercase() {
        // GIVEN: Device names with different casing
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeIds with different cases
        let upper = NodeId::from_did_device(did, "LAPTOP").unwrap();
        let lower = NodeId::from_did_device(did, "laptop").unwrap();
        let mixed = NodeId::from_did_device(did, "LaPtOp").unwrap();

        // THEN: All produce same NodeId (normalized to lowercase)
        assert_eq!(upper, lower, "Uppercase should normalize to lowercase");
        assert_eq!(lower, mixed, "Mixed case should normalize to lowercase");
    }

    #[test]
    fn test_from_did_device_device_normalization_trim() {
        // GIVEN: Device names with leading/trailing spaces
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeIds
        let trimmed = NodeId::from_did_device(did, "laptop").unwrap();
        let with_spaces = NodeId::from_did_device(did, "  laptop  ").unwrap();

        // THEN: Spaces are trimmed, same NodeId
        assert_eq!(trimmed, with_spaces, "Should trim leading/trailing spaces");
    }

    #[test]
    fn test_from_did_device_invalid_device_whitespace_only() {
        // GIVEN: Device name with only whitespace
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeId with whitespace-only device
        let result = NodeId::from_did_device(did, "   ");

        // THEN: Error (trimmed to empty)
        assert!(result.is_err(), "Should fail when device trims to empty");
    }

    #[test]
    fn test_from_did_device_valid_special_chars() {
        // GIVEN: Device names with allowed special chars
        let did = "did:zhtp:abc123def456";
        let valid_devices = vec![
            "my-laptop",
            "device_1",
            "phone.backup",
            "test-device_2.primary",
        ];

        for device in valid_devices {
            // WHEN: Creating NodeId
            let result = NodeId::from_did_device(did, device);

            // THEN: Success
            assert!(result.is_ok(), "Should accept valid chars in: {}", device);
        }
    }

    // ------------------------------------------------------------------------
    // GIVEN a NodeId
    // WHEN hex conversion methods are called
    // THEN proper hex encoding/decoding works
    // ------------------------------------------------------------------------

    #[test]
    fn test_hex_conversion_round_trip() {
        // GIVEN: A NodeId
        let original = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Converting to hex and back
        let hex = original.to_hex();
        let decoded = NodeId::from_hex(&hex);

        // THEN: Round-trip succeeds
        assert!(decoded.is_ok(), "Hex decoding should succeed");
        assert_eq!(original, decoded.unwrap(), "Round-trip must preserve NodeId");
    }

    #[test]
    fn test_from_hex_valid_40_chars() {
        // GIVEN: Valid 40-character hex string (20 bytes)
        let hex = "0123456789abcdef0123456789abcdef01234567";

        // WHEN: Creating NodeId from hex
        let result = NodeId::from_hex(hex);

        // THEN: Success
        assert!(result.is_ok(), "Should accept 40 hex chars");
    }

    #[test]
    fn test_from_hex_invalid_length() {
        // GIVEN: Hex strings of wrong length
        let invalid_hexes = vec![
            "abc",                    // too short
            "0123456789abcdef0123",   // 20 chars (10 bytes)
            "0123456789abcdef0123456789abcdef0123456789", // 42 chars (21 bytes)
        ];

        for hex in invalid_hexes {
            // WHEN: Creating NodeId
            let result = NodeId::from_hex(hex);

            // THEN: Error mentioning expected length
            assert!(result.is_err(), "Should fail with wrong length: {}", hex);
            let err = result.unwrap_err().to_string();
            assert!(err.contains("40"), "Error should mention expected 40 chars");
        }
    }

    #[test]
    fn test_from_hex_invalid_characters() {
        // GIVEN: Invalid hex strings
        let invalid_hexes = vec![
            "0123456789abcdefg123456789abcdef01234567", // 'g' not hex
            "0123456789abcdef 123456789abcdef01234567", // space
        ];

        for hex in invalid_hexes {
            // WHEN: Creating NodeId
            let result = NodeId::from_hex(hex);

            // THEN: Error
            assert!(result.is_err(), "Should fail with invalid hex: {}", hex);
        }
    }

    #[test]
    fn test_from_hex_canonical_form_lowercase() {
        // GIVEN: Uppercase hex string
        let uppercase = "0123456789ABCDEF0123456789ABCDEF01234567";

        // WHEN: Creating NodeId
        let result = NodeId::from_hex(uppercase);

        // THEN: Should accept and normalize to lowercase
        assert!(result.is_ok(), "Should accept uppercase hex");
        let node = result.unwrap();
        let output_hex = node.to_hex();

        // Verify output is lowercase
        assert!(output_hex.chars().all(|c| !c.is_uppercase()),
            "to_hex() must output lowercase");
        assert_eq!(output_hex, uppercase.to_lowercase(),
            "Hex should normalize to lowercase");
    }

    #[test]
    fn test_from_hex_rejects_0x_prefix() {
        // GIVEN: Hex with 0x prefix
        let hex_with_prefix = "0x0123456789abcdef0123456789abcdef01234567";

        // WHEN: Creating NodeId
        let result = NodeId::from_hex(hex_with_prefix);

        // THEN: Should reject (42 chars, not 40)
        assert!(result.is_err(), "Should reject 0x prefix");
    }

    #[test]
    fn test_from_hex_rejects_odd_length() {
        // GIVEN: Odd-length hex string (not divisible by 2)
        let odd_hex = "0123456789abcdef0123456789abcdef0123456"; // 39 chars

        // WHEN: Creating NodeId
        let result = NodeId::from_hex(odd_hex);

        // THEN: Should reject
        assert!(result.is_err(), "Should reject odd-length hex");
    }

    // ------------------------------------------------------------------------
    // GIVEN two NodeIds
    // WHEN xor_distance() is called
    // THEN correct Kademlia distance is returned
    // ------------------------------------------------------------------------

    #[test]
    fn test_xor_distance_self_is_zero() {
        // GIVEN: Same NodeId
        let node = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Calculating distance to self
        let distance = node.xor_distance(&node);

        // THEN: Distance is all zeros
        assert_eq!(distance, [0u8; 20], "Distance to self must be zero");
    }

    #[test]
    fn test_xor_distance_symmetric() {
        // GIVEN: Two different NodeIds
        let node1 = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();
        let node2 = NodeId::from_did_device("did:zhtp:def456", "phone").unwrap();

        // WHEN: Calculating distance both ways
        let dist_1_to_2 = node1.xor_distance(&node2);
        let dist_2_to_1 = node2.xor_distance(&node1);

        // THEN: Distance is symmetric
        assert_eq!(dist_1_to_2, dist_2_to_1, "XOR distance must be symmetric");
    }

    #[test]
    fn test_xor_distance_different_nodes() {
        // GIVEN: Two different NodeIds
        let node1 = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();
        let node2 = NodeId::from_did_device("did:zhtp:def456", "phone").unwrap();

        // WHEN: Calculating distance
        let distance = node1.xor_distance(&node2);

        // THEN: Distance is non-zero
        assert_ne!(distance, [0u8; 20], "Distance between different nodes must be non-zero");
    }

    #[test]
    fn test_xor_distance_known_values() {
        // GIVEN: Two NodeIds with known byte values
        let bytes1 = [0xAA; 20]; // All bits 10101010
        let bytes2 = [0x55; 20]; // All bits 01010101
        let node1 = NodeId::from_bytes(bytes1);
        let node2 = NodeId::from_bytes(bytes2);

        // WHEN: Calculating XOR distance
        let distance = node1.xor_distance(&node2);

        // THEN: XOR of 0xAA and 0x55 is 0xFF (all bits 1)
        let expected = [0xFF; 20];
        assert_eq!(distance, expected,
            "XOR distance must be bitwise XOR: 0xAA ^ 0x55 = 0xFF");
    }

    // ------------------------------------------------------------------------
    // GIVEN a NodeId
    // WHEN storage hash conversion is used
    // THEN proper 20 ↔ 32 byte conversion works
    // ------------------------------------------------------------------------

    #[test]
    fn test_storage_hash_conversion_round_trip() {
        // GIVEN: A NodeId
        let original = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Converting to Hash and back
        let hash = original.to_storage_hash();
        let restored = NodeId::from_storage_hash(&hash);

        // THEN: Round-trip preserves NodeId
        assert_eq!(original, restored, "NodeId → Hash → NodeId must preserve value");
    }

    #[test]
    fn test_to_storage_hash_pads_to_32_bytes() {
        // GIVEN: A NodeId (20 bytes)
        let node = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Converting to storage hash
        let hash = node.to_storage_hash();

        // THEN: Hash is 32 bytes (padded)
        assert_eq!(hash.as_bytes().len(), 32, "Storage Hash must be 32 bytes");

        // First 20 bytes match NodeId
        assert_eq!(&hash.as_bytes()[0..20], node.as_bytes());

        // Last 12 bytes are zero-padded
        assert_eq!(&hash.as_bytes()[20..32], &[0u8; 12]);
    }

    #[test]
    fn test_from_storage_hash_ignores_padding() {
        // GIVEN: A Hash with non-zero bytes in padding area
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..20].copy_from_slice(&[0xAB; 20]); // NodeId part
        hash_bytes[20..32].copy_from_slice(&[0xFF; 12]); // Non-zero padding

        let hash = Hash::from_bytes(&hash_bytes);

        // WHEN: Converting to NodeId
        let node = NodeId::from_storage_hash(&hash);

        // THEN: Only first 20 bytes used, padding ignored
        assert_eq!(node.as_bytes(), &[0xAB; 20]);
        assert_ne!(node.as_bytes(), &hash_bytes[0..20].iter()
            .chain(&[0xFF; 12])
            .copied()
            .collect::<Vec<u8>>()[..]);
    }

    // ------------------------------------------------------------------------
    // GIVEN a NodeId
    // WHEN Display trait is used
    // THEN hex representation is shown
    // ------------------------------------------------------------------------

    #[test]
    fn test_display_shows_hex() {
        // GIVEN: A NodeId
        let node = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Using Display trait
        let display = format!("{}", node);

        // THEN: Shows hex (40 chars)
        assert_eq!(display.len(), 40, "Display should show 40 hex chars");
        assert_eq!(display, node.to_hex(), "Display should match to_hex()");
    }

    // ------------------------------------------------------------------------
    // Property Tests - Additional invariants
    // ------------------------------------------------------------------------

    #[test]
    fn test_property_bytes_round_trip() {
        // GIVEN: A NodeId
        let original = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Converting to bytes and back
        let bytes = *original.as_bytes();
        let restored = NodeId::from_bytes(bytes);

        // THEN: Round-trip preserves value
        assert_eq!(original, restored);
    }
}
