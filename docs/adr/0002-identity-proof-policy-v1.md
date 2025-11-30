# ADR: Identity Proof Policy v1

## ADR Number
0002

## Date
2025-11-30

## Status
**Proposed** → 

## Context

The existing implementation treats `ZeroKnowledgeProof` as an ungoverned catch-all struct with:

- **no versioning** - no `version` field, no way to track format changes
- **no canonical schema** - 6 fields (`proof_system`, `proof_data`, `public_inputs`, `verification_key`, `plonky2_proof`, `proof`) with unclear semantics
- **no registry** - no authoritative list of supported proof types
- **no validation rules** - malformed proofs deserialize silently
- **string-based dispatch** - `match proof.proof_system.as_str()` allows typos, returns `Ok(false)` for unknown types
- **inconsistent usage across modules** - lib-proofs uses `ZkProofType` enum, lib-identity uses free-form strings (`"Age-Verification"`, `"Citizenship-Verification"`, etc.)
- **no binding between deterministic identity and post-quantum keypairs** - seed-anchored DID exists separately from PQC keys with no cryptographic proof of ownership

As a result, proofs are **fragile, unverifiable, incompatible across versions, and unsafe to evolve**.

This ADR establishes a coherent governance model for all identity-related proofs.

---

## Decision

Adopt **Identity Proof Policy v1**, which introduces:

1. **Canonical proof envelope** - strict schema with required fields
2. **Strict proof type governance** - enum-based, not stringly-typed
3. **Versioning rules** - explicit version tracking for migration
4. **Schema validation** - reject malformed proofs early
5. **Rejection of unknown proof types** - error instead of silent failure
6. **Proof Registry** - authoritative list of supported proof formats
7. **Canonical binary serialization** - CBOR instead of JSON
8. **Deterministic ownership binding** - cryptographic proof linking DID to PQ signature key
9. **Long-term upgrade and deprecation strategy** - safe evolution path

---

# Identity Proof Policy — Version 1 (Revised)

**Canonical governance for all proofs in the identity system.**

## Status
**Proposed for adoption**

---

## Summary

This policy defines how all proofs — **signature proofs, zero-knowledge proofs, and credential proofs** — are represented, versioned, validated, verified, and upgraded across the identity and device ecosystem.

It replaces the prior ungoverned model where `ZeroKnowledgeProof` acted as a catch-all structure with no clear rules, no schema, no versioning, and inconsistent usage across modules.

This revised v1 establishes the foundation for **long-term compatibility, secure verification, and coherent expansion**.

---

## 1. Purpose

Proofs connect **identity, devices, and capabilities**.

- **Identity is deterministic** (seed-anchored).
- **Capabilities** — PQ signature keys, encryption keys, ZK circuits, credentials — are separate and must be **bound** to the identity.

This policy defines:

- **which proof types exist**
- **how they are encoded**
- **how they are verified**
- **how versioning works**
- **how proofs remain compatible across upgrades**

**The goal**: a stable, explicit, enforceable foundation for all proofs.

---

## 2. Proof Types (Authoritative Taxonomy)

All proofs in the system must belong to **exactly one** of:

### 2.1. Signature Proof of Possession

Proves that a private key **controls or "owns"** a capability, identity, or action.

**Example uses:**
- Binding seed-derived DID to PQ signature key
- Device-level authentication
- Wallet account derivation proofs

### 2.2. Zero-Knowledge Proof

Proves a statement about the identity **without revealing** the underlying data.

**Example uses:**
- Age ≥ threshold
- Jurisdiction membership
- Selective disclosure
- Credential anonymity

### 2.3. Credential Proof

Proves that an **external issuer** has signed a claim about the identity.

**Example uses:**
- Verifiable credentials
- DAO membership attestations
- Community reputation proofs

**This taxonomy is fixed and must be enforced system-wide.**

---

## 3. Canonical Encoding (Proof Envelope)

All proofs must be encoded inside a **strict envelope**:

```rust
{
  version: "v1",               // format version
  proof_type: "<enum>",        // canonical, not stringly typed
  did_version: "v1",           // binds proof to DID generation rules
  circuit_hash: <bytes|null>,  // required for ZK proofs
  verification_key: <bytes>,   // required for signature proofs
  public_inputs: <bytes>,      // statement being proven
  proof_data: <bytes>,         // signature, ZK proof, or credential bytes
}
```

### Rules:

- `version` identifies the proof encoding version.
- `proof_type` is a **strict enum**, never a free-form string.
- `did_version` prevents cross-version mismatches.
- `circuit_hash` **MUST** be included for ZK proofs.
- `verification_key` **MUST** be included for signature-based proofs.
- `public_inputs` **MUST** define the exact message or commitment being proven.
- `proof_data` **MUST** contain the actual proof bytes.

**This envelope ensures all proofs share a coherent schema.**

---

## 4. Ownership Proof (Mandatory)

Every identity must include a **binding** between:

- the **seed-derived DID**
- the **post-quantum signature keypair**

This ensures that the entity generating PQ signatures is the **same entity** that owns the deterministic identity.

### Binding Message (Canonical)

```rust
b"IDENTITY_BIND_V1:" + did.as_bytes()
```

### Signature-Based Binding

Use **Dilithium signature**:

```rust
signature = dilithium_sign(message, dil_sk)
```

**Store as:**

```rust
version: "v1"
proof_type: SignaturePopV1
did_version: "v1"
verification_key: dil_pk
public_inputs: message
proof_data: signature
```

### Verification Rule

A verifier must:

1. Reconstruct binding message from DID.
2. Verify signature with public key.
3. Check DID matches identity root.
4. Check `proof_type == SignaturePopV1`.
5. Ensure proof envelope passes schema validation.

**This is the Identity Ownership Proof v1 structure.**

---

## 5. Consistent Decoding with Schema Validation

Every proof type must provide:

```rust
fn validate_schema(&self) -> Result<()>;
fn verify(&self, engine: &ProofEngine) -> Result<bool>;
```

Schema validation must check:

- key sizes
- field existence
- non-empty constraints
- encoding constraints
- version fields
- correct `proof_type` values

**Malformed proofs MUST NOT deserialize silently.**

---

## 6. Dispatch and Verification Rules

Proof verification must **never rely on free-form strings**.

### Correct pattern:

```rust
match proof.proof_type {
    ProofType::SignaturePopV1 => verify_signature_pop_v1(&proof),
    ProofType::ZkIdentityV1 => verify_identity_zk_v1(&proof),
    ProofType::ZkRangeV1 => verify_range_zk_v1(&proof),
    ...
}
```

### Incorrect pattern:

```rust
if proof.proof_system == "ZHTP-Optimized-Identity" { ... }
```

The enum ensures:

- no typos
- no silent fallbacks
- no accidental acceptance of unknown methods

**Unknown proof types MUST error:**

```rust
Err(anyhow!("Unsupported proof type"))
```

---

## 7. Proof Registry (Authoritative List of Supported Proofs)

We define:

```rust
ProofRegistry {
  supported: HashMap<(ProofType, Version), ProofSpec>,
}
```

Each entry includes:

- how to validate schema
- how to verify
- whether deprecated
- expected key sizes
- circuit hash (if ZK)

This provides:

- **forward compatibility**
- **backward compatibility**
- **version negotiation**
- **explicit deprecation lifecycle**

**This registry is the canonical reference.**

---

## 8. Canonical Serialization (Mandatory)

**JSON must NOT be used for cryptographic proofs.**

It is not canonical and can collapse structural distinctions.

All proofs must use:

- **canonical CBOR**, or
- a **custom canonical binary format** (future)

This ensures:

- cross-device equality
- deterministic hashing
- stable serialization for signing
- long-term durability

---

## 9. Proof Lifecycle and Upgrade Policy

This version establishes the rules:

- **Versioning**: All proofs declare a schema version (`"v1"`).
- **Backward compat**: Older proofs remain verifiable if the underlying cryptography is safe.
- **Forward compat**: New versions must not override old types; they must introduce new `ProofType::XYZ_V2`.
- **Deprecation**: Deprecated proofs remain supported via registry flags but flagged in logs.
- **Migration**: New proofs may coexist; identities can re-issue updated proofs when upgrading.

**This guarantees stability.**

---

## 10. Security Model

Identity proofs must defend against:

- replay attacks
- key substitution
- DID mismatch
- public key swapping
- malformed proof bypass
- cross-circuit confusion

### The enforcement mechanisms:

- canonical binding message
- version fields
- `proof_type` enum
- schema validation
- rejection of unknown proofs
- circuit commitment hashes

**Together they form a secure, extensible foundation.**

---

## 11. Consequences

### Benefits

- ✅ deterministic identity root
- ✅ strong binding of capabilities to identity
- ✅ robust proof governance
- ✅ consistent upgrades
- ✅ safe evolution of ZK systems
- ✅ prevention of silent failures
- ✅ stable serialization
- ✅ type-safe dispatch

### Costs

- ⚠️ requires `ProofRegistry` implementation
- ⚠️ requires refactoring `ZkProof` into enums
- ⚠️ must rewrite verification logic
- ⚠️ must introduce canonical serialization

**These are acceptable and necessary.**

---

## 12. Decision

**Adopt Identity Proof Policy v1 (Revised)** as the authoritative governance model for all proofs.

This policy supersedes implicit, string-based, untyped proof handling and establishes a **stable, secure architecture** for proof formats, verification rules, and long-term compatibility.

---

## Alternatives Considered

1. **Keep ZeroKnowledgeProof generic** (rejected: unsafe, ungoverned)
2. **Hardcode proof formats per use-case** (rejected: brittle, unscalable)
3. **Delay binding and proof governance** (rejected: blocks identity stability)
4. **Use third-party proof formats** (rejected: incompatible, too early)

---

## Future Work

### Phase 1: Core Infrastructure
- [ ] Implement `ProofType` enum and per-type structs
- [ ] Build `ProofRegistry` module
- [ ] Replace JSON with canonical CBOR serialization
- [ ] Integrate DID versioning influence into verification rules

### Phase 2: Proof Types
- [ ] Add ZK circuit commitment hashes
- [ ] Define Credential Proof v1 format
- [ ] Implement Identity Ownership Proof v1 in identity constructor

### Phase 3: Migration
- [ ] Refactor all existing modules to adopt new proof schema
- [ ] Migrate `ZhtpIdentity.ownership_proof` to new format
- [ ] Update `ZkCredential.proof` structure
- [ ] Update `IdentityAttestation.proof` structure
- [ ] Update `privacy/zk_proofs.rs` to use enum-based dispatch

---

## References

- ADR-0001: Seed-Anchored Identity (establishes deterministic identity root)
- lib-proofs/src/types/zk_proof.rs (current ungoverned implementation)
- lib-identity/src/privacy/zk_proofs.rs (inconsistent string-based usage)
- Issue #10: P1-7 deterministic identity requirement

---

## Revision History

- **2025-11-30**: Initial version (v1) - establishes proof governance framework
