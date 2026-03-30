use soroban_sdk::{contracttype, Address, BytesN, Env, Map, String, Symbol, Vec};

use crate::error::Error;

/// Represents a zero-knowledge commitment to private data
/// Stores hash of data without revealing the actual content
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkCommitment {
    /// Commitment hash (32 bytes) - binding commitment to private data
    pub commitment_hash: BytesN<32>,
    /// Public label describing what data is committed (without revealing content)
    pub public_label: String,
    /// Timestamp when commitment was created
    pub created_at: u64,
    /// Address that created the commitment
    pub committer: Address,
    /// Privacy tier - determines who can verify
    pub privacy_tier: PrivacyTier,
}

/// Privacy tiers for different levels of data access
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivacyTier {
    /// Public - anyone can verify
    Public = 0,
    /// Private - only data owner and authorized parties
    Private = 1,
    /// Confidential - requires multi-party authorization
    Confidential = 2,
    /// Restricted - regulatory/audit access only
    Restricted = 3,
}

/// Selective disclosure proof - reveals only specific fields
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectiveDisclosureProof {
    /// Product ID this proof relates to
    pub product_id: String,
    /// Fields being disclosed (field names)
    pub disclosed_fields: Vec<Symbol>,
    /// Commitment proofs for disclosed fields
    pub field_commitments: Map<Symbol, BytesN<32>>,
    /// Proof timestamp
    pub timestamp: u64,
    /// Proof expires at (0 = never)
    pub expires_at: u64,
}

/// Privacy-preserving product data
/// Stores sensitive data as commitments rather than plaintext
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateProductData {
    /// Product ID reference
    pub product_id: String,
    /// Public data (visible to all)
    pub public_data: Map<Symbol, String>,
    /// Private commitments (hash only, content hidden)
    pub private_commitments: Map<Symbol, ZkCommitment>,
    /// Authorized viewers for private data
    pub authorized_viewers: Vec<Address>,
    /// Data owner
    pub owner: Address,
}

/// Audit record that preserves privacy
/// Proves an action happened without revealing sensitive details
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyPreservingAudit {
    /// Audit entry ID
    pub audit_id: u64,
    /// Action type (encrypted/committed)
    pub action_commitment: BytesN<32>,
    /// Actor commitment (identity hidden but verifiable)
    pub actor_commitment: BytesN<32>,
    /// Timestamp (public)
    pub timestamp: u64,
    /// Success/failure (public)
    pub success: bool,
    /// Proof that audit is legitimate
    pub audit_proof: BytesN<32>,
}

/// Access permission for selective disclosure
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosurePermission {
    /// Who granted the permission
    pub granter: Address,
    /// Who can access
    pub grantee: Address,
    /// What fields can be accessed
    pub allowed_fields: Vec<Symbol>,
    /// Permission granted at
    pub granted_at: u64,
    /// Permission expires at (0 = never)
    pub expires_at: u64,
    /// Specific product ID (empty = applies to all)
    pub product_id: String,
}

/// Zero-knowledge proof stub for extensibility
/// Full zk-SNARK implementation requires off-chain proving/verification
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkProofStub {
    /// Proof type identifier
    pub proof_type: Symbol,
    /// Verification key reference
    pub vk_ref: BytesN<32>,
    /// Proof data (simplified)
    pub proof_data: BytesN<64>,
    /// Public inputs hash
    pub public_inputs_hash: BytesN<32>,
}

/// Privacy configuration for a product
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyConfig {
    /// Default privacy tier for new data
    pub default_tier: PrivacyTier,
    /// Fields that should always be private
    pub always_private_fields: Vec<Symbol>,
    /// Fields that can be disclosed with permission
    pub disclosable_fields: Vec<Symbol>,
    /// Requires audit for all disclosures
    pub audit_disclosures: bool,
    /// Auto-expire permissions after (seconds, 0 = never)
    pub permission_ttl: u64,
}

/// Validates a privacy tier value
pub fn validate_privacy_tier(tier: u32) -> Result<PrivacyTier, Error> {
    match tier {
        0 => Ok(PrivacyTier::Public),
        1 => Ok(PrivacyTier::Private),
        2 => Ok(PrivacyTier::Confidential),
        3 => Ok(PrivacyTier::Restricted),
        _ => Err(Error::InvalidInput),
    }
}

/// Check if address is authorized to view data at given privacy tier
pub fn can_access_privacy_tier(
    accessor: &Address,
    data_owner: &Address,
    authorized_viewers: &Vec<Address>,
    tier: &PrivacyTier,
) -> bool {
    match tier {
        PrivacyTier::Public => true,
        PrivacyTier::Private => {
            accessor == data_owner || authorized_viewers.contains(accessor)
        }
        PrivacyTier::Confidential => {
            // Requires explicit authorization
            accessor == data_owner || authorized_viewers.contains(accessor)
        }
        PrivacyTier::Restricted => {
            // Only data owner
            accessor == data_owner
        }
    }
}
