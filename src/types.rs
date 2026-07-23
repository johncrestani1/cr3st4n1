use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Cr3st4n1Credential {
    pub cr3st4n1: Cr3st4n1Meta,
    pub identity: Identity,
    pub device: Device,
    pub trust: Trust,
    #[serde(rename = "_signature")]
    pub signature: FileSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Cr3st4n1Meta {
    pub version: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generator: Option<Generator>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Generator {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Identity {
    #[serde(rename = "type")]
    pub identity_type: IdentityType,
    pub display_name: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    pub verification: Verification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_agent_metadata: Option<AiAgentMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Vec<License>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    Human,
    AiAgent,
    Organization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Verification {
    pub level: VerificationLevel,
    pub providers: Vec<VerificationProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationLevel {
    SelfDeclared,
    EmailVerified,
    Contract,
    IdentityDocument,
    Notarized,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationProvider {
    #[serde(rename = "type")]
    pub provider_type: ProviderType,
    pub provider: String,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    ESignature,
    Membership,
    GovId,
    Notary,
    PlatformRegistration,
    JurisdictionLicense,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiAgentMetadata {
    pub operator_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomy_level: Option<AutonomyLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyLevel {
    Supervised,
    SemiAutonomous,
    Autonomous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct License {
    pub jurisdiction: String,
    pub authority: String,
    pub permit_id: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub license_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Device {
    pub binding_level: BindingLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_fingerprint: Option<String>,
    pub registered_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BindingLevel {
    Fingerprinted,
    Attested,
    None,
    Cloud,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Trust {
    pub level: u8,
    pub credential_chain: Vec<CredentialChainEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialChainEntry {
    pub issuer: String,
    pub issued_at: String,
    pub method: String,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileSignature {
    pub signer: String,
    pub algorithm: String,
    pub signed_at: String,
    pub signature: String,
}
