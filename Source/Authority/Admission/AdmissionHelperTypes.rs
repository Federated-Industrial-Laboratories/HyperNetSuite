// SPDX-License-Identifier: MIT
// Native admission helper messages keep authority artifacts opaque to public listeners.
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "HyperNetNativeAdmission/1";
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ROLES: usize = 2;

/// Lowercase hexadecimal native signed/certified bytes; never private keys.
pub type Artifact = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleRequest {
    /// 0 is native Pages/reader; 1 is chat. The policy fixes each role's template.
    pub role: u64,
    pub member: String,
    pub relay: String,
    pub request: Artifact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Principal {
    pub role: u64,
    pub member: String,
    pub relay: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Claim {
    pub policy: String,
    pub slot: u64,
    pub generation: u64,
    pub claim: String,
    pub request_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum RegistrarRequest {
    Describe,
    /// Reserve a native slot generation for this exact outer durable claim.
    Challenge {
        claim: String,
        #[serde(rename = "requestDigest")]
        request_digest: String,
        roles: Vec<RoleRequest>,
        /// Bound application/operator policy acceptance; opaque to the native listener.
        #[serde(rename = "applicationBinding")]
        application_binding: String,
    },
    Enrol {
        challenge: Artifact,
        acceptance: Artifact,
    },
    Status {
        binding: Claim,
    },
    RenewalChallenge {
        binding: Claim,
    },
    /// A fresh enrolled-key proof, separate from the original admission credential.
    Renew {
        binding: Claim,
        proof: Artifact,
    },
    Revoke {
        binding: Claim,
        reason: String,
    },
    /// Explicit owner-approved adoption preserves existing keys and retained floors.
    Adopt {
        challenge: Artifact,
        acceptance: Artifact,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum CandidateRequest {
    /// Verify purpose and currentness before showing or retaining the descriptor key.
    Inspect {
        bootstrap: Artifact,
        proof: Artifact,
        #[serde(rename = "expectedKey")]
        expected_key: Option<String>,
    },
    Prepare {
        bootstrap: Artifact,
        proof: Artifact,
        #[serde(rename = "expectedKey")]
        expected_key: String,
        roles: Vec<u64>,
        #[serde(rename = "minimumRoute")]
        minimum_route: u64,
    },
    AcceptChallenge {
        challenge: Artifact,
        #[serde(rename = "applicationBinding")]
        application_binding: String,
        #[serde(rename = "requestDigest")]
        request_digest: String,
        claim: String,
    },
    AcceptResult {
        result: Artifact,
        /// Optional refresh selection; initial installation requires all roles.
        #[serde(default)]
        roles: Option<Vec<u64>>,
    },
    RenewalProof {
        challenge: Artifact,
    },
    Status,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleProfile {
    pub role: u64,
    /// Local private native profile path, emitted only by the local candidate helper.
    pub profile: String,
    pub directory: String,
    pub member: String,
    pub reader_grant: String,
    pub connect_grant: Option<String>,
    pub clock_witness: String,
    pub authority_route: String,
    pub destination_route: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum Response {
    Descriptor {
        bootstrap: Artifact,
        proof: Artifact,
        #[serde(rename = "policyGeneration")]
        policy_generation: u64,
        #[serde(rename = "currentKey")]
        current_key: String,
        #[serde(rename = "signingKey")]
        signing_key: String,
        network: String,
        incarnation: String,
        policy: String,
        #[serde(rename = "claimFloor")]
        claim_floor: u64,
        #[serde(rename = "accessEnd")]
        access_end: crate::trust_validity::End,
        #[serde(rename = "maximumParticipants")]
        maximum_participants: u64,
        roles: Vec<u64>,
    },
    Prepared {
        roles: Vec<RoleRequest>,
        #[serde(rename = "candidateDigest")]
        candidate_digest: String,
    },
    Challenge {
        binding: Claim,
        challenge: Artifact,
        #[serde(rename = "expiresMs")]
        expires_ms: u64,
    },
    Acceptance {
        acceptance: Artifact,
    },
    Ready {
        binding: Claim,
        result: Artifact,
        principals: Vec<Principal>,
    },
    Installed {
        binding: Claim,
        profiles: Vec<RoleProfile>,
    },
    Retired {
        binding: Claim,
        result: Artifact,
    },
    Pending {
        binding: Option<Claim>,
        code: String,
    },
    Refused {
        code: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope<T> {
    pub format: String,
    pub body: T,
}
