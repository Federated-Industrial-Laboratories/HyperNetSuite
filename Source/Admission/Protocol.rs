// SPDX-License-Identifier: MIT
// Signed admission messages bind reviewed permissions, local keys and exact retry intent.
use anyhow::{Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const FORMAT: &str = "HyperNetAdmission/1";
pub const REQUEST_BYTES: usize = 65536;
pub const SIGNED_BYTES: usize = 8 * 1024 * 1024;
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn artifact(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.len() <= maximum * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn digest_value(value: &impl Serialize) -> Result<String> {
    Ok(digest(&serde_json::to_vec(value)?))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Signed {
    pub format: String,
    pub purpose: String,
    pub key: String,
    pub payload: String,
    pub signature: String,
}
impl Drop for Signed {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}
impl Signed {
    pub fn new<T: Serialize>(purpose: &str, value: &T, key: &SigningKey) -> Result<Self> {
        ensure!(
            matches!(purpose, "descriptor" | "challenge" | "request" | "response"),
            "unsupported admission signing purpose"
        );
        let payload = serde_json::to_vec(value)?;
        ensure!(
            payload.len() <= SIGNED_BYTES,
            "signed admission value exceeds bound"
        );
        let mut bytes = format!("{FORMAT}\0{purpose}\0").into_bytes();
        bytes.extend_from_slice(&payload);
        let envelope = Self {
            format: FORMAT.into(),
            purpose: purpose.into(),
            key: hex::encode(key.verifying_key().as_bytes()),
            payload: hex::encode(payload),
            signature: hex::encode(key.sign(&bytes).to_bytes()),
        };
        let maximum = if purpose == "request" {
            REQUEST_BYTES
        } else {
            super::transport::RESPONSE_BYTES
        };
        ensure!(
            serde_json::to_vec(&envelope)?.len() <= maximum,
            "signed admission envelope exceeds transport bound"
        );
        Ok(envelope)
    }
    pub fn verify<T: DeserializeOwned>(
        &self,
        purpose: &str,
        key: &str,
        maximum: usize,
    ) -> Result<T> {
        ensure!(
            self.format == FORMAT
                && self.purpose == purpose
                && self.key == key
                && identifier(key)
                && artifact(&self.payload, maximum)
                && self.signature.len() == 128
                && artifact(&self.signature, 64),
            "invalid signed admission envelope"
        );
        let key: [u8; 32] = hex::decode(key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signing key"))?;
        let payload = hex::decode(&self.payload)?;
        let mut bytes = format!("{FORMAT}\0{purpose}\0").into_bytes();
        bytes.extend_from_slice(&payload);
        VerifyingKey::from_bytes(&key)?.verify_strict(
            &bytes,
            &Signature::from_slice(&hex::decode(&self.signature)?)?,
        )?;
        Ok(serde_json::from_slice(&payload)?)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Role {
    pub role: u64,
    pub member: String,
    pub relay: String,
    pub request: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HrcIntent {
    pub request: serde_json::Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    pub attempt: String,
    pub control_key: String,
    pub descriptor_digest: String,
    pub display_name: String,
    pub roles: Vec<Role>,
    pub hrc: Option<HrcIntent>,
    pub invitation: Option<String>,
}
impl Intent {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            identifier(&self.attempt)
                && identifier(&self.control_key)
                && identifier(&self.descriptor_digest)
                && self.invitation.as_ref().is_none_or(|v| identifier(v)),
            "invalid join intent identity"
        );
        ensure!(
            !self.display_name.trim().is_empty()
                && self.display_name.len() <= 128
                && !self.display_name.chars().any(char::is_control),
            "display name must contain 1 to 128 bytes without controls"
        );
        ensure!(
            !self.roles.is_empty()
                && self.roles.len() <= 2
                && self.roles.windows(2).all(|r| r[0].role < r[1].role),
            "invalid native role selection"
        );
        for r in &self.roles {
            ensure!(
                r.role <= 1
                    && identifier(&r.member)
                    && identifier(&r.relay)
                    && artifact(&r.request, 8192),
                "invalid native role request"
            );
        }
        ensure!(
            self.roles.iter().any(|r| r.role == 1) == self.hrc.is_some(),
            "chat role requires its typed HRC extension"
        );
        if let Some(hrc) = &self.hrc {
            ensure!(
                serde_json::to_vec(&hrc.request)?.len() <= 16384 && hrc.request.is_object(),
                "HRC extension exceeds bound"
            );
            ensure!(
                hrc.request.get("claimId").and_then(|v| v.as_str()) == Some(self.attempt.as_str()),
                "HRC claim differs from local attempt"
            );
            let principal = &self.roles.iter().find(|r| r.role == 1).unwrap().member;
            ensure!(
                hrc.request.get("nativePrincipal").and_then(|v| v.as_str())
                    == Some(principal.as_str()),
                "HRC principal differs from native chat role"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 24576,
            "join intent exceeds bound"
        );
        Ok(())
    }
    fn stable_hrc(&self) -> Option<HrcIntent> {
        let mut hrc = self.hrc.clone();
        if let Some(hrc) = &mut hrc
            && let Some(object) = hrc.request.as_object_mut()
        {
            object.remove("operatorConsent");
        }
        hrc
    }
    pub fn digest(&self) -> Result<String> {
        let mut stable = self.clone();
        stable.hrc = self.stable_hrc();
        digest_value(&stable)
    }
    pub fn application_binding(&self) -> Result<String> {
        digest_value(&self.stable_hrc())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeRequest {
    #[serde(default)]
    pub previous: Option<Signed>,
    pub attempt: String,
    pub control_key: String,
    pub intent_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub origin: String,
    pub boot: String,
    pub nonce: String,
    pub expires_boot_ms: u64,
    pub attempt: String,
    pub control_key: String,
    pub intent_digest: String,
    pub native_claim: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "camelCase", deny_unknown_fields)]
pub enum Admission {
    Invite { secret: String },
    Password { password: String },
    Public,
    Operator,
}
impl Drop for Admission {
    fn drop(&mut self) {
        match self {
            Self::Invite { secret } => secret.zeroize(),
            Self::Password { password } => password.zeroize(),
            Self::Public | Self::Operator => {}
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Action {
    AcknowledgeRemoval {
        #[serde(rename = "resultDigest")]
        result_digest: String,
    },
    Start {
        intent: Intent,
        admission: Admission,
    },
    AcceptNative {
        #[serde(rename = "acceptance")]
        acceptance: String,
    },
    AcceptHrc {
        registration: serde_json::Value,
    },
    Status,
    RenewalChallenge,
    Renew {
        proof: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub challenge: Signed,
    pub action: Action,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum Response {
    Removed {
        result: String,
    },
    RemovalAcknowledged,
    NativeChallenge {
        challenge: String,
    },
    NativeReady {
        result: String,
        hrc: Option<serde_json::Value>,
    },
    Ready {
        native: serde_json::Value,
        hrc: Option<serde_json::Value>,
    },
    RenewalChallenge {
        challenge: String,
    },
    Pending {
        code: String,
    },
    Refused {
        code: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Permissions {
    pub modes: Vec<super::store::Mode>,
    pub access: super::store::End,
    pub reader: bool,
    pub chat: bool,
    pub room_creation: bool,
    pub moderation: bool,
    pub publishing: bool,
    pub hosting: bool,
    pub agents: bool,
    pub maximum_members: usize,
    pub hrc: Option<serde_json::Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub origin: String,
    pub name: String,
    pub network: String,
    pub incarnation: String,
    pub policy: String,
    pub generation: u64,
    pub bootstrap_digest: String,
    pub signing_key: String,
    pub permissions: Permissions,
    pub welcome: Option<String>,
}

/// The displayed lifetime and native services must come from certified policy bounds.
pub fn native_permissions(native: &Value, permissions: &Permissions) -> Result<()> {
    let end = native
        .get("accessEnd")
        .ok_or_else(|| anyhow::anyhow!("certified access lifetime absent"))?;
    ensure!(
        match permissions.access {
            super::store::End::UntilRemoved => end == &serde_json::json!({"untilWithdrawn":1}),
            super::store::End::Expires { expires_ms } => end.as_u64() == Some(expires_ms),
        },
        "advertised access lifetime differs from native policy"
    );
    ensure!(
        (1..=super::store::MAX_MEMBERS).contains(&permissions.maximum_members),
        "invalid advertised member capacity"
    );
    ensure!(
        native
            .get("maximumParticipants")
            .and_then(Value::as_u64)
            .is_some_and(|n| permissions.maximum_members as u64 <= n),
        "advertised member capacity exceeds native policy"
    );
    let expected = [(0u64, permissions.reader), (1u64, permissions.chat)]
        .into_iter()
        .filter_map(|(role, enabled)| enabled.then_some(role))
        .collect::<Vec<_>>();
    let roles: Vec<u64> = serde_json::from_value(
        native
            .get("roles")
            .ok_or_else(|| anyhow::anyhow!("certified role list absent"))?
            .clone(),
    )?;
    ensure!(
        roles == expected,
        "advertised services differ from native policy"
    );
    Ok(())
}

#[cfg(test)]
mod native_bounds_tests {
    use super::*;
    #[test]
    fn permanent_display_requires_permanent_certified_native_access() {
        let mut permissions = Permissions {
            modes: vec![super::super::store::Mode::InviteOnly],
            access: super::super::store::End::UntilRemoved,
            reader: true,
            chat: false,
            room_creation: false,
            moderation: false,
            publishing: false,
            hosting: false,
            agents: false,
            maximum_members: 32,
            hrc: None,
        };
        let mut native = serde_json::json!({"accessEnd":5000,"maximumParticipants":32,"roles":[0]});
        assert!(native_permissions(&native, &permissions).is_err());
        native["accessEnd"] = serde_json::json!({"untilWithdrawn":1});
        native_permissions(&native, &permissions).unwrap();
        permissions.maximum_members = 33;
        assert!(native_permissions(&native, &permissions).is_err());
        permissions.maximum_members = 32;
        permissions.chat = true;
        assert!(native_permissions(&native, &permissions).is_err());
        permissions.chat = false;
        permissions.access = super::super::store::End::Expires { expires_ms: 5000 };
        assert!(native_permissions(&native, &permissions).is_err());
        native["accessEnd"] = serde_json::json!(5000);
        native_permissions(&native, &permissions).unwrap();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Descriptor {
    pub format: String,
    pub native: serde_json::Value,
    pub metadata: Signed,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_bind_purpose_identity_and_exact_bytes() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = hex::encode(key.verifying_key().as_bytes());
        let signed = Signed::new("challenge", &serde_json::json!({"attempt":"one"}), &key).unwrap();
        assert_eq!(
            signed
                .verify::<serde_json::Value>("challenge", &public, 1024)
                .unwrap()["attempt"],
            "one"
        );
        assert!(
            signed
                .verify::<serde_json::Value>("descriptor", &public, 1024)
                .is_err()
        );
        assert!(
            signed
                .verify::<serde_json::Value>("challenge", &"00".repeat(32), 1024)
                .is_err()
        );
        let mut changed = signed.clone();
        changed.payload.push_str("20");
        assert!(
            changed
                .verify::<serde_json::Value>("challenge", &public, 1024)
                .is_err()
        );
    }
}

#[cfg(test)]
mod stable_tests {
    use super::*;
    #[test]
    fn replacing_consent_does_not_replace_native_intent_but_changing_scope_does() {
        let mut intent = Intent {
            attempt: "11".repeat(32),
            control_key: "22".repeat(32),
            descriptor_digest: "33".repeat(32),
            display_name: "Agent".into(),
            roles: vec![Role {
                role: 1,
                member: "44".repeat(32),
                relay: "55".repeat(32),
                request: "01".into(),
            }],
            hrc: Some(HrcIntent {
                request: serde_json::json!({"claimId":"11".repeat(32),"nativePrincipal":"44".repeat(32),"rooms":[1],"operatorConsent":{"hex":"abcd"}}),
            }),
            invitation: None,
        };
        intent.validate().unwrap();
        let original = intent.digest().unwrap();
        let application = intent.application_binding().unwrap();
        intent.hrc.as_mut().unwrap().request["operatorConsent"] = serde_json::json!({"hex":"ef01"});
        assert_eq!(intent.digest().unwrap(), original);
        assert_eq!(intent.application_binding().unwrap(), application);
        intent.hrc.as_mut().unwrap().request["rooms"] = serde_json::json!([1, 2]);
        assert_ne!(intent.digest().unwrap(), original);
        assert_ne!(intent.application_binding().unwrap(), application);
    }
}
