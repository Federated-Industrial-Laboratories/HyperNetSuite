// SPDX-License-Identifier: MIT
// Durable invitation reservations retain exact outcomes; retired native claims cannot replay.
use super::{
    password::Verifier,
    protocol::{self, Intent, identifier},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
pub const STATE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PENDING: usize = 8;
pub const MAX_INVITATIONS: usize = 64;
pub const MAX_MEMBERS: usize = 64;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub enum End {
    UntilRemoved,
    Expires {
        #[serde(rename = "expiresMs")]
        expires_ms: u64,
    },
}
impl End {
    pub fn current(&self, now: u64) -> bool {
        match self {
            Self::UntilRemoved => true,
            Self::Expires { expires_ms } => now < *expires_ms,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    InviteOnly,
    Password,
    Public,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Invitation {
    pub id: String,
    pub secret_digest: String,
    pub enabled: bool,
    pub end: End,
    pub maximum_uses: u32,
    pub uses: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Reserved,
    Challenged,
    NativeReady,
    Ready,
    Revoking,
    Retired,
}
impl Phase {
    pub fn pending(self) -> bool {
        matches!(self, Self::Reserved | Self::Challenged | Self::NativeReady)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Claim {
    pub intent: Intent,
    pub intent_digest: String,
    pub native_claim: String,
    pub phase: Phase,
    pub native_binding: Option<serde_json::Value>,
    pub challenge: Option<String>,
    pub challenge_expires_ms: Option<u64>,
    pub hrc_invitation: Option<serde_json::Value>,
    pub hrc_result: Option<serde_json::Value>,
    #[serde(default)]
    pub retirement: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Retirement {
    pub attempt: String,
    pub control_key: String,
    pub intent_digest: String,
    pub native_claim: String,
    pub result: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Removal {
    pub attempt: String,
    pub targets: Vec<String>,
    pub home_complete: bool,
    pub after: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct State {
    pub version: u8,
    pub generation: u64,
    pub enabled: bool,
    pub mode: Mode,
    pub password: Option<Verifier>,
    pub maximum_members: usize,
    pub access: End,
    pub counter: u64,
    pub retired_floor: u64,
    pub invitations: Vec<Invitation>,
    pub claims: Vec<Claim>,
    #[serde(default)]
    pub retirements: Vec<Retirement>,
    #[serde(default)]
    pub removal: Option<Removal>,
}
pub struct OperatorAuthorization {
    pub operator: serde_json::Value,
    pub maximum: usize,
}
pub fn ordinal(claim: &str) -> Result<u64> {
    ensure!(identifier(claim), "invalid native claim identifier");
    Ok(u64::from_str_radix(&claim[..16], 16)?)
}
impl State {
    pub fn new(maximum_members: usize, access: End) -> Result<Self> {
        let value = Self {
            version: 1,
            generation: 1,
            enabled: false,
            mode: Mode::InviteOnly,
            password: None,
            maximum_members,
            access,
            counter: 0,
            retired_floor: 0,
            invitations: vec![],
            claims: vec![],
            retirements: vec![],
            removal: None,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.generation > 0
                && (1..=MAX_MEMBERS).contains(&self.maximum_members)
                && self.invitations.len() <= MAX_INVITATIONS
                && self.claims.len() <= self.maximum_members
                && self.retirements.len() <= 2 * MAX_MEMBERS
                && self.claims.len() + self.retirements.len() <= 2 * MAX_MEMBERS
                && self.claims.iter().filter(|c| c.phase.pending()).count() <= MAX_PENDING
                && self.retired_floor <= self.counter,
            "admission state exceeds its limits"
        );
        if let Some(removal) = &self.removal {
            ensure!(
                identifier(&removal.attempt)
                    && removal.targets.len() <= MAX_MEMBERS
                    && removal.targets.iter().all(|s| identifier(s))
                    && removal.after.as_ref().is_none_or(|s| identifier(s)),
                "invalid retained removal operation"
            );
        }
        if let Some(password) = &self.password {
            password.validate()?;
        }
        ensure!(
            self.mode != Mode::Password || self.password.is_some(),
            "password mode needs a verifier"
        );
        let mut ids = std::collections::BTreeSet::new();
        for i in &self.invitations {
            ensure!(
                identifier(&i.id)
                    && identifier(&i.secret_digest)
                    && i.maximum_uses > 0
                    && i.uses <= i.maximum_uses
                    && ids.insert(&i.id),
                "invalid invitation policy"
            );
        }
        ids.clear();
        let mut keys = std::collections::BTreeSet::new();
        let mut native = std::collections::BTreeSet::new();
        for c in &self.claims {
            c.intent.validate()?;
            ensure!(
                c.intent.digest()? == c.intent_digest
                    && ids.insert(&c.intent.attempt)
                    && keys.insert(&c.intent.control_key)
                    && native.insert(&c.native_claim)
                    && ordinal(&c.native_claim)? > 0
                    && ordinal(&c.native_claim)? <= self.counter,
                "invalid durable claim"
            );
            ensure!(
                serde_json::to_vec(c)?.len() <= 192 * 1024,
                "retained claim exceeds bound"
            );
            ensure!(
                c.phase != Phase::Retired
                    || c.retirement
                        .as_ref()
                        .is_some_and(|s| protocol::artifact(s, 128 * 1024)),
                "terminal claim lacks retirement evidence"
            );
            ensure!(
                c.phase == Phase::Reserved
                    || c.phase == Phase::Revoking
                    || c.native_binding.is_some(),
                "claim lacks its native binding"
            );
        }
        for receipt in &self.retirements {
            ensure!(
                identifier(&receipt.attempt)
                    && identifier(&receipt.control_key)
                    && identifier(&receipt.intent_digest)
                    && ids.insert(&receipt.attempt)
                    && keys.insert(&receipt.control_key)
                    && native.insert(&receipt.native_claim)
                    && ordinal(&receipt.native_claim)? <= self.retired_floor
                    && protocol::artifact(&receipt.result, 128 * 1024),
                "invalid retained retirement receipt"
            );
        }
        Ok(())
    }
    pub fn claim(&self, attempt: &str, key: &str, digest: &str) -> Result<Option<&Claim>> {
        if let Some(c) = self.claims.iter().find(|c| c.intent.attempt == attempt) {
            ensure!(
                c.intent.control_key == key && c.intent_digest == digest,
                "claim content conflicts with retained request"
            );
            return Ok(Some(c));
        }
        ensure!(
            !self.claims.iter().any(|c| c.intent.control_key == key),
            "this control key already has a retained claim"
        );
        Ok(None)
    }
    pub fn retirement(&self, attempt: &str, key: &str, digest: &str) -> Result<Option<Retirement>> {
        if let Some(receipt) = self.retirements.iter().find(|r| r.attempt == attempt) {
            ensure!(
                receipt.control_key == key && receipt.intent_digest == digest,
                "retirement receipt differs from identity"
            );
            return Ok(Some(receipt.clone()));
        }
        if let Some(claim) = self.claim(attempt, key, digest)?
            && claim.phase == Phase::Retired
        {
            return Ok(Some(Retirement {
                attempt: attempt.into(),
                control_key: key.into(),
                intent_digest: digest.into(),
                native_claim: claim.native_claim.clone(),
                result: claim
                    .retirement
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("retirement proof absent"))?,
            }));
        }
        Ok(None)
    }
    pub fn acknowledge_retirement(&mut self, receipt: &Retirement, digest: &str) -> Result<()> {
        ensure!(
            protocol::digest(receipt.result.as_bytes()) == digest,
            "retirement acknowledgement differs"
        );
        self.retirements
            .retain(|r| r.native_claim != receipt.native_claim);
        self.claims
            .retain(|c| c.native_claim != receipt.native_claim || c.phase != Phase::Retired);
        Ok(())
    }
    /// Allocation issues no native authority and consumes no invitation use.
    pub fn allocate(
        &mut self,
        request: &protocol::ChallengeRequest,
        native_floor: u64,
    ) -> Result<String> {
        ensure!(
            identifier(&request.attempt)
                && identifier(&request.control_key)
                && identifier(&request.intent_digest),
            "invalid challenge identity"
        );
        if let Some(c) = self.claim(
            &request.attempt,
            &request.control_key,
            &request.intent_digest,
        )? {
            return Ok(c.native_claim.clone());
        }
        if let Some(receipt) = self.retirement(
            &request.attempt,
            &request.control_key,
            &request.intent_digest,
        )? {
            return Ok(receipt.native_claim);
        }
        self.counter = self
            .counter
            .max(native_floor)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("admission ordinal exhausted"))?;
        Ok(format!(
            "{:016x}{}",
            self.counter,
            crate::random_hex::<24>()
        ))
    }
    pub fn reserve(
        &mut self,
        intent: Intent,
        native_claim: &str,
        admission: &protocol::Admission,
        now: u64,
        native_floor: u64,
        operator: Option<&OperatorAuthorization>,
    ) -> Result<Claim> {
        intent.validate()?;
        let request_digest = intent.digest()?;
        if let Some(c) = self.claim(&intent.attempt, &intent.control_key, &request_digest)? {
            ensure!(c.native_claim == native_claim, "native claim changed");
            let mut existing = c.clone();
            if existing.phase != Phase::Ready && existing.phase != Phase::Revoking {
                existing.intent = intent;
                *self
                    .claims
                    .iter_mut()
                    .find(|c| c.native_claim == native_claim)
                    .unwrap() = existing.clone();
            }
            return Ok(existing);
        }
        ensure!(
            !self
                .claims
                .iter()
                .any(|c| c.phase == Phase::Reserved && c.native_binding.is_none()),
            "AdmissionRecoveryPending"
        );
        let selected = ordinal(native_claim)?;
        ensure!(
            selected > native_floor.max(self.retired_floor) && selected <= self.counter,
            "claim ticket retired; obtain a fresh challenge"
        );
        ensure!(
            self.enabled && self.access.current(now),
            "new joining is unavailable"
        );
        ensure!(
            self.claims.len() < self.maximum_members
                && self.retirements.len() < MAX_MEMBERS
                && self.claims.iter().filter(|c| c.phase.pending()).count() < MAX_PENDING,
            "admission capacity reached"
        );
        let agent = intent.hrc.as_ref().filter(|h| {
            h.request
                .pointer("/classification/kind")
                .and_then(serde_json::Value::as_str)
                == Some("agent")
        });
        if let Some(agent) = agent {
            let approved = operator.ok_or_else(|| anyhow::anyhow!("OperatorConsentRequired"))?;
            ensure!(
                agent.request.pointer("/classification/operator") == Some(&approved.operator)
                    && (1..=8).contains(&approved.maximum),
                "invalid operator admission"
            );
            let used = self
                .claims
                .iter()
                .filter(|c| {
                    c.intent.hrc.as_ref().is_some_and(|h| {
                        h.request
                            .pointer("/classification/kind")
                            .and_then(serde_json::Value::as_str)
                            == Some("agent")
                            && h.request.pointer("/classification/operator")
                                == Some(&approved.operator)
                    })
                })
                .count();
            ensure!(used < approved.maximum, "OperatorAgentQuota");
        }
        match admission {
            protocol::Admission::Invite { secret } => {
                let id = intent
                    .invitation
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("admission refused"))?;
                let invitation = self
                    .invitations
                    .iter_mut()
                    .find(|i| &i.id == id)
                    .ok_or_else(|| anyhow::anyhow!("admission refused"))?;
                use base64::Engine;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(secret)?;
                ensure!(
                    bytes.len() == 32
                        && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
                            == *secret
                        && invitation.enabled
                        && invitation.end.current(now)
                        && invitation.uses < invitation.maximum_uses
                        && protocol::digest(&bytes) == invitation.secret_digest,
                    "admission refused"
                );
                invitation.uses = invitation
                    .uses
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("invitation exhausted"))?;
            }
            protocol::Admission::Password { password } => {
                ensure!(
                    intent.invitation.is_none()
                        && self.mode == Mode::Password
                        && self
                            .password
                            .as_ref()
                            .is_some_and(|v| v.verify(password.as_bytes()).unwrap_or(false)),
                    "admission refused"
                );
            }
            protocol::Admission::Operator => {
                ensure!(
                    agent.is_some() && operator.is_some() && intent.invitation.is_none(),
                    "OperatorConsentRequired"
                );
            }
            protocol::Admission::Public => {
                ensure!(
                    intent.invitation.is_none() && self.mode == Mode::Public,
                    "admission refused"
                );
            }
        }
        let c = Claim {
            intent,
            intent_digest: request_digest,
            native_claim: native_claim.into(),
            phase: Phase::Reserved,
            native_binding: None,
            challenge: None,
            challenge_expires_ms: None,
            hrc_invitation: None,
            hrc_result: None,
            retirement: None,
        };
        self.claims.push(c.clone());
        Ok(c)
    }
    /// The registrar calls this only after a certified native retirement, or proven non-submission.
    pub fn retire(&mut self, native_claim: &str, result: String) -> Result<()> {
        let index = self
            .claims
            .iter()
            .position(|c| c.native_claim == native_claim)
            .ok_or_else(|| anyhow::anyhow!("claim absent"))?;
        ensure!(
            self.claims[index].phase == Phase::Revoking,
            "claim retirement must first be durable"
        );
        ensure!(
            protocol::artifact(&result, 128 * 1024),
            "retirement proof exceeds retained bound"
        );
        self.retired_floor = self.retired_floor.max(ordinal(native_claim)?);
        let claim = &mut self.claims[index];
        claim.phase = Phase::Retired;
        claim.challenge = None;
        claim.hrc_invitation = None;
        claim.hrc_result = None;
        claim.retirement = Some(result.clone());
        if self.retirements.len() < 2 * MAX_MEMBERS {
            self.retirements.push(Retirement {
                attempt: claim.intent.attempt.clone(),
                control_key: claim.intent.control_key.clone(),
                intent_digest: claim.intent_digest.clone(),
                native_claim: claim.native_claim.clone(),
                result,
            });
            self.claims.remove(index);
        }
        // A full receipt table retains terminal claims in existing slots. Withdrawal still succeeds;
        // new admissions wait for receipt acknowledgements instead of losing offline evidence.
        Ok(())
    }
    pub fn retire_invitations(&mut self, now: u64) {
        self.invitations
            .retain(|i| i.enabled && i.end.current(now) && i.uses < i.maximum_uses);
    }
}
pub struct Locked {
    directory: PathBuf,
    _lock: File,
    state: State,
    poisoned: bool,
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.len() <= STATE_BYTES as u64,
        "admission state must be a private bounded file"
    );
    let mut bytes = Vec::new();
    f.take(STATE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= STATE_BYTES,
        "admission state exceeds its bound"
    );
    Ok(bytes)
}
fn lock(directory: &Path) -> Result<File> {
    super::private::directory(directory)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("Admission.lock"))?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "admission lock must be private"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "admission state is busy"
    );
    Ok(lock)
}
impl Locked {
    pub fn create(directory: &Path, state: State) -> Result<Self> {
        let held = lock(directory)?;
        state.validate()?;
        crate::files::write_new(
            &directory.join("Admission.json"),
            &serde_json::to_vec(&state)?,
        )?;
        File::open(directory)?.sync_all()?;
        Ok(Self {
            directory: directory.into(),
            _lock: held,
            state,
            poisoned: false,
        })
    }
    pub fn open(directory: &Path) -> Result<Self> {
        let held = lock(directory)?;
        let state: State = serde_json::from_slice(&read(&directory.join("Admission.json"))?)?;
        state.validate()?;
        Ok(Self {
            directory: directory.into(),
            _lock: held,
            state,
            poisoned: false,
        })
    }
    pub fn state(&self) -> Result<&State> {
        ensure!(
            !self.poisoned,
            "admission storage requires reopening after an uncertain write"
        );
        Ok(&self.state)
    }
    pub fn transact<T>(&mut self, change: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        ensure!(
            !self.poisoned,
            "admission storage requires reopening after an uncertain write"
        );
        let mut next = self.state.clone();
        let result = change(&mut next)?;
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("state generation exhausted"))?;
        next.validate()?;
        let bytes = serde_json::to_vec(&next)?;
        ensure!(
            bytes.len() <= STATE_BYTES,
            "admission state storage exhausted"
        );
        let temporary = self
            .directory
            .join(format!(".admission-{}", crate::random_hex::<16>()));
        let write = (|| -> Result<()> {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            std::fs::rename(&temporary, self.directory.join("Admission.json"))?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write {
            self.poisoned = true;
            let _ = std::fs::remove_file(temporary);
            return Err(e);
        }
        self.state = next;
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    fn intent() -> Intent {
        Intent {
            attempt: "11".repeat(32),
            control_key: "22".repeat(32),
            descriptor_digest: "33".repeat(32),
            display_name: "Reader".into(),
            roles: vec![protocol::Role {
                role: 0,
                member: "44".repeat(32),
                relay: "55".repeat(32),
                request: "01".into(),
            }],
            hrc: None,
            invitation: Some("66".repeat(32)),
        }
    }
    #[test]
    fn exact_claim_does_not_reconsume_invite_and_retirement_fences_replay() {
        let mut s = State::new(1, End::UntilRemoved).unwrap();
        s.enabled = true;
        s.invitations.push(Invitation {
            id: "66".repeat(32),
            secret_digest: protocol::digest(&[7; 32]),
            enabled: true,
            end: End::UntilRemoved,
            maximum_uses: 1,
            uses: 0,
        });
        let i = intent();
        let digest = i.digest().unwrap();
        let request = protocol::ChallengeRequest {
            previous: None,
            attempt: i.attempt.clone(),
            control_key: i.control_key.clone(),
            intent_digest: digest,
        };
        let ticket = s.allocate(&request, 99).unwrap();
        assert_eq!(ordinal(&ticket).unwrap(), 100);
        assert_eq!(s.invitations[0].uses, 0);
        let auth = protocol::Admission::Invite {
            secret: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7; 32]),
        };
        s.reserve(i.clone(), &ticket, &auth, 1, 99, None).unwrap();
        s.reserve(i.clone(), &ticket, &auth, 1, 100, None).unwrap();
        assert_eq!(s.invitations[0].uses, 1);
        let mut changed = i.clone();
        changed.display_name = "changed".into();
        assert!(s.reserve(changed, &ticket, &auth, 1, 100, None).is_err());
        s.claims[0].phase = Phase::Revoking;
        s.retire(&ticket, "01".into()).unwrap();
        let receipt = s
            .retirement(
                &request.attempt,
                &request.control_key,
                &request.intent_digest,
            )
            .unwrap()
            .unwrap();
        assert!(
            s.retirement(&request.attempt, &"99".repeat(32), &request.intent_digest)
                .is_err()
        );
        assert!(
            s.acknowledge_retirement(&receipt, &"00".repeat(32))
                .is_err()
        );
        assert!(s.reserve(i, &ticket, &auth, 1, 100, None).is_err());
        assert!(s.claims.is_empty());
        s.validate().unwrap();
        s.acknowledge_retirement(&receipt, &protocol::digest(b"01"))
            .unwrap();
        assert!(s.retirements.is_empty());
        assert_eq!(s.retired_floor, 100);
        s.validate().unwrap();
    }

    #[test]
    fn receipt_backpressure_reserves_space_for_every_live_withdrawal() {
        let mut state = State::new(MAX_MEMBERS, End::UntilRemoved).unwrap();
        state.enabled = true;
        state.mode = Mode::Public;
        state.counter = (2 * MAX_MEMBERS) as u64;
        for n in 1..=2 * MAX_MEMBERS {
            let mut intent = intent();
            intent.invitation = None;
            intent.attempt = format!("{n:064x}");
            intent.control_key = format!("{:064x}", n + 1000);
            let claim = Claim {
                intent_digest: intent.digest().unwrap(),
                intent,
                native_claim: format!("{n:016x}{}", "11".repeat(24)),
                phase: Phase::Revoking,
                native_binding: Some(serde_json::json!({})),
                challenge: None,
                challenge_expires_ms: None,
                hrc_invitation: None,
                hrc_result: None,
                retirement: None,
            };
            state.claims.push(claim);
            if n <= MAX_MEMBERS {
                let id = state.claims.last().unwrap().native_claim.clone();
                state.retire(&id, "01".into()).unwrap();
            }
        }
        state.validate().unwrap();
        let mut newcomer = intent();
        newcomer.invitation = None;
        let request = protocol::ChallengeRequest {
            previous: None,
            attempt: newcomer.attempt.clone(),
            control_key: newcomer.control_key.clone(),
            intent_digest: newcomer.digest().unwrap(),
        };
        let ticket = state.allocate(&request, state.counter).unwrap();
        assert!(
            state
                .reserve(newcomer, &ticket, &protocol::Admission::Public, 1, 0, None)
                .err()
                .unwrap()
                .to_string()
                .contains("admission capacity reached")
        );
        while let Some(claim) = state.claims.first() {
            let id = claim.native_claim.clone();
            state.retire(&id, "01".into()).unwrap();
            state.validate().unwrap();
        }
        assert_eq!(state.retirements.len(), 2 * MAX_MEMBERS);
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn failed_transaction_does_not_publish_and_uncertain_write_poison_requires_reopen() {
        let directory =
            std::env::temp_dir().join(format!("hypernet-claims-{}", crate::random_hex::<12>()));
        super::super::saved::create_directory(&directory).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let mut locked =
            Locked::create(&directory, State::new(2, End::UntilRemoved).unwrap()).unwrap();
        assert!(Locked::open(&directory).is_err());
        let failed: Result<()> = locked.transact(|s| {
            s.enabled = true;
            anyhow::bail!("aborted")
        });
        assert!(failed.is_err());
        assert!(!locked.state().unwrap().enabled);
        locked
            .transact(|s| {
                s.enabled = true;
                Ok(())
            })
            .unwrap();
        drop(locked);
        let mut reopened = Locked::open(&directory).unwrap();
        assert!(reopened.state().unwrap().enabled);
        std::fs::rename(
            directory.join("Admission.json"),
            directory.join("Retained.json"),
        )
        .unwrap();
        std::fs::create_dir(directory.join("Admission.json")).unwrap();
        assert!(
            reopened
                .transact(|s| {
                    s.enabled = false;
                    Ok(())
                })
                .is_err()
        );
        assert!(reopened.state().is_err());
    }
}
