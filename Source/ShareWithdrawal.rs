// SPDX-License-Identifier: MIT
// Persist signed withdrawal intent before sending and preserve its generation on retries.
use crate::{Config, Identity, files, page_proof, protocol};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    #[serde(rename = "type")]
    kind: String,
    agreement_id: String,
    page_id: String,
    expected_generation: Option<u64>,
}

pub struct Pending {
    path: PathBuf,
    directory: PathBuf,
    _lock: File,
}

impl Pending {
    pub fn lock(config: &Config, identity: &Identity, agreement: &str, page: &str) -> Result<Self> {
        protocol::hex_bytes::<32>(&config.network)?;
        protocol::hex_bytes::<32>(&identity.public_key)?;
        protocol::hex_bytes::<16>(agreement)?;
        protocol::hex_bytes::<16>(page)?;
        let parent = config
            .identity
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let directory = parent.join("Withdrawals");
        let mut builder = fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        match builder.mode(0o700).create(&directory) {
            Ok(()) => File::open(parent)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = fs::symlink_metadata(&directory)?;
        ensure!(
            metadata.is_dir()
                && metadata.mode() & 0o077 == 0
                && metadata.uid() == unsafe { libc::geteuid() },
            "withdrawal directory must be private and owned by the current user"
        );
        let scope = format!(
            "{}{}{}{}",
            config.network, identity.public_key, agreement, page
        );
        let name = hex::encode(Sha256::digest(scope.as_bytes()));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(format!("Lock{name}")))?;
        let metadata = lock.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.mode() & 0o077 == 0
                && metadata.uid() == unsafe { libc::geteuid() },
            "withdrawal lock must be private and owned by the current user"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another sharing operation is active for this page"
        );
        Ok(Self {
            path: directory.join(format!("Pending{name}.json")),
            directory,
            _lock: lock,
        })
    }

    fn exists(&self) -> Result<bool> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn require_resolved(&self) -> Result<()> {
        ensure!(
            !self.exists()?,
            "resolve the pending withdrawal with retry-withdrawal before sharing again"
        );
        Ok(())
    }

    fn save(&self, config: &Config, identity: &Identity, intent: &Intent) -> Result<()> {
        let envelope = protocol::signed(
            config,
            identity,
            &crate::random_hex::<16>(),
            crate::now()?,
            serde_json::to_value(intent)?,
        )?;
        let temporary = self
            .directory
            .join(format!("Pending{}.json", crate::random_hex::<16>()));
        files::write_new(&temporary, &serde_json::to_vec(&envelope)?)?;
        fs::rename(&temporary, &self.path)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn load(
        &self,
        config: &Config,
        identity: &Identity,
        agreement: &str,
        page: &str,
    ) -> Result<Intent> {
        let envelope: page_proof::Envelope =
            serde_json::from_slice(&files::read_bounded(&self.path, true)?)?;
        ensure!(
            envelope.public_key == identity.public_key,
            "pending withdrawal belongs to another author"
        );
        let (request, _) = page_proof::envelope::<Intent>(&config.network, &envelope)?;
        let intent = request.command;
        ensure!(
            intent.kind == "FederationWithdrawalIntent"
                && intent.agreement_id == agreement
                && intent.page_id == page,
            "pending withdrawal scope mismatch"
        );
        Ok(intent)
    }

    fn remove(&self) -> Result<()> {
        fs::remove_file(&self.path)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

fn call(config: &Config, identity: &Identity, command: Value) -> Result<Value> {
    protocol::send(
        config,
        identity,
        &crate::random_hex::<16>(),
        crate::now()?,
        command,
    )
}

pub fn status(config: &Config, identity: &Identity, agreement: &str, page: &str) -> Result<Value> {
    let response = call(
        config,
        identity,
        json!({"type":"FederationShareStatus","agreementId":agreement,"pageId":page}),
    )?;
    validate_status(&response["result"], agreement, page)?;
    Ok(response["result"].clone())
}

fn validate_status(value: &Value, agreement: &str, page: &str) -> Result<()> {
    let generation = value["generation"]
        .as_u64()
        .context("missing share generation")?;
    let withdrawn = value["lastWithdrawalGeneration"]
        .as_u64()
        .context("missing withdrawal generation")?;
    ensure!(
        value["agreementId"].as_str() == Some(agreement)
            && value["pageId"].as_str() == Some(page)
            && value["allowed"].is_boolean()
            && withdrawn <= generation,
        "invalid sharing status"
    );
    Ok(())
}

pub fn run(
    config: &Config,
    identity: &Identity,
    agreement: &str,
    page: &str,
    retry: bool,
    expected: Option<u64>,
) -> Result<()> {
    let pending = Pending::lock(config, identity, agreement, page)?;
    let existed = pending.exists()?;
    let mut intent = if existed {
        pending.load(config, identity, agreement, page)?
    } else {
        ensure!(!retry, "no pending withdrawal exists for this page");
        let intent = Intent {
            kind: "FederationWithdrawalIntent".into(),
            agreement_id: agreement.into(),
            page_id: page.into(),
            expected_generation: None,
        };
        pending.save(config, identity, &intent)?;
        intent
    };
    let result = (|| -> Result<Value> {
        if intent.expected_generation.is_none() {
            let current = status(config, identity, agreement, page)?;
            let generation = current["generation"]
                .as_u64()
                .context("missing share generation")?;
            if existed && expected.is_none() {
                return Ok(
                    json!({"withdrawal":"Pending","reason":"GenerationConfirmationRequired","current":current,"pendingFile":pending.path}),
                );
            }
            ensure!(
                expected.is_none_or(|value| value == generation),
                "share generation changed; review current sharing status before retrying"
            );
            intent.expected_generation = Some(generation);
            pending.save(config, identity, &intent)?;
        } else if expected.is_some_and(|value| Some(value) != intent.expected_generation) {
            let current = status(config, identity, agreement, page)?;
            let previous = intent
                .expected_generation
                .context("missing withdrawal generation")?;
            if current["lastWithdrawalGeneration"]
                .as_u64()
                .is_some_and(|value| value <= previous)
            {
                ensure!(
                    current["generation"].as_u64() == expected,
                    "share generation changed; review current sharing status before retrying"
                );
                intent.expected_generation = expected;
                pending.save(config, identity, &intent)?;
            }
        }
        let generation = intent
            .expected_generation
            .context("missing withdrawal generation")?;
        let response = call(
            config,
            identity,
            json!({"type":"FederationUnshare","agreementId":agreement,"pageId":page,"expectedGeneration":generation}),
        )?;
        let current = &response["result"];
        validate_status(current, agreement, page)?;
        ensure!(
            current["lastWithdrawalGeneration"]
                .as_u64()
                .is_some_and(|value| value > generation),
            "authority did not confirm withdrawal"
        );
        pending.remove()?;
        Ok(
            json!({"withdrawal":"Confirmed","sharing":if current["allowed"] == true {"SupersededByLaterConsent"} else {"Withdrawn"},"current":current}),
        )
    })();
    match result {
        Ok(value) => {
            crate::print_value(&value)?;
            if value["withdrawal"] == "Pending" {
                bail!(
                    "withdrawal is pending; retry with the displayed --expected-generation after reviewing current sharing"
                );
            }
            Ok(())
        }
        Err(error) => {
            crate::print_value(
                &json!({"withdrawal":"Pending","agreementId":agreement,"pageId":page,"expectedGeneration":intent.expected_generation,"pendingFile":pending.path}),
            )?;
            Err(error.context("withdrawal remains pending; no global withdrawal is confirmed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pending_intent_survives_restart_verifies_scope_and_blocks_sharing() {
        let directory =
            std::env::temp_dir().join(format!("HyperNetWithdrawals{}", crate::random_hex::<8>()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let key = SigningKey::from_bytes(&[19; 32]);
        let identity = Identity {
            public_key: hex::encode(key.verifying_key().as_bytes()),
            secret_key: hex::encode(key.to_bytes()),
        };
        let config = Config {
            application: false,
            network: "10".repeat(32),
            identity: directory.join("Identity.json"),
            endpoint: "https://invalid.test".into(),
            ca_certificate: "Unused".into(),
            client_certificate: None,
            client_key: None,
        };
        let agreement = "11".repeat(16);
        let page = "12".repeat(16);
        let intent = Intent {
            kind: "FederationWithdrawalIntent".into(),
            agreement_id: agreement.clone(),
            page_id: page.clone(),
            expected_generation: Some(7),
        };
        {
            let pending = Pending::lock(&config, &identity, &agreement, &page).unwrap();
            pending.require_resolved().unwrap();
            pending.save(&config, &identity, &intent).unwrap();
            assert!(pending.require_resolved().is_err());
            assert!(Pending::lock(&config, &identity, &agreement, &page).is_err());
        }
        let pending = Pending::lock(&config, &identity, &agreement, &page).unwrap();
        assert_eq!(
            pending
                .load(&config, &identity, &agreement, &page)
                .unwrap()
                .expected_generation,
            Some(7)
        );
        assert!(
            pending
                .load(&config, &identity, &agreement, &"13".repeat(16))
                .is_err()
        );
        let mut bytes: Value =
            serde_json::from_slice(&files::read_bounded(&pending.path, true).unwrap()).unwrap();
        bytes["signature"] = json!("00".repeat(64));
        fs::write(&pending.path, serde_json::to_vec(&bytes).unwrap()).unwrap();
        assert!(pending.load(&config, &identity, &agreement, &page).is_err());
        pending.remove().unwrap();
        pending.require_resolved().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
