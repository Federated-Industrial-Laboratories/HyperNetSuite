// SPDX-License-Identifier: MIT
// Possession-bound application grants over the independent signed Pages interface.
use crate::{
    Config, Identity, adapter_files as files, markup,
    page_proof::{self, Envelope},
    protocol,
};
use anyhow::{Context, Result, ensure};
use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
#[derive(Clone, ValueEnum)]
pub enum ReviewMode {
    Manual,
    Automatic,
}
#[derive(Subcommand)]
pub enum Command {
    /// Sign this fresh application's exact requested scope without contacting the network.
    Consent {
        #[arg(long)]
        owner_key: String,
        #[arg(long)]
        expires: u64,
        #[arg(long = "namespace", required = true)]
        namespaces: Vec<String>,
        #[arg(long = "page-id")]
        page_ids: Vec<String>,
        #[arg(long = "permission", required = true)]
        permissions: Vec<String>,
        #[arg(long)]
        review_policy_digest: Option<String>,
        #[arg(long, value_enum)]
        review_mode: Option<ReviewMode>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Approve an application's exact signed consent using its separate owner profile.
    Grant {
        #[arg(long)]
        consent: PathBuf,
    },
    Get {
        #[arg(long)]
        application_key: String,
    },
    List {
        #[arg(long)]
        after: Option<String>,
    },
    Revoke {
        #[arg(long)]
        application_key: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Consent {
    #[serde(rename = "type")]
    kind: String,
    owner_key: String,
    expires: u64,
    namespaces: Vec<String>,
    page_ids: Option<Vec<String>>,
    permissions: Vec<String>,
    review_policy_digest: Option<String>,
    review_mode: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    #[serde(rename = "type")]
    kind: String,
    consent: Envelope,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub owner_key: String,
    pub application_key: String,
    pub grant: Envelope,
    pub grant_digest: String,
    pub expires: u64,
    pub namespaces: Vec<String>,
    pub page_ids: Option<Vec<String>>,
    pub permissions: Vec<String>,
    pub review_policy_digest: Option<String>,
    pub review_mode: Option<String>,
    pub revoked: bool,
}
fn sorted(values: &[String], maximum: usize) -> bool {
    !values.is_empty() && values.len() <= maximum && values.windows(2).all(|p| p[0] < p[1])
}
fn validate(value: &Consent) -> Result<()> {
    protocol::hex_bytes::<32>(&value.owner_key)?;
    ensure!(
        value.kind == "ApplicationConsent"
            && sorted(&value.namespaces, 8)
            && value.namespaces.iter().all(|v| markup::namespace(v)),
        "invalid application namespaces"
    );
    if let Some(ids) = &value.page_ids {
        ensure!(sorted(ids, 16), "invalid application page allowlist");
        for id in ids {
            protocol::hex_bytes::<16>(id)?;
        }
    }
    ensure!(
        sorted(&value.permissions, 4)
            && value.permissions.iter().all(|p| matches!(
                p.as_str(),
                "PagesRead" | "PagesSubmit" | "ReviewInspect" | "ReviewDecide"
            )),
        "invalid application permissions"
    );
    if value.permissions.iter().any(|p| p == "ReviewDecide") {
        ensure!(
            value.permissions.iter().any(|p| p == "ReviewInspect"),
            "ReviewDecide requires ReviewInspect"
        );
        protocol::hex_bytes::<32>(
            value
                .review_policy_digest
                .as_deref()
                .context("review policy digest required")?,
        )?;
        ensure!(
            matches!(value.review_mode.as_deref(), Some("Manual" | "Automatic")),
            "review mode required"
        );
    } else {
        ensure!(
            value.review_policy_digest.is_none() && value.review_mode.is_none(),
            "review policy and mode require ReviewDecide"
        );
    }
    Ok(())
}
fn call(c: &Config, key: &Identity, command: Value) -> Result<Value> {
    protocol::send(c, key, &crate::random_hex::<16>(), crate::now()?, command)
}
fn proof(network: &str, record: &Record) -> Result<()> {
    let (grant, digest) = page_proof::envelope::<Create>(network, &record.grant)?;
    let (consent, _) = page_proof::envelope::<Consent>(network, &grant.command.consent)?;
    let v = &consent.command;
    validate(v)?;
    ensure!(
        grant.command.kind == "ApplicationGrantCreate"
            && record.grant.public_key == v.owner_key
            && grant.command.consent.public_key == record.application_key
            && record.owner_key == v.owner_key
            && record.grant_digest == digest
            && record.expires == v.expires
            && record.namespaces == v.namespaces
            && record.page_ids == v.page_ids
            && record.permissions == v.permissions
            && record.review_policy_digest == v.review_policy_digest
            && record.review_mode == v.review_mode,
        "application grant metadata differs from signed consent"
    );
    Ok(())
}
pub fn current(c: &Config, key: &Identity) -> Result<Record> {
    let reply = call(
        c,
        key,
        json!({"type":"ApplicationGrantGet","applicationKey":key.public_key}),
    )?;
    let record: Record = serde_json::from_value(reply["result"]["application"].clone())?;
    proof(&c.network, &record)?;
    ensure!(
        record.application_key == key.public_key
            && !record.revoked
            && record.expires > crate::now()?,
        "application grant is not current"
    );
    Ok(record)
}
pub fn review_policy(
    c: &Config,
    key: &Identity,
    automatic: bool,
    digest: &str,
    command: &mut Value,
) -> Result<()> {
    if !c.application {
        ensure!(
            !automatic,
            "automatic apply requires an application profile and Automatic grant"
        );
        return Ok(());
    }
    let grant = current(c, key)?;
    let mode = if automatic { "Automatic" } else { "Manual" };
    ensure!(
        grant.permissions.iter().any(|p| p == "ReviewDecide")
            && grant.review_policy_digest.as_deref() == Some(digest)
            && grant.review_mode.as_deref() == Some(mode),
        "current application review policy or mode does not match"
    );
    command["applicationPolicyDigest"] = json!(digest);
    command["applicationReviewMode"] = json!(mode);
    Ok(())
}
pub fn manual_review(c: &Config, key: &Identity, command: &mut Value) -> Result<()> {
    if c.application {
        let grant = current(c, key)?;
        ensure!(
            grant.review_mode.as_deref() == Some("Manual")
                && grant.permissions.iter().any(|p| p == "ReviewDecide"),
            "manual page review requires a Manual ReviewDecide application grant"
        );
        command["applicationPolicyDigest"] = json!(grant.review_policy_digest);
        command["applicationReviewMode"] = json!("Manual");
        command["reviewExpires"] = json!(crate::now()?.saturating_add(300).min(grant.expires));
    }
    Ok(())
}
pub fn run(path: Option<&Path>, command: Command) -> Result<()> {
    let c: Config = files::read(path.context("--config is required")?, files::MAX_FILE)?;
    let key = crate::load_identity(&c.identity)?;
    let body = match command {
        Command::Consent {
            owner_key,
            expires,
            namespaces,
            page_ids,
            permissions,
            review_policy_digest,
            review_mode,
            output,
        } => {
            let now = crate::now()?;
            ensure!(
                expires > now && expires <= now.saturating_add(604800),
                "application expiry must be within seven days"
            );
            ensure!(
                owner_key != key.public_key,
                "application and owner must use separate keys"
            );
            let namespaces = namespaces
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let permissions = permissions
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let page_ids = if page_ids.is_empty() {
                None
            } else {
                Some(
                    page_ids
                        .into_iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                )
            };
            let consent = Consent {
                kind: "ApplicationConsent".into(),
                owner_key,
                expires,
                namespaces,
                page_ids,
                permissions,
                review_policy_digest,
                review_mode: review_mode.map(|m| match m {
                    ReviewMode::Manual => "Manual".into(),
                    ReviewMode::Automatic => "Automatic".into(),
                }),
            };
            validate(&consent)?;
            let envelope = protocol::signed(
                &c,
                &key,
                &crate::random_hex::<16>(),
                now,
                serde_json::to_value(consent)?,
            )?;
            files::write(&output, &envelope)?;
            return crate::print_value(
                &json!({"applicationKey":key.public_key,"consent":output,"granted":false}),
            );
        }
        Command::Grant { consent } => {
            let envelope: Envelope = files::read(&consent, files::MAX_FILE)?;
            let (request, _) = page_proof::envelope::<Consent>(&c.network, &envelope)?;
            validate(&request.command)?;
            ensure!(
                request.command.owner_key == key.public_key
                    && envelope.public_key != key.public_key,
                "application consent belongs to another owner"
            );
            json!({"type":"ApplicationGrantCreate","consent":envelope})
        }
        Command::Get { application_key } => {
            protocol::hex_bytes::<32>(&application_key)?;
            json!({"type":"ApplicationGrantGet","applicationKey":application_key})
        }
        Command::List { after } => {
            if let Some(value) = &after {
                protocol::hex_bytes::<32>(value)?;
            }
            json!({"type":"ApplicationGrantList","after":after})
        }
        Command::Revoke { application_key } => {
            protocol::hex_bytes::<32>(&application_key)?;
            json!({"type":"ApplicationGrantRevoke","applicationKey":application_key})
        }
    };
    let response = call(&c, &key, body)?;
    if let Some(record) = response["result"].get("application") {
        let record: Record = serde_json::from_value(record.clone())?;
        proof(&c.network, &record)?;
    }
    crate::print_value(&response)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_grant_binds_distinct_owner_application_and_exact_scope() {
        let owner = crate::mail_protocol::new_identity();
        let app = crate::mail_protocol::new_identity();
        let c = Config {
            application: false,
            network: "01".repeat(32),
            endpoint: "https://example.test".into(),
            ca_certificate: "Unused".into(),
            identity: "Unused".into(),
            client_certificate: None,
            client_key: None,
        };
        let now = crate::now().unwrap();
        let consent: Envelope = serde_json::from_value(
            protocol::signed(
                &c,
                &app,
                &"02".repeat(16),
                now,
                json!({"type":"ApplicationConsent","ownerKey":owner.public_key,"expires":now+300,
                "namespaces":["News"],"pageIds":null,"permissions":["PagesRead"],
                "reviewPolicyDigest":null,"reviewMode":null}),
            )
            .unwrap(),
        )
        .unwrap();
        let grant: Envelope = serde_json::from_value(
            protocol::signed(
                &c,
                &owner,
                &"03".repeat(16),
                now,
                json!({"type":"ApplicationGrantCreate","consent":consent}),
            )
            .unwrap(),
        )
        .unwrap();
        let (_, digest) = page_proof::envelope::<Create>(&c.network, &grant).unwrap();
        let mut record = Record {
            owner_key: owner.public_key.clone(),
            application_key: app.public_key.clone(),
            grant,
            grant_digest: digest,
            expires: now + 300,
            namespaces: vec!["News".into()],
            page_ids: None,
            permissions: vec!["PagesRead".into()],
            review_policy_digest: None,
            review_mode: None,
            revoked: false,
        };
        proof(&c.network, &record).unwrap();
        record.permissions.push("PagesSubmit".into());
        assert!(proof(&c.network, &record).is_err());
        record.permissions.pop();
        record.application_key = owner.public_key.clone();
        assert!(proof(&c.network, &record).is_err());
        record.application_key = app.public_key.clone();
        assert!(proof(&"04".repeat(32), &record).is_err());
    }
    #[test]
    fn scope_validation_preserves_role_and_resource_intersections() {
        let mut consent = Consent {
            kind: "ApplicationConsent".into(),
            owner_key: "01".repeat(32),
            expires: 42,
            namespaces: vec!["News".into()],
            page_ids: Some(vec!["02".repeat(16)]),
            permissions: vec!["ReviewDecide".into(), "ReviewInspect".into()],
            review_policy_digest: Some("03".repeat(32)),
            review_mode: Some("Manual".into()),
        };
        validate(&consent).unwrap();
        consent.permissions.pop();
        assert!(validate(&consent).is_err());
        consent.permissions = vec!["PagesRead".into()];
        assert!(validate(&consent).is_err());
        consent.review_policy_digest = None;
        consent.review_mode = None;
        validate(&consent).unwrap();
        consent.namespaces.push("News".into());
        assert!(validate(&consent).is_err());
        consent.namespaces = vec!["*".into()];
        assert!(validate(&consent).is_err());
        consent.namespaces = vec!["News".into()];
        consent.permissions = vec!["Administrator".into()];
        assert!(validate(&consent).is_err());
    }
}
