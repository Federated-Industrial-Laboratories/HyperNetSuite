// SPDX-License-Identifier: MIT
// Content owners create encrypted cold archives and restore through current authorised repair.
use super::*;
use crate::{
    authority_domains::{
        self as domain,
        backup::{self, Command as Action, package::Package},
        page,
    },
    authority_membership::reference,
    authority_pages::{Client, content_cli, media},
    authority_proof::{Digest as Id, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::Context;
use domain_cli::{Capability, Online};
use std::{ffi::OsStr, path::Path};
use zeroize::Zeroizing;
#[path = "AuthorityBackupResume.rs"]
mod resume;
#[derive(Subcommand)]
pub enum Command {
    /// Register the exact native destination's separately signed storage consent.
    Register {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        profile: PathBuf,
    },
    Destination {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        destination: String,
    },
    Destinations {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        after: Option<String>,
    },
    WithdrawDestination {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        destination: String,
    },
    /// Fetch current Page bytes and associated canonical media, encrypt, and commit the archive manifest.
    Create {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        placement: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        retention_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Get {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        archive: String,
    },
    List {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        after: Option<String>,
    },
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        archive: String,
    },
    /// Keep restored content non-serving, then repair only exact still-current placements.
    Restore {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        staging_directory: PathBuf,
    },
    /// Generate an offline archive decryption identity; store it separately from the destination.
    KeyGenerate {
        #[arg(long)]
        output: PathBuf,
    },
}
fn id(v: &str) -> Result<Id> {
    trust_bootstrap::hex32(v)
}
fn version(v: &str, kind: u64) -> Result<VersionRef> {
    let f = v.split(':').collect::<Vec<_>>();
    ensure!(f.len() == 3, "reference must be ID:generation:digest");
    let r = VersionRef {
        kind,
        id: id(f[0])?,
        generation: f[1].parse()?,
        digest: id(f[2])?,
    };
    crate::authority_proof::validate_versions(std::slice::from_ref(&r), 1)?;
    Ok(r)
}
fn scope(c: &Client) -> (Id, Id) {
    let s = c.store.descriptor().scope();
    (s.network, s.incarnation)
}
fn summary(c: &Client, status: &str) -> Result<()> {
    let cache = c.cache()?;
    let mut destinations = vec![];
    let mut archives = vec![];
    for r in cache.state.records.values() {
        if r.reference.kind == backup::DESTINATION {
            let d = backup::Destination::parse(
                &r.payload,
                cache.state.network,
                cache.state.incarnation,
            )?;
            destinations.push(json!({"id":hex::encode(r.reference.id),"generation":r.reference.generation,"digest":hex::encode(r.reference.digest),"name":d.profile.name,"host":hex::encode(d.profile.manifest.host),"volume":hex::encode(d.profile.volume),"bytes":d.profile.bytes,"objects":d.profile.objects,"retentionMs":d.profile.retention_ms,"withdrawn":d.withdrawn}));
        } else if r.reference.kind == backup::ARCHIVE {
            let a = backup::Archive::parse(
                r.payload.bytes()?,
                cache.state.network,
                cache.state.incarnation,
            )?;
            archives.push(json!({"id":hex::encode(a.id),"generation":r.reference.generation,"digest":hex::encode(r.reference.digest),"destination":hex::encode(a.destination.id),"placement":hex::encode(a.placement.id),"bytes":a.bytes,"expiresMs":a.expires_ms,"opaque":a.opaque,"withdrawn":cache.state.records.contains_key(&(backup::TOMBSTONE,a.id))}));
        }
    }
    crate::print_value(&json!({"status":status,"destinations":destinations,"archives":archives}))
}
fn resolve_archive(c: &mut Client, p: &Package, grant: &VersionRef) -> Result<VersionRef> {
    let cache = c.cache()?;
    if let Some(r) = cache.state.records.get(&(backup::ARCHIVE, p.archive.id)) {
        ensure!(
            r.payload.bytes()? == p.archive.envelope,
            "archive ID already names another manifest"
        );
        c.domain_action(
            Action::Get {
                archive: p.archive.id,
            }
            .into(),
            None,
        )?;
    } else {
        c.domain_action(
            Action::Create {
                archive: p.archive.clone(),
            }
            .into(),
            Some(grant.clone()),
        )?;
    }
    Ok(c.cache()?
        .state
        .record(backup::ARCHIVE, p.archive.id)?
        .reference
        .clone())
}
fn create(
    online: Online,
    capability: Capability,
    placement: String,
    destination: String,
    retention_ms: u64,
    output: PathBuf,
) -> Result<()> {
    let mut c = Client::new(&online)?;
    let grant = c.grant(capability)?;
    let placement = version(&placement, 159)?;
    let destination = id(&destination)?;
    let (n, i) = scope(&c);
    if output.try_exists()? {
        let bytes = files::read_single(&output, backup::package::PACKAGE_LIMIT, true)?;
        let p = Package::parse(&bytes, n, i)?;
        ensure!(
            p.archive.placement == placement
                && p.profile.id == destination
                && p.archive.owner == c.key.verifying_key().to_bytes()
                && p.archive.expires_ms - p.archive.created_ms == retention_ms,
            "existing backup output belongs to another request"
        );
        resolve_archive(&mut c, &p, &grant)?;
        return summary(&c, "BackupArchiveCommitted");
    }
    resume::create(&mut c, &grant, &placement, destination)?;
    c.domain_action(Action::Destination { destination }.into(), None)?;
    let destination_ref = c
        .cache()?
        .state
        .record(backup::DESTINATION, destination)?
        .reference
        .clone();
    c.domain_action(
        Action::Prepare {
            placement: placement.clone(),
            destination: destination_ref.clone(),
        }
        .into(),
        Some(grant.clone()),
    )?;
    let cache = c.cache()?;
    let selected = cache.state.record(159, placement.id)?.clone();
    ensure!(selected.reference == placement, "backup placement changed");
    let content = page::content::Placement::parse(&selected.payload)?;
    let dest = backup::Destination::parse(
        &cache
            .state
            .record(backup::DESTINATION, destination)?
            .payload,
        n,
        i,
    )?;
    ensure!(
        retention_ms > 0 && retention_ms <= dest.profile.retention_ms,
        "requested retention exceeds destination consent"
    );
    let source = Zeroizing::new(content_cli::fetch_source(
        &mut c,
        &grant,
        &placement,
        page::content::Effect::Read,
    )?);
    let mut asset_entries = vec![];
    let mut assets = vec![];
    if !content.opaque {
        let mut records = cache
            .state
            .records
            .values()
            .filter(|r| r.reference.kind == 144)
            .filter_map(|r| {
                page::Asset::parse(&r.payload)
                    .ok()
                    .filter(|a| a.revision == content.revision)
                    .map(|a| (r.clone(), a))
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|(r, _)| r.reference.index());
        for (r, a) in records {
            let route = content_cli::selected_transport(&c, &a.hosts)?;
            let progress = c
                .directory
                .join(format!("BackupRead{}", hex::encode(r.reference.digest)));
            let bytes = Zeroizing::new(media::read_asset(
                &mut c,
                &grant,
                r.reference.clone(),
                &route,
                &progress,
            )?);
            asset_entries.push(V::Array(vec![V::Bytes(r.bytes), V::Bytes(bytes.to_vec())]));
            assets.push(r.reference);
        }
    }
    let plain = Zeroizing::new(wire::encode_bounded(
        &V::Array(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("BackupContent".into()),
            V::Bytes(n.to_vec()),
            V::Bytes(i.to_vec()),
            V::Bytes(selected.bytes),
            V::Bytes(source.to_vec()),
            V::Array(asset_entries),
        ]),
        backup::MAXIMUM_ARCHIVE,
    )?);
    let recipients = dest
        .profile
        .recipients
        .iter()
        .map(|k| crate::sealed_crypto::recipient_from_key(*k))
        .collect::<Result<Vec<_>>>()?;
    let ciphertext =
        crate::sealed_crypto::encrypt_bounded(&recipients, &plain, backup::MAXIMUM_ARCHIVE)?;
    ensure!(
        ciphertext.len() <= backup::MAXIMUM_ARCHIVE,
        "encrypted backup exceeds archive admission"
    );
    let now = c.clock.health()?.observe()?.wall_ms;
    let mut archive = backup::Archive {
        id: rand::random(),
        owner: c.key.verifying_key().to_bytes(),
        destination: destination_ref,
        placement,
        assets,
        digest: wire::digest(&ciphertext),
        bytes: ciphertext.len() as u64,
        created_ms: now,
        expires_ms: now
            .checked_add(retention_ms)
            .context("backup expiry overflow")?,
        opaque: content.opaque,
        envelope: vec![],
    };
    archive.envelope = wire::sign_envelope(&archive.payload(n, i)?, &c.key)?;
    let p = Package {
        profile: dest.profile,
        archive,
        ciphertext,
    };
    let bytes = p.encode()?;
    Package::parse(&bytes, n, i)?;
    files::write_new(&output, &bytes)?;
    resolve_archive(&mut c, &p, &grant)?;
    crate::print_value(
        &json!({"status":"BackupArchiveCommitted","archive":hex::encode(p.archive.id),"output":output,"destination":hex::encode(p.profile.id),"next":"Import the encrypted package with HyperNet backup destination import","serving":false}),
    )
}
fn restore(
    online: Online,
    capability: Capability,
    package: PathBuf,
    identity: PathBuf,
    staging: PathBuf,
) -> Result<()> {
    let mut c = Client::new(&online)?;
    let grant = c.grant(capability)?;
    let (n, i) = scope(&c);
    let bytes = files::read_single(&package, backup::package::PACKAGE_LIMIT, true)?;
    let p = Package::parse(&bytes, n, i)?;
    ensure!(
        p.archive.owner == c.key.verifying_key().to_bytes(),
        "only the content owner can restore its archive"
    );
    let secret = Zeroizing::new(files::read_single(&identity, 4096, true)?);
    let key: age::x25519::Identity = std::str::from_utf8(&secret)?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid backup decryption identity"))?;
    let public = crate::sealed_crypto::recipient_key(&key.to_public())?;
    ensure!(
        p.profile.recipients.contains(&public),
        "decryption identity is outside destination encryption consent"
    );
    let plain =
        crate::sealed_crypto::decrypt_bounded(&key, &p.ciphertext, backup::MAXIMUM_ARCHIVE)?;
    let v = wire::decode_bounded(&plain, backup::MAXIMUM_ARCHIVE)?;
    let f = v.array(8)?;
    ensure!(
        f[0].uint()? == 201
            && f[1].uint()? == 1
            && f[2].text()? == "BackupContent"
            && f[3].fixed::<32>()? == n
            && f[4].fixed::<32>()? == i,
        "backup content scope differs"
    );
    let record = domain::Record::parse(f[5].bytes()?, n, i)?;
    ensure!(
        record.reference == p.archive.placement,
        "backup content placement differs"
    );
    let content = page::content::Placement::parse(&record.payload)?;
    ensure!(
        content.owner == p.archive.owner
            && content.opaque == p.archive.opaque
            && f[6].bytes()?.len() as u64 == content.bytes
            && <[u8; 32]>::from(Sha256::digest(f[6].bytes()?)) == content.digest,
        "backup source differs from immutable placement"
    );
    let mut assets = vec![];
    for entry in f[7].list(64)? {
        let e = entry.array(2)?;
        let r = domain::Record::parse(e[0].bytes()?, n, i)?;
        ensure!(
            r.reference.kind == 144,
            "backup contains another object class"
        );
        let a = page::Asset::parse(&r.payload)?;
        ensure!(
            a.revision == content.revision,
            "backup media belongs to another revision"
        );
        crate::markup::media::validate_asset_bytes(&a.manifest, e[1].bytes()?)
            .map_err(anyhow::Error::msg)?;
        assets.push((r, a, e[1].bytes()?));
    }
    ensure!(
        assets
            .iter()
            .map(|(r, _, _)| r.reference.clone())
            .collect::<Vec<_>>()
            == p.archive.assets,
        "backup media closure differs"
    );
    resume::restore(&mut c, &grant, &p, f[6].bytes()?, &assets, &staging)?;
    c.domain_action(
        Action::Get {
            archive: p.archive.id,
        }
        .into(),
        None,
    )?;
    let cached = c.cache()?;
    let ar = cached.state.record(backup::ARCHIVE, p.archive.id)?.clone();
    ensure!(
        ar.payload.bytes()? == p.archive.envelope,
        "package is not the exact committed archive"
    );
    c.domain_action(
        Action::Restore {
            archive: ar.reference.clone(),
        }
        .into(),
        Some(grant.clone()),
    )?;
    let directory = if staging.try_exists()? {
        files::private_directory(&staging)?
    } else {
        files::create_directory(&staging)?
    };
    let _lock = files::lock(&directory)?;
    let stage = wire::encode(&V::Array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("BackupRestoreStaging".into()),
        V::Bytes(p.archive.id.to_vec()),
        reference(&ar.reference),
        V::Text("NonServing".into()),
    ]))?;
    retain(&directory, "Restore.cbor", &stage)?;
    retain(&directory, "Content.bin", f[6].bytes()?)?;
    for (r, _, bytes) in &assets {
        retain(
            &directory,
            &format!("Asset{}.bin", hex::encode_upper(r.reference.id)),
            bytes,
        )?;
    }
    // Repair obtains fresh authority for every chunk. No archived index, permit or journal is imported.
    c.domain_action(
        Action::Restore {
            archive: ar.reference,
        }
        .into(),
        Some(grant.clone()),
    )?;
    content_cli::repair_source(&mut c, &grant, &p.archive.placement, f[6].bytes()?)?;
    for (r, a, bytes) in assets {
        let route = content_cli::selected_transport(&c, &a.hosts)?;
        let progress = staging.join(format!("MediaRepair{}", hex::encode_upper(r.reference.id)));
        media::repair_asset(&mut c, &grant, r.reference, &route, &progress, bytes)?;
    }
    crate::print_value(
        &json!({"status":"BackupContentRestored","archive":hex::encode(p.archive.id),"stagingDirectory":staging,"index":"Not imported; rebuild only through current authorised search"}),
    )
}
fn retain(directory: &std::fs::File, name: &str, bytes: &[u8]) -> Result<()> {
    match files::read_at(directory, OsStr::new(name), backup::MAXIMUM_ARCHIVE, true) {
        Ok(old) => ensure!(
            old == bytes,
            "restore staging already contains different content"
        ),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            files::atomic_at(directory, OsStr::new(name), bytes, false)?
        }
        Err(e) => return Err(e),
    }
    Ok(())
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::KeyGenerate { output } => {
            use age::secrecy::ExposeSecret;
            let key = age::x25519::Identity::generate();
            files::write_new(&output, key.to_string().expose_secret().as_bytes())?;
            crate::print_value(
                &json!({"status":"BackupIdentityCreated","recipient":hex::encode(crate::sealed_crypto::recipient_key(&key.to_public())?),"identity":output}),
            )
        }
        Command::Create {
            online,
            capability,
            placement,
            destination,
            retention_ms,
            output,
        } => create(
            online,
            capability,
            placement,
            destination,
            retention_ms,
            output,
        ),
        Command::Restore {
            online,
            capability,
            package,
            identity,
            staging_directory,
        } => restore(online, capability, package, identity, staging_directory),
        other => {
            let (online, action, capability) = match other {
                Command::Register {
                    online,
                    capability,
                    profile,
                } => {
                    let verified = super::bootstrap(&online.location)?;
                    let s = verified.descriptor().scope();
                    let p = backup::Profile::parse(
                        &files::read_public_single(&profile, backup::MAXIMUM_PROFILE)?,
                        s.network,
                        s.incarnation,
                    )?;
                    (online, Action::Register { profile: p }, Some(capability))
                }
                Command::Destination {
                    online,
                    destination,
                } => (
                    online,
                    Action::Destination {
                        destination: id(&destination)?,
                    },
                    None,
                ),
                Command::Destinations { online, after } => (
                    online,
                    Action::Destinations {
                        after: after.as_deref().map(id).transpose()?,
                    },
                    None,
                ),
                Command::WithdrawDestination {
                    online,
                    destination,
                } => (
                    online,
                    Action::WithdrawDestination {
                        destination: version(&destination, backup::DESTINATION)?,
                    },
                    None,
                ),
                Command::Get { online, archive } => (
                    online,
                    Action::Get {
                        archive: id(&archive)?,
                    },
                    None,
                ),
                Command::List { online, after } => (
                    online,
                    Action::List {
                        after: after.as_deref().map(id).transpose()?,
                    },
                    None,
                ),
                Command::Withdraw { online, archive } => (
                    online,
                    Action::Withdraw {
                        archive: version(&archive, backup::ARCHIVE)?,
                    },
                    None,
                ),
                _ => unreachable!(),
            };
            let mut c = Client::new(&online)?;
            let grant = capability.map(|p| c.grant(p)).transpose()?;
            let pending = c
                .store
                .resume_ordinary()?
                .map(|p| crate::authority_proof::Intent::from_signed(p.signed()))
                .transpose()?
                .map(|i| domain::Operation::parse(&i))
                .transpose()?;
            let pending_mutation = pending.as_ref().is_some_and(|p| p.command.mutation());
            if !pending_mutation {
                match &action {
                    Action::Register { profile } => {
                        c.domain_action(
                            Action::InspectConsent {
                                profile: profile.clone(),
                            }
                            .into(),
                            grant.clone(),
                        )?;
                    }
                    Action::WithdrawDestination { destination } => {
                        c.domain_action(
                            Action::Destination {
                                destination: destination.id,
                            }
                            .into(),
                            None,
                        )?;
                    }
                    Action::Withdraw { archive } => {
                        c.domain_action(
                            Action::Get {
                                archive: archive.id,
                            }
                            .into(),
                            None,
                        )?;
                    }
                    _ => {}
                }
            }
            let result = c.domain_action(action.into(), grant)?;
            summary(&c, "BackupContext")?;
            if result.value.array(5)?[4].array(4)?[3] != V::Null {
                crate::print_value(
                    &json!({"after":hex::encode(result.value.array(5)?[4].array(4)?[3].fixed::<32>()?)}),
                )?;
            }
            Ok(())
        }
    }
}
