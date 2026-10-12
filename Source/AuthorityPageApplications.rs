// SPDX-License-Identifier: MIT
// Separate owner and application signers consent to exact native Page permissions.
use super::*;
use crate::authority_applications::Registration;
use ed25519_dalek::Signer;

#[derive(Subcommand)]
pub enum Command {
    Get {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        application: String,
    },
    /// Sign exact native permissions as the currently registered application owner.
    Offer {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        application: String,
        #[arg(long, required = true)]
        namespace: Vec<String>,
        #[arg(long)]
        page_id: Vec<String>,
        #[arg(long, required = true)]
        permission: Vec<String>,
        /// Zero means manual review; one means an explicit automated review policy.
        #[arg(long, requires = "review_policy")]
        review_mode: Option<u64>,
        #[arg(long, requires = "review_mode")]
        review_policy: Option<String>,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Display exact signed permissions for inspection without granting authority.
    Inspect {
        #[command(flatten)]
        location: crate::authority_inspection_cli::Location,
        #[arg(long)]
        input: PathBuf,
    },
    /// Countersign an inspected owner offer using the application's own key.
    Accept {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        offer_sha256: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Commit the exact dual-signed policy as its owner.
    Install {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        input: PathBuf,
    },
}
fn registration(result: &ResultState, application: Digest) -> Result<Registration> {
    let scope = result.prefix.scope();
    let governance = crate::authority_governance::Governance::parse(
        scope.network,
        scope.incarnation,
        &result.cache.records,
    )?;
    Registration::parse(
        governance.record_bytes(127, application)?,
        scope.network,
        scope.incarnation,
    )
}
fn digest(bytes: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes).into()
}
fn parse_payload(bytes: &[u8], network: Digest, incarnation: Digest) -> Result<V> {
    let value = wire::decode(bytes)?;
    let f = value.array(15)?;
    ensure!(
        f[0].uint()? == 200
            && f[1].uint()? == 1
            && f[2].text()? == "AuthorityPageApplicationPolicy"
            && f[3].fixed::<32>()? == network
            && f[4].fixed::<32>()? == incarnation,
        "Page application policy context differs"
    );
    Ok(value)
}
fn show(bytes: &[u8], bootstrap: &Verified) -> Result<()> {
    let (payload, signatures) = wire::envelope(bytes, 2)?;
    let scope = bootstrap.descriptor().scope();
    let value = parse_payload(&payload, scope.network, scope.incarnation)?;
    let f = value.array(15)?;
    let strings = |v: &V, bound| -> Result<Vec<String>> {
        v.list(bound)?
            .iter()
            .map(|v| Ok(v.text()?.to_owned()))
            .collect()
    };
    let pages = if f[10] == V::Null {
        None
    } else {
        Some(
            f[10]
                .list(16)?
                .iter()
                .map(|v| Ok(hex::encode(v.fixed::<16>()?)))
                .collect::<Result<Vec<_>>>()?,
        )
    };
    let review = if f[12] == V::Null {
        None
    } else {
        let r = f[12].array(2)?;
        Some(json!({"mode":r[0].uint()?,"policyDigest":hex::encode(r[1].fixed::<32>()?)}))
    };
    crate::print_value(
        &json!({"status":"PageApplicationConsent","currentPermission":false,
        "sha256":hex::encode(digest(bytes)),"application":hex::encode(f[5].fixed::<32>()?),"owner":hex::encode(f[6].fixed::<32>()?),
        "namespaces":strings(&f[9],8)?,"pages":pages,"permissions":strings(&f[11],7)?,"review":review,"expiresMs":f[13].uint()?,
        "signers":signatures.iter().map(|s|hex::encode(s.0)).collect::<Vec<_>>()}),
    )
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Get {
            online,
            application,
        } => {
            let mut c = Client::new(&online)?;
            let application = id(&application)?;
            let (result, _) = c.action(
                Action::ApplicationGet { application },
                None,
                Resolved::default(),
            )?;
            if let Some(record) = result.cache.state.records.get(&(148, application)) {
                show(record.payload.bytes()?, &c.bootstrap)?;
            }
            summary(&result)
        }
        Command::Offer {
            online,
            application,
            mut namespace,
            page_id,
            mut permission,
            review_mode,
            review_policy,
            expires_ms,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let application = id(&application)?;
            let (result, _) = c.action(
                Action::ApplicationGet { application },
                None,
                Resolved::default(),
            )?;
            let admission = registration(&result, application)?;
            ensure!(
                admission.owner == c.key.verifying_key().to_bytes(),
                "Page policy offer requires the current owner"
            );
            namespace.sort();
            permission.sort();
            ensure!(
                !namespace.is_empty()
                    && namespace.len() <= 8
                    && namespace.iter().all(|n| crate::markup::namespace(n))
                    && namespace.windows(2).all(|w| w[0] < w[1]),
                "invalid Page application namespace set"
            );
            let allowed = [
                "MediaInspect",
                "MediaRead",
                "MediaSubmit",
                "PagesRead",
                "PagesSubmit",
                "ReviewDecide",
                "ReviewInspect",
            ];
            ensure!(
                !permission.is_empty()
                    && permission.windows(2).all(|w| w[0] < w[1])
                    && permission.iter().all(|p| allowed.contains(&p.as_str())),
                "invalid Page application permissions"
            );
            let mut pages = page_id.iter().map(|p| raw(p)).collect::<Result<Vec<_>>>()?;
            pages.sort();
            ensure!(
                pages.len() <= 16
                    && !pages.contains(&[0; 16])
                    && pages.windows(2).all(|w| w[0] < w[1]),
                "invalid Page application scope"
            );
            let review = review_mode
                .zip(review_policy)
                .map(|(mode, p)| -> Result<_> { Ok((mode, id(&p)?)) })
                .transpose()?;
            ensure!(
                permission.iter().any(|p| p == "ReviewDecide") == review.is_some()
                    && review
                        .is_none_or(|(mode, _)| mode <= 1
                            && permission.iter().any(|p| p == "ReviewInspect")),
                "review decisions require an explicit native review policy and inspection permission"
            );
            ensure!(
                expires_ms > crate::now()?.saturating_mul(1000)
                    && expires_ms <= admission.validity.1,
                "Page policy expiry exceeds the current registration"
            );
            let policy = page::ApplicationPolicy {
                application,
                owner: admission.owner,
                registration: admission.reference,
                grant: admission.grant,
                namespaces: namespace,
                pages: if pages.is_empty() { None } else { Some(pages) },
                permissions: permission,
                review,
                expires_ms,
                previous: result
                    .cache
                    .state
                    .records
                    .get(&(148, application))
                    .map(|r| r.reference.clone()),
                envelope: vec![],
            };
            let scope = c.bootstrap.descriptor().scope();
            let bytes =
                wire::sign_envelope(&policy.payload(scope.network, scope.incarnation)?, &c.key)?;
            ensure!(
                bytes.len() + 128 <= page::MAXIMUM_PROVENANCE,
                "Page policy exceeds its signed record budget"
            );
            files::write_new(&output, &bytes)?;
            show(&bytes, &c.bootstrap)
        }
        Command::Inspect { location, input } => {
            let bootstrap = control::bootstrap(&location)?;
            show(
                &files::read_public_single(&input, page::MAXIMUM_PROVENANCE)?,
                &bootstrap,
            )
        }
        Command::Accept {
            online,
            input,
            offer_sha256,
            output,
        } => {
            let bytes = files::read_public_single(&input, page::MAXIMUM_PROVENANCE)?;
            ensure!(
                digest(&bytes) == id(&offer_sha256)?,
                "Page policy differs from the inspected offer"
            );
            let mut c = Client::new(&online)?;
            let scope = c.bootstrap.descriptor().scope();
            let (network, incarnation) = (scope.network, scope.incarnation);
            let (payload, mut signatures) = wire::envelope(&bytes, 1)?;
            let value = parse_payload(&payload, network, incarnation)?;
            let f = value.array(15)?;
            let application = f[5].fixed::<32>()?;
            ensure!(
                application == c.key.verifying_key().to_bytes(),
                "Page policy acceptance key differs"
            );
            let (result, _) = c.action(
                Action::ApplicationGet { application },
                None,
                Resolved::default(),
            )?;
            let admission = registration(&result, application)?;
            ensure!(
                signatures.len() == 1
                    && signatures[0].0 == admission.owner
                    && f[6].fixed::<32>()? == admission.owner,
                "Page policy offer is not from the current registered owner"
            );
            signatures.push((
                application,
                c.key
                    .sign(&wire::signature_message(&payload, &application))
                    .to_bytes(),
            ));
            signatures.sort_by_key(|s| s.0);
            let bytes = wire::encode(&V::Array(vec![
                V::Uint(0),
                V::Uint(1),
                V::Bytes(payload),
                V::Array(
                    signatures
                        .iter()
                        .map(|(k, s)| V::Array(vec![V::Bytes(k.to_vec()), V::Bytes(s.to_vec())]))
                        .collect(),
                ),
            ]))?;
            let policy = page::ApplicationPolicy::parse(&bytes, network, incarnation)?;
            ensure!(
                policy.registration == admission.reference
                    && policy.grant == admission.grant
                    && policy.expires_ms > crate::now()?.saturating_mul(1000)
                    && policy.expires_ms <= admission.validity.1
                    && policy.previous
                        == result
                            .cache
                            .state
                            .records
                            .get(&(148, application))
                            .map(|r| r.reference.clone()),
                "Page application admission or policy changed; obtain a fresh offer"
            );
            files::write_new(&output, &bytes)?;
            show(&bytes, &c.bootstrap)
        }
        Command::Install { online, input } => {
            let mut c = Client::new(&online)?;
            let scope = c.bootstrap.descriptor().scope();
            let policy = page::ApplicationPolicy::parse(
                &files::read_public_single(&input, page::MAXIMUM_PROVENANCE)?,
                scope.network,
                scope.incarnation,
            )?;
            ensure!(
                policy.owner == c.key.verifying_key().to_bytes(),
                "Page policy install requires its owner"
            );
            // Preserve a pending exact install instead of inserting another command into its stream.
            if c.store.resume_ordinary()?.is_none() {
                c.action(
                    Action::ApplicationGet {
                        application: policy.application,
                    },
                    None,
                    Resolved::default(),
                )?;
            }
            let (result, _) =
                c.action(Action::Application { policy }, None, Resolved::default())?;
            summary(&result)
        }
    }
}
