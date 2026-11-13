// SPDX-License-Identifier: Apache-2.0
//! Retire only completed public exports and duplicate inert inputs after current/previous retention.
use super::*;
use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Retirement {
    generation: u64,
    files: BTreeMap<PathBuf, String>,
}
fn inventory(
    root: &Path,
    directory: &Path,
    out: &mut BTreeMap<PathBuf, String>,
    total: &mut u64,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 6, "certificate export nesting exceeds bound");
    let m = fs::symlink_metadata(directory)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o022 == 0,
        "certificate export directory differs"
    );
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            path.starts_with(root)
                && m.uid() == unsafe { libc::geteuid() }
                && !m.file_type().is_symlink(),
            "certificate export leaves retained ownership"
        );
        if m.is_dir() {
            inventory(root, &path, out, total, depth + 1)?;
        } else {
            *total = total
                .checked_add(m.len())
                .context("certificate export size overflow")?;
            ensure!(
                out.len() < 256 && *total <= 8_388_608,
                "certificate export inventory exceeds bound"
            );
            let hash = digest(&files::public_file(&path, 8_388_608)?);
            out.insert(path, hash);
        }
    }
    Ok(())
}
fn referenced(value: &Value, folder: &Path) -> bool {
    match value {
        Value::String(s) => Path::new(s).starts_with(folder),
        Value::Array(v) => v.iter().any(|v| referenced(v, folder)),
        Value::Object(v) => v.values().any(|v| referenced(v, folder)),
        _ => false,
    }
}
fn protected(host: &Host<'_>, s: &State, n: u64) -> bool {
    [&s.current, &s.previous, &s.pending]
        .into_iter()
        .flatten()
        .any(|g| g.number == n)
        || host.state.results.iter().any(|(key, value)| {
            key != "certificates" && referenced(value, &inputs::path(&host.c.root, n))
        })
        || s.pending.as_ref().is_some_and(|g| {
            g.bases
                .values()
                .any(|p| p.starts_with(inputs::path(&host.c.root, n)))
        })
}
fn empty_directories(path: &Path, depth: usize) -> Result<()> {
    ensure!(depth <= 6, "retired certificate nesting exceeds bound");
    if !path.exists() {
        return Ok(());
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && !m.file_type().is_symlink(),
        "retired directory changed"
    );
    for entry in fs::read_dir(path)? {
        empty_directories(&entry?.path(), depth + 1)?;
    }
    fs::remove_dir(path)?;
    Ok(())
}
fn finish(host: &mut Host<'_>, s: &mut State) -> Result<()> {
    let Some(plan) = s.retiring.clone() else {
        return Ok(());
    };
    ensure!(
        !protected(host, s, plan.generation),
        "retirement now references retained certificate state"
    );
    let folder = inputs::path(&host.c.root, plan.generation);
    ensure!(
        plan.files.len() <= 256,
        "retired certificate inventory exceeds bound"
    );
    for (path, hash) in &plan.files {
        ensure!(
            path.starts_with(&folder)
                && path
                    .components()
                    .all(|c| !matches!(c, std::path::Component::ParentDir)),
            "retired path differs"
        );
        if path.exists() {
            ensure!(
                digest(&files::public_file(path, 8_388_608)?) == *hash,
                "retired certificate export changed"
            );
        }
        if let Some(retained) = host.state.artifacts.get(&text(path)?) {
            ensure!(retained == hash, "retirement artifact differs");
        }
        host.state.artifacts.remove(&text(path)?);
    }
    // The durable inventory precedes deletion, so normal startup validation tolerates interrupted cleanup.
    host.save()?;
    let mut mapped = Vec::new();
    for (path, hash) in &plan.files {
        if path.extension().and_then(|x| x.to_str()) == Some("key") {
            continue;
        }
        if !host.state.artifacts.values().any(|v| v == hash) {
            mapped.push((path.clone(), operator::ExportKind::Input, hash.clone()));
        }
        mapped.push((path.clone(), operator::ExportKind::Output, hash.clone()));
    }
    for who in ["Administrator", "ServiceOwner"] {
        if host.p(&format!("Op{who}")).exists() {
            for batch in mapped.chunks(4) {
                operator::retire_certificate_exports(host, who, batch)?;
            }
        }
    }
    for path in plan.files.keys() {
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    empty_directories(&folder, 0)?;
    File::open(folder.parent().context("certificate root absent")?)?.sync_all()?;
    let prefix = format!("certificate/{}/", plan.generation);
    host.state.ids.retain(|key, _| !key.starts_with(&prefix));
    s.retiring = None;
    save(host, s)
}
pub(super) fn prune(host: &mut Host<'_>, s: &mut State) -> Result<()> {
    finish(host, s)?;
    let root = host.p("Successor/Certificates");
    if !root.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(&root)?
        .map(|e| Ok(e?.path()))
        .collect::<Result<Vec<_>>>()?;
    entries.sort();
    ensure!(
        entries.len() <= 64,
        "unacknowledged certificate generations exceed retained bound"
    );
    for folder in entries {
        let name = folder
            .file_name()
            .and_then(|n| n.to_str())
            .context("certificate generation name differs")?;
        let n = name
            .strip_prefix("Generation")
            .context("unexpected certificate export directory")?
            .parse::<u64>()?;
        ensure!(
            inputs::path(&host.c.root, n) == folder,
            "certificate generation path differs"
        );
        if protected(host, s, n) {
            continue;
        }
        let mut files = BTreeMap::new();
        let mut total = 0;
        inventory(&folder, &folder, &mut files, &mut total, 0)?;
        s.retiring = Some(Retirement {
            generation: n,
            files,
        });
        save(host, s)?;
        finish(host, s)?;
    }
    Ok(())
}
fn prune_offers(
    host: &Host<'_>,
    name: &str,
    generation: u64,
    deployment: Option<&str>,
    service_key: Option<&str>,
) -> Result<()> {
    let folder = host.p(name).join("OperationalOffers");
    if !folder.exists() {
        return Ok(());
    }
    ensure!(
        !host.p(name).join("Transition.json").exists(),
        "unresolved local successor prevents public history retirement"
    );
    let meta = fs::symlink_metadata(&folder)?;
    ensure!(
        meta.is_dir()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o022 == 0
            && folder.canonicalize()? == folder,
        "public offer directory changed"
    );
    for entry in fs::read_dir(&folder)? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.is_file(),
            "public offer ownership changed"
        );
        let data = files::public_file(&path, 98304)?;
        let value = crate::trust_wire::decode(&data)?;
        let v = value.array(6)?;
        ensure!(
            v[0].uint()? == 200 && v[1].uint()? == 1 && v[2].text()? == "AuthorityDeploymentOffer",
            "retained history artifact differs"
        );
        let offer =
            crate::authority_deployments::Offer::parse(v[3].bytes()?, v[4].bytes()?, &v[5])?;
        ensure!(
            path.file_name().and_then(|p| p.to_str())
                == Some(format!("Generation{:020}.cbor", offer.manifest.generation).as_str()),
            "public offer filename differs"
        );
        if let Some(expected) = deployment {
            ensure!(
                hex::encode(offer.manifest.deployment) == expected,
                "retained offer belongs to another deployment"
            );
        }
        if let Some(expected) = service_key {
            ensure!(
                offer.manifest.roles.len() == 1
                    && offer.manifest.roles[0].role == 0
                    && hex::encode(offer.manifest.roles[0].service_key) == expected,
                "retained authority offer identity differs"
            );
        }
        if offer
            .manifest
            .generation
            .checked_add(2)
            .is_some_and(|n| n <= generation)
        {
            fs::remove_file(path)?;
        }
    }
    File::open(folder)?.sync_all()?;
    Ok(())
}
pub(super) fn offers(host: &Host<'_>, name: &str) -> Result<()> {
    let Some(ack) = host.remembered(&format!("certificate-history/{name}")) else {
        return Ok(());
    };
    prune_offers(
        host,
        name,
        number(&ack, "generation")?,
        Some(&host.state.ids[&format!("deployment/{name}")]),
        None,
    )
}
pub(super) fn authority_offers(host: &Host<'_>, g: &Generation) -> Result<()> {
    for n in 1..=4 {
        if let Some(generation) = g
            .steps
            .get(&format!("A{n}"))
            .and_then(|v| v["generation"].as_u64())
        {
            prune_offers(
                host,
                &format!("A{n}"),
                generation,
                None,
                Some(&string(
                    &host.state.results[&format!("role/Voter{n}")],
                    "identity",
                )?),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, symlink},
    };
    #[test]
    fn retirement_inventory_rejects_symlink_without_touching_other_files() {
        let root = std::env::temp_dir().join(format!(
            "HyperNetCertificateInventory{}",
            crate::random_hex::<16>()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let file = root.join("Certificate.pem");
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&file)
            .unwrap()
            .write_all(b"public certificate")
            .unwrap();
        let mut entries = BTreeMap::new();
        let mut total = 0;
        inventory(&root, &root, &mut entries, &mut total, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(total, 18);
        symlink(&file, root.join("Alias.pem")).unwrap();
        assert!(inventory(&root, &root, &mut BTreeMap::new(), &mut 0, 0).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"public certificate");
        fs::remove_file(root.join("Alias.pem")).unwrap();
        fs::remove_file(file).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
