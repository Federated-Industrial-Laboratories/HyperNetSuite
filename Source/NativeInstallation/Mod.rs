// SPDX-License-Identifier: MIT
// Install a fixed signed Core/Suite pair through their existing upstream verifiers.
#[path = "Files.rs"]
mod files;
#[path = "Helper.rs"]
mod helper;
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

const VERSION: &str = "0.11.0";
const PUBLISHER: &str = "6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e";
const FORMAT: &str = "HyperNetNativeInstallation/1";
const ARCHIVE_LIMIT: u64 = 536870912;
#[derive(Clone, Copy)]
enum Product {
    Core,
    Suite,
}
impl Product {
    fn label(self) -> &'static str {
        match self {
            Self::Core => "Core",
            Self::Suite => "Suite",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Core => "HyperNet",
            Self::Suite => "HyperNetSuite",
        }
    }
    fn contract(self) -> &'static str {
        match self {
            Self::Core => "HyperNet080Authority2",
            Self::Suite => "HyperNet080Client1",
        }
    }
    fn helpers(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::Core => (
                include_bytes!("Package/Core/Bundle.py"),
                include_bytes!("Package/Core/PackageTrust.py"),
            ),
            Self::Suite => (
                include_bytes!("../../Tools/Bundle.py"),
                include_bytes!("../../Tools/PackageTrust.py"),
            ),
        }
    }
    fn base(self) -> String {
        format!("{}-{VERSION}-linux-x86_64", self.name())
    }
    fn root(self, root: &Path) -> PathBuf {
        root.join("Products").join(self.label())
    }
    fn prefix(self, root: &Path, archive: &str) -> Result<PathBuf> {
        hexadecimal(archive)?;
        Ok(self
            .root(root)
            .join("Installed")
            .join(format!("{}-{VERSION}-{archive}", self.name())))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Package {
    product: String,
    version: String,
    prefix: PathBuf,
    archive_sha256: String,
    manifest_sha256: String,
    binary_sha256: String,
    root_pin: String,
    root_generation: u64,
    sequence: u64,
    target_digest: String,
    trust_digest: String,
    state_contract: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    core: Package,
    suite: Package,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Installation {
    format: String,
    status: String,
    core_executable: PathBuf,
    suite_executable: PathBuf,
    core_image: String,
    packages: Pair,
}
#[derive(Subcommand)]
pub enum Command {
    /// Verify and install the supplied coordinated Packages/Core and Packages/Suite sets.
    Install {
        #[arg(long)]
        release_directory: PathBuf,
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Reverify both retained signed targets and every installed file.
    Inspect {
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}
pub fn directory() -> Result<PathBuf> {
    let root = std::env::var_os("XDG_STATE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".local/state")))
        .context("local state directory unavailable")?;
    ensure!(root.is_absolute(), "local state directory must be absolute");
    Ok(root.join("HyperNetSuite/Installation"))
}
fn hexadecimal(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid package digest"
    );
    Ok(())
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("package verifier omitted {field}"))
}
fn digest(value: &Value, field: &str) -> Result<String> {
    let value = text(value, field)?;
    hexadecimal(value)?;
    Ok(value.to_owned())
}
fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
fn add(arguments: &mut Vec<OsString>, name: &str, path: &Path) {
    arguments.push(name.into());
    arguments.push(path.into());
}
struct Work(PathBuf);
impl Work {
    fn new(root: &Path) -> Result<Self> {
        let path = root.join(format!(".Input-{}", files::random()));
        files::directory(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn pin(helper: &helper::Helper, key: &Path, expected: &str) -> Result<()> {
    let mut a = args(&["KeyPin"]);
    add(&mut a, "--public-key", key);
    ensure!(
        helper.run(&a)?["rootPin"] == expected,
        "package publisher differs from the pinned release key"
    );
    Ok(())
}
fn admission_args(operation: &str, prefix: &Path, trust: &Path, evidence: &Path) -> Vec<OsString> {
    let mut a = args(&[operation]);
    if operation != "InspectInstalledTarget" {
        add(&mut a, "--trust-directory", trust);
    }
    for (name, path) in [
        ("--prefix", prefix.to_owned()),
        ("--public-key", evidence.join("Publisher.pub")),
        ("--policy", evidence.join("Target.json")),
        ("--policy-signature", evidence.join("Target.json.sig")),
    ] {
        add(&mut a, name, &path);
    }
    a
}
fn checked_record(
    root: &Path,
    product: Product,
    archive: &str,
    receipt: &Value,
    publisher: &str,
) -> Result<(Package, Option<String>)> {
    let manifest = &receipt["manifest"];
    ensure!(
        manifest["product"] == product.name() && manifest["version"] == VERSION,
        "choose the exact supported native release"
    );
    let prefix = product.prefix(root, archive)?;
    let binary_path = format!("Bin/{}", product.name());
    let binary = manifest["files"]
        .as_array()
        .context("package inventory missing")?
        .iter()
        .find(|v| v["path"] == binary_path)
        .context("package executable missing")?;
    let record = Package {
        product: product.name().into(),
        version: VERSION.into(),
        prefix: prefix.clone(),
        archive_sha256: archive.into(),
        manifest_sha256: files::digest(&prefix.join("Manifest.json"), 262144)?,
        binary_sha256: digest(binary, "sha256")?,
        root_pin: publisher.into(),
        root_generation: receipt["rootGeneration"]
            .as_u64()
            .context("package root generation missing")?,
        sequence: receipt["sequence"]
            .as_u64()
            .context("package update sequence missing")?,
        target_digest: digest(receipt, "targetDigest")?,
        trust_digest: digest(receipt, "trustDigest")?,
        state_contract: product.contract().into(),
    };
    let image = if matches!(product, Product::Core) {
        let image = text(&manifest["metadata"], "imageId")?;
        hexadecimal(
            image
                .strip_prefix("sha256:")
                .context("invalid Core image identity")?,
        )?;
        Some(image.to_owned())
    } else {
        None
    };
    Ok((record, image))
}
fn install_product(
    root: &Path,
    release: &Path,
    product: Product,
    publisher: &str,
) -> Result<(Package, Option<String>)> {
    let work = Work::new(root)?;
    let input = release.join(product.label());
    for (source, destination, maximum) in [
        (
            format!("{}.tar", product.base()),
            "Archive.tar",
            ARCHIVE_LIMIT,
        ),
        (
            format!("{}.tar.sig", product.base()),
            "Archive.tar.sig",
            32768,
        ),
        (
            format!("{}.target.json", product.base()),
            "Target.json",
            32768,
        ),
        (
            format!("{}.target.json.sig", product.base()),
            "Target.json.sig",
            32768,
        ),
        ("Publisher.pub".into(), "Publisher.pub", 8192),
    ] {
        files::copy(&input.join(source), &work.0.join(destination), maximum)?;
    }
    let helper = helper::Helper::new(&work.0, product)?;
    pin(&helper, &work.0.join("Publisher.pub"), publisher)?;
    let archive = files::digest(&work.0.join("Archive.tar"), ARCHIVE_LIMIT)?;
    let prefix = product.prefix(root, &archive)?;
    files::directory(prefix.parent().context("package prefix missing")?)?;
    let trust = product.root(root).join("Trust");
    if !trust.try_exists()? {
        let mut a = args(&[
            "TrustInit",
            "--root-pin",
            publisher,
            "--root-generation",
            "1",
            "--version-floor",
            VERSION,
            "--state-contract",
            product.contract(),
        ]);
        add(&mut a, "--trust-directory", &trust);
        add(&mut a, "--public-key", &work.0.join("Publisher.pub"));
        helper.run(&a)?;
    }
    let mut verify = args(&["Verify"]);
    add(&mut verify, "--archive", &work.0.join("Archive.tar"));
    add(&mut verify, "--signature", &work.0.join("Archive.tar.sig"));
    add(&mut verify, "--public-key", &work.0.join("Publisher.pub"));
    let expected = helper.run(&verify)?;
    ensure!(
        expected["product"] == product.name() && expected["version"] == VERSION,
        "choose the exact supported native release"
    );
    if !prefix.try_exists()? {
        let mut a = admission_args("Install", &prefix, &trust, &work.0);
        add(&mut a, "--archive", &work.0.join("Archive.tar"));
        add(&mut a, "--signature", &work.0.join("Archive.tar.sig"));
        if matches!(product, Product::Core) {
            a.push("--defer-image-load".into());
        }
        helper.run(&a)?;
    }
    let receipt = helper.run(&admission_args("AdmitInstalled", &prefix, &trust, &work.0))?;
    ensure!(
        receipt["manifest"] == expected,
        "existing installed package differs; it was preserved"
    );
    let (record, image) = checked_record(root, product, &archive, &receipt, publisher)?;
    let retained = product
        .root(root)
        .join("Targets")
        .join(&record.target_digest);
    files::directory(&retained)?;
    for name in ["Publisher.pub", "Target.json", "Target.json.sig"] {
        files::exact(
            &retained.join(name),
            &files::read(&work.0.join(name), 32768, true)?,
        )?;
    }
    Ok((record, image))
}
fn inspect_product(
    root: &Path,
    product: Product,
    record: &Package,
    publisher: &str,
) -> Result<(Package, Option<String>)> {
    ensure!(
        record.product == product.name()
            && record.version == VERSION
            && record.root_pin == publisher
            && record.state_contract == product.contract(),
        "retained package selection differs from the supported release"
    );
    ensure!(
        record.prefix == product.prefix(root, &record.archive_sha256)?,
        "retained package prefix differs"
    );
    hexadecimal(&record.target_digest)?;
    let evidence = product
        .root(root)
        .join("Targets")
        .join(&record.target_digest);
    ensure!(
        evidence.is_dir(),
        "retained signed target evidence is missing"
    );
    files::directory(&evidence)?;
    let helper = helper::Helper::new(root, product)?;
    pin(&helper, &evidence.join("Publisher.pub"), publisher)?;
    let trust_path = product.root(root).join("Trust");
    let mut inspect = args(&["TrustInspect"]);
    add(&mut inspect, "--trust-directory", &trust_path);
    let before = helper.run(&inspect)?;
    let mut receipt = helper.run(&admission_args(
        "InspectInstalledTarget",
        &record.prefix,
        &trust_path,
        &evidence,
    ))?;
    let trust = &before["trust"];
    ensure!(
        receipt["activationAllowed"] == false
            && receipt["rootPin"] == publisher
            && trust["rootPin"] == publisher
            && trust["rootGeneration"] == receipt["rootGeneration"]
            && trust["sequence"] == receipt["sequence"]
            && trust["targetDigest"] == receipt["targetDigest"]
            && trust["versionFloor"] == VERSION
            && trust["stateContract"] == product.contract(),
        "historical package is not the exact retained current selection"
    );
    receipt["trustDigest"] = before["trustDigest"].clone();
    let result = checked_record(root, product, &record.archive_sha256, &receipt, publisher)?;
    ensure!(
        &result.0 == record,
        "retained package evidence or update trust changed; verify the selected release again"
    );
    // The prefix is selected by archive identity as well as signed target and manifest.
    ensure!(
        files::digest(&record.prefix.join("Package/Archive.tar"), ARCHIVE_LIMIT)?
            == record.archive_sha256,
        "retained archive identity differs"
    );
    ensure!(
        helper.run(&inspect)? == before,
        "package trust changed during inspection; retry"
    );
    Ok(result)
}
fn inspect_inner(root: &Path, retained: &Installation, publisher: &str) -> Result<Installation> {
    ensure!(
        retained.format == FORMAT && retained.status == "Ready",
        "native installation is incomplete"
    );
    let (core, image) = inspect_product(root, Product::Core, &retained.packages.core, publisher)?;
    let (suite, _) = inspect_product(root, Product::Suite, &retained.packages.suite, publisher)?;
    let current = Installation {
        format: FORMAT.into(),
        status: "Ready".into(),
        core_executable: core.prefix.join("Bin/HyperNet"),
        suite_executable: suite.prefix.join("Bin/HyperNetSuite"),
        core_image: image.context("Core image missing")?,
        packages: Pair { core, suite },
    };
    ensure!(
        &current == retained,
        "retained installation locations differ"
    );
    Ok(current)
}
fn install(root: &Path, release: &Path, publisher: &str) -> Result<Installation> {
    let _lock = files::Lock::acquire(root)?;
    ensure!(
        release.is_absolute(),
        "choose an absolute coordinated Packages folder"
    );
    let (core, image) = install_product(root, release, Product::Core, publisher)?;
    let (suite, _) = install_product(root, release, Product::Suite, publisher)?;
    let candidate = Installation {
        format: FORMAT.into(),
        status: "Ready".into(),
        core_executable: core.prefix.join("Bin/HyperNet"),
        suite_executable: suite.prefix.join("Bin/HyperNetSuite"),
        core_image: image.context("Core image missing")?,
        packages: Pair { core, suite },
    };
    let candidate = inspect_inner(root, &candidate, publisher)?;
    files::publish(
        &root.join("Installation.json"),
        &serde_json::to_vec_pretty(&candidate)?,
    )?;
    Ok(candidate)
}
fn inspect(root: &Path, publisher: &str) -> Result<Installation> {
    ensure!(
        root.is_dir(),
        "no coordinated native installation is saved; install the supplied tools"
    );
    let _lock = files::Lock::acquire(root)?;
    let retained =
        serde_json::from_slice(&files::read(&root.join("Installation.json"), 65536, true)?)?;
    inspect_inner(root, &retained, publisher)
}
pub fn run(command: Command) -> Result<()> {
    let (result, json) = match command {
        Command::Install {
            release_directory,
            directory: selected,
            json,
        } => (
            install(
                &selected.map(Ok).unwrap_or_else(directory)?,
                &release_directory,
                PUBLISHER,
            )?,
            json,
        ),
        Command::Inspect {
            directory: selected,
            json,
        } => (
            inspect(&selected.map(Ok).unwrap_or_else(directory)?, PUBLISHER)?,
            json,
        ),
    };
    if json {
        crate::print_value(&serde_json::to_value(result)?)
    } else {
        println!(
            "Signed Core and Suite installation verified.\nCore: {}\nSuite: {}",
            result.core_executable.display(),
            result.suite_executable.display()
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/NativeInstallation.rs"]
mod tests;
