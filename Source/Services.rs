// SPDX-License-Identifier: MIT
// Separately approved SSH grants invoke a pinned OpenSSH client without ambient configuration.
use crate::{Config, Identity, mail_protocol as signed, transfer_files as files};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
};
const CONSENT: &[u8] = b"HyperNet/SshConsent/1\0";
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Consent {
    version: u32,
    network: String,
    service_key: String,
    generation: u64,
    endpoint: String,
    address: std::net::SocketAddr,
    ssh_host_key: String,
    account: String,
    purpose: String,
    command_digest: String,
    image_digest: String,
    authority_endpoint: String,
    authority_address: std::net::SocketAddr,
    authority_signer: String,
    certificate_digest: String,
    memory_bytes: u64,
    pids: u64,
    cpu_quota: u64,
    cpu_period: u64,
    state_bytes: u64,
    maximum_session_seconds: u64,
    expires: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Service {
    consent: signed::Signed,
    consent_digest: String,
    body: Consent,
    active: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    grant_id: String,
    service_key: String,
    service_generation: u64,
    member_key: String,
    ssh_public_key: String,
    account: String,
    purpose: String,
    expires: u64,
    accepted: bool,
    revoked: bool,
}
#[derive(Subcommand)]
pub enum Command {
    /// Sign the exact endpoint, forced-command image and resource specification.
    Consent {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Register {
        #[arg(long)]
        consent: PathBuf,
    },
    Withdraw {
        #[arg(long)]
        expected_generation: u64,
    },
    List,
    Inspect {
        #[arg(long)]
        service_key: String,
    },
    /// Request a bounded grant; the service operator must accept separately.
    Request {
        #[arg(long)]
        service_key: String,
        #[arg(long)]
        authority_key: String,
        #[arg(long)]
        ssh_public_key: PathBuf,
        /// Maintained OpenSSH client; sibling ssh-keygen signs the possession proof.
        #[arg(long)]
        ssh_binary: PathBuf,
        /// Dedicated private key, readable without an interactive passphrase.
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        purpose: String,
        #[arg(long)]
        expires: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Accept {
        #[arg(long)]
        grant_id: String,
    },
    Revoke {
        #[arg(long)]
        grant_id: String,
    },
    Status {
        #[arg(long)]
        grant_id: String,
    },
    /// Invoke the service's fixed command with dedicated native SSH credentials.
    Connect {
        #[arg(long)]
        grant_id: String,
        #[arg(long)]
        authority_key: String,
        #[arg(long)]
        ssh_binary: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        ssh_public_key: PathBuf,
        /// Send this private regular file to the fixed service command (at most 8 MiB).
        #[arg(long)]
        input: Option<PathBuf>,
        /// Save verified service output to a new local file instead of terminal text.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
fn ssh_key(text: &str) -> Result<String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let parts: Vec<_> = text.split_whitespace().collect();
    ensure!(
        parts.len() >= 2 && parts[0] == "ssh-ed25519" && !text.contains(['\r', '\n', '\0']),
        "a single native ssh-ed25519 public key is required"
    );
    let bytes = STANDARD.decode(parts[1])?;
    ensure!(
        bytes.len() == 51
            && bytes[..4] == 11u32.to_be_bytes()
            && &bytes[4..15] == b"ssh-ed25519"
            && bytes[15..19] == 32u32.to_be_bytes()
            && STANDARD.encode(&bytes) == parts[1],
        "noncanonical SSH public key"
    );
    ed25519_dalek::VerifyingKey::from_bytes(bytes[19..].try_into()?)?;
    Ok(format!("ssh-ed25519 {}", parts[1]))
}
fn consent(config: &Config, envelope: &signed::Signed, authority: Option<&str>) -> Result<Consent> {
    let c: Consent = signed::verify(CONSENT, &config.network, &envelope.public_key, envelope)?;
    ensure!(
        c.version == 1
            && c.network == config.network
            && c.service_key == envelope.public_key
            && c.generation > 0
            && c.expires > crate::now()?
            && c.account == "HyperNetService"
            && (1..=300).contains(&c.maximum_session_seconds),
        "invalid SSH service consent"
    );
    if let Some(key) = authority {
        ensure!(
            c.authority_signer == key,
            "SSH authority signer differs from the verified fingerprint"
        );
    }
    crate::checked_key(&c.authority_signer)?;
    crate::checked_key(&c.command_digest)?;
    crate::checked_key(&c.image_digest)?;
    crate::checked_key(&c.certificate_digest)?;
    ensure!(
        ssh_key(&c.ssh_host_key)? == c.ssh_host_key,
        "SSH host key must be canonical and comment-free"
    );
    let endpoint = reqwest::Url::parse(&c.endpoint)?;
    ensure!(
        endpoint.scheme() == "ssh"
            && endpoint.host_str().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && matches!(endpoint.path(), "" | "/")
            && endpoint.port() == Some(c.address.port())
            && c.address.port() > 0
            && !c.address.ip().is_unspecified()
            && !c.address.ip().is_multicast(),
        "invalid SSH service endpoint"
    );
    ensure!(
        !c.purpose.is_empty() && c.purpose.len() <= 256 && !c.purpose.chars().any(char::is_control),
        "invalid SSH purpose"
    );
    Ok(c)
}
fn service(config: &Config, value: &Value, authority: Option<&str>) -> Result<Service> {
    let s: Service = serde_json::from_value(value.clone())?;
    let c = consent(config, &s.consent, authority)?;
    ensure!(
        serde_json::to_value(&c)? == serde_json::to_value(&s.body)?
            && s.consent_digest == signed::signed_digest(CONSENT, &s.consent)?,
        "SSH directory changed signed service consent"
    );
    Ok(s)
}
fn get_service(
    config: &Config,
    identity: &Identity,
    key: &str,
    authority: Option<&str>,
) -> Result<Service> {
    crate::checked_key(key)?;
    let result = signed::authority(
        config,
        identity,
        json!({"type":"SshServiceGet","serviceKey":key}),
    )?;
    let s = service(config, &result["service"], authority)?;
    ensure!(s.body.service_key == key, "wrong SSH service returned");
    Ok(s)
}
fn get_grant(config: &Config, identity: &Identity, id: &str) -> Result<Grant> {
    crate::protocol::hex_bytes::<16>(id)?;
    let result = signed::authority(config, identity, json!({"type":"SshGrantGet","grantId":id}))?;
    let grant: Grant = serde_json::from_value(result["grant"].clone())?;
    ensure!(grant.grant_id == id, "wrong SSH grant returned");
    Ok(grant)
}
pub fn run(path: Option<&Path>, command: Command) -> Result<()> {
    let config: Config = serde_json::from_slice(&crate::files::read_bounded(
        path.context("--config required")?,
        false,
    )?)?;
    crate::checked_key(&config.network)?;
    let identity = crate::load_identity(&config.identity)?;
    let result = match command {
        Command::Consent { spec, output } => {
            let body: Consent = serde_json::from_slice(&crate::files::read_bounded(&spec, false)?)?;
            ensure!(
                body.service_key == identity.public_key,
                "consent signing identity mismatch"
            );
            let envelope = signed::sign(CONSENT, &config.network, &identity, &body)?;
            consent(&config, &envelope, Some(&body.authority_signer))?;
            files::write_new(&output, &serde_json::to_vec_pretty(&envelope)?)?;
            json!({"consent":output,"serviceKey":body.service_key,"generation":body.generation,"workerMemoryBytes":body.memory_bytes,"gateMemoryBytes":134217728u64,"gatePids":32,"gateCpuQuota":50000,"gateVolatileBytes":8388608})
        }
        Command::Register { consent: path } => {
            let envelope = signed::read_signed(&path)?;
            let c = consent(&config, &envelope, None)?;
            ensure!(
                c.service_key == identity.public_key,
                "only the service operator can register consent"
            );
            signed::authority(
                &config,
                &identity,
                json!({"type":"SshServiceRegister","consent":envelope}),
            )?
        }
        Command::Withdraw {
            expected_generation,
        } => signed::authority(
            &config,
            &identity,
            json!({"type":"SshServiceWithdraw","serviceKey":identity.public_key,"expectedGeneration":expected_generation}),
        )?,
        Command::List => {
            let value = signed::authority(&config, &identity, json!({"type":"SshServices"}))?;
            for item in value["services"].as_array().context("missing services")? {
                service(&config, item, None)?;
            }
            value
        }
        Command::Inspect { service_key } => {
            json!({"service":get_service(&config, &identity, &service_key, None)?})
        }
        Command::Request {
            service_key,
            authority_key,
            ssh_public_key,
            ssh_binary,
            identity: ssh_identity,
            purpose,
            expires,
            output,
        } => {
            crate::checked_key(&authority_key)?;
            let s = get_service(&config, &identity, &service_key, Some(&authority_key))?;
            ensure!(
                s.active
                    && s.body.purpose == purpose
                    && expires > crate::now()?
                    && expires <= crate::now()?.saturating_add(s.body.maximum_session_seconds)
                    && expires <= s.body.expires,
                "request exceeds the active service purpose or lifetime"
            );
            let bytes = files::read(&ssh_public_key, 16384, false)?;
            let key = ssh_key(std::str::from_utf8(&bytes)?.trim())?;
            let request = if output.try_exists()? {
                let value: Value = serde_json::from_slice(&files::read(&output, 16384, true)?)?;
                ensure!(
                    value["network"] == config.network
                        && value["memberKey"] == identity.public_key
                        && value["command"]["serviceKey"] == service_key
                        && value["command"]["serviceGeneration"] == s.body.generation
                        && value["command"]["sshPublicKey"] == key
                        && value["command"]["purpose"] == purpose
                        && value["command"]["expires"] == expires,
                    "saved SSH grant request differs from these arguments"
                );
                crate::ssh_proof::verify(
                    value["command"]["sshKeyProof"]
                        .as_str()
                        .context("saved SSH request lacks a key possession proof")?,
                    &config.network,
                    &identity.public_key,
                    &key,
                )?;
                value["command"].clone()
            } else {
                let proof = crate::ssh_proof::generate(
                    &ssh_binary,
                    &ssh_identity,
                    &config.network,
                    &identity.public_key,
                    &key,
                )?;
                let request = json!({"type":"SshGrantCreate","grantId":crate::random_hex::<16>(),"serviceKey":service_key,"serviceGeneration":s.body.generation,"sshPublicKey":key,"sshKeyProof":proof,"account":s.body.account,"purpose":purpose,"expires":expires});
                files::write_new(
                    &output,
                    &serde_json::to_vec_pretty(
                        &json!({"network":config.network,"memberKey":identity.public_key,"command":request}),
                    )?,
                )?;
                request
            };
            signed::authority(&config, &identity, request)?
        }
        Command::Accept { grant_id } => {
            crate::protocol::hex_bytes::<16>(&grant_id)?;
            signed::authority(
                &config,
                &identity,
                json!({"type":"SshGrantAccept","grantId":grant_id}),
            )?
        }
        Command::Revoke { grant_id } => {
            crate::protocol::hex_bytes::<16>(&grant_id)?;
            signed::authority(
                &config,
                &identity,
                json!({"type":"SshGrantRevoke","grantId":grant_id}),
            )?
        }
        Command::Status { grant_id } => json!({"grant":get_grant(&config, &identity, &grant_id)?}),
        Command::Connect {
            grant_id,
            authority_key,
            ssh_binary,
            identity: ssh_identity,
            ssh_public_key,
            input,
            output,
        } => {
            crate::checked_key(&authority_key)?;
            let g = get_grant(&config, &identity, &grant_id)?;
            let s = get_service(&config, &identity, &g.service_key, Some(&authority_key))?;
            ensure!(
                s.active
                    && g.accepted
                    && !g.revoked
                    && g.expires > crate::now()?
                    && g.member_key == identity.public_key
                    && g.service_generation == s.body.generation
                    && g.account == s.body.account
                    && g.purpose == s.body.purpose
                    && g.expires <= s.body.expires,
                "SSH grant is stale, unaccepted or bound to another member or service"
            );
            let public = files::read(&ssh_public_key, 16384, false)?;
            ensure!(
                ssh_key(std::str::from_utf8(&public)?.trim())? == g.ssh_public_key,
                "SSH public key differs from the accepted grant"
            );
            let secret = zeroize::Zeroizing::new(files::read(&ssh_identity, 16384, true)?);
            let _ = secret;
            connect(
                &s.body,
                &g,
                &ssh_binary,
                &ssh_identity,
                input.as_deref(),
                output.as_deref(),
            )?;
            json!({"grantId":grant_id,"completed":true})
        }
    };
    crate::print_value(&result)
}
fn ssh_arguments(c: &Consent, key: &Path, hosts: &Path) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = vec!["-F", "/dev/null", "-T"]
        .into_iter()
        .map(Into::into)
        .collect();
    for option in [
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "UpdateHostKeys=no",
        "VerifyHostKeyDNS=no",
        "CheckHostIP=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "ExitOnForwardFailure=yes",
        "RequestTTY=no",
        "PermitLocalCommand=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "ControlMaster=no",
        "ControlPath=none",
        "ControlPersist=no",
        "Tunnel=no",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "HostbasedAuthentication=no",
        "GSSAPIAuthentication=no",
        "PubkeyAuthentication=yes",
        "PreferredAuthentications=publickey",
        "AddKeysToAgent=no",
        "EnableEscapeCommandline=no",
        "EscapeChar=none",
        "HostKeyAlgorithms=ssh-ed25519",
        "PubkeyAcceptedAlgorithms=ssh-ed25519",
        "ConnectTimeout=5",
        "ConnectionAttempts=1",
        "ServerAliveInterval=2",
        "ServerAliveCountMax=2",
        "SessionType=default",
    ] {
        args.push("-o".into());
        args.push(option.into());
    }
    for option in [
        format!("UserKnownHostsFile={}", hosts.display()),
        format!("HostKeyAlias=HyperNet{}", c.service_key),
    ] {
        args.push("-o".into());
        args.push(option.into());
    }
    args.extend([
        "-i".into(),
        key.as_os_str().into(),
        "-p".into(),
        c.address.port().to_string().into(),
        "-l".into(),
        c.account.clone().into(),
        "--".into(),
        c.address.ip().to_string().into(),
    ]);
    args
}
fn connect(
    c: &Consent,
    g: &Grant,
    binary: &Path,
    identity: &Path,
    input: Option<&Path>,
    output: Option<&Path>,
) -> Result<()> {
    use std::io::{Read, Write};
    const MAXIMUM: usize = 8 * 1024 * 1024;
    crate::ssh_proof::client(binary)?;
    let target = output.map(files::Destination::open).transpose()?;
    let input = input
        .map(|p| files::read(p, MAXIMUM, true).map(zeroize::Zeroizing::new))
        .transpose()?;
    let root = Path::new("/tmp").join(format!("HyperNetSsh{}", crate::random_hex::<16>()));
    files::create_directory(&root)?;
    let result = (|| {
        let hosts = root.join("KnownHosts");
        files::write_new(
            &hosts,
            format!("HyperNet{} {}\n", c.service_key, c.ssh_host_key).as_bytes(),
        )?;
        // Copy only this dedicated key to eliminate replacement and adjacent-certificate races.
        let key = root.join("Identity");
        let secret = zeroize::Zeroizing::new(files::read(identity, 16384, true)?);
        files::write_new(&key, &secret)?;
        let mut child = Process::new(binary)
            .args(ssh_arguments(c, &key, &hosts))
            .env_clear()
            .env("LANG", "C")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let input_thread = input.map(|bytes| {
            let mut pipe = child.stdin.take().expect("input pipe requested");
            std::thread::spawn(move || pipe.write_all(&bytes))
        });
        fn capture(reader: impl Read, maximum: usize) -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            reader.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= maximum,
                "SSH service output exceeded its 8 MiB bound"
            );
            Ok(bytes)
        }
        let stdout = child.stdout.take().expect("stdout pipe requested");
        let stderr = child.stderr.take().expect("stderr pipe requested");
        let out = std::thread::spawn(move || capture(stdout, MAXIMUM));
        let err = std::thread::spawn(move || capture(stderr, MAXIMUM));
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if crate::now()? >= g.expires {
                let _ = child.kill();
                break child.wait()?;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let stdout = zeroize::Zeroizing::new(
            out.join()
                .map_err(|_| anyhow::anyhow!("SSH output reader failed"))??,
        );
        let stderr = zeroize::Zeroizing::new(
            err.join()
                .map_err(|_| anyhow::anyhow!("SSH error reader failed"))??,
        );
        if !stderr.is_empty() {
            eprint!(
                "{}",
                crate::terminal_text(&String::from_utf8_lossy(&stderr), true)
            );
        }
        if let Some(writer) = input_thread {
            writer
                .join()
                .map_err(|_| anyhow::anyhow!("SSH input writer failed"))??;
        }
        ensure!(
            status.success(),
            "SSH service invocation failed (status {:?})",
            status.code()
        );
        ensure!(
            crate::now()? < g.expires,
            "SSH grant expired before output could be published"
        );
        if let Some(target) = target {
            target.publish(&stdout)?;
        } else {
            print!(
                "{}",
                crate::terminal_text(&String::from_utf8_lossy(&stdout), true)
            );
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&root);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_ssh_keys_reject_options_and_malformed_blobs() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let mut blob = 11u32.to_be_bytes().to_vec();
        blob.extend(b"ssh-ed25519");
        blob.extend(32u32.to_be_bytes());
        blob.extend(key.verifying_key().to_bytes());
        let text = format!("ssh-ed25519 {}", STANDARD.encode(blob));
        assert_eq!(ssh_key(&format!("{text} optional-comment")).unwrap(), text);
        assert!(ssh_key(&format!("command=bad {text}")).is_err());
        assert!(ssh_key(&format!("{text}\n{text}")).is_err());
        assert!(ssh_key("ssh-ed25519 AAAA").is_err());
    }
}
