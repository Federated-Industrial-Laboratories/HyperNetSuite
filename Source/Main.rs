// SPDX-License-Identifier: MIT
// Independent signed HyperNet command client and local device-key management.
#[path = "BridgeConsent.rs"]
mod bridge_consent;
#[path = "Federation.rs"]
mod federation;
#[path = "FederationProof.rs"]
mod federation_proof;
#[path = "Files.rs"]
mod files;
#[path = "Mail.rs"]
mod mail;
#[path = "MailArchive.rs"]
mod mail_archive;
#[path = "MailCrypto.rs"]
mod mail_crypto;
#[path = "MailDelivery.rs"]
mod mail_delivery;
#[path = "MailProtocol.rs"]
mod mail_protocol;
#[path = "MailTls.rs"]
mod mail_tls;
#[path = "MailVault.rs"]
mod mail_vault;
#[path = "Markup.rs"]
mod markup;
#[path = "Navigation.rs"]
mod navigation;
#[path = "PageProof.rs"]
mod page_proof;
#[path = "Pages.rs"]
mod pages;
#[path = "Protocol.rs"]
mod protocol;
#[path = "Reader.rs"]
mod reader;
#[path = "Services.rs"]
mod services;
#[path = "ShareWithdrawal.rs"]
mod share_withdrawal;
#[path = "SshProof.rs"]
mod ssh_proof;
#[path = "TransferFiles.rs"]
mod transfer_files;
#[path = "TransferProtocol.rs"]
mod transfer_protocol;
#[path = "TransferVault.rs"]
mod transfer_vault;
#[path = "Transfers.rs"]
mod transfers;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "HyperNetSuite",
    version,
    about = "Independent HyperNet command-line client"
)]
struct Options {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Consented encrypted file exchange.
    Transfers(transfers::Arguments),
    /// Discover, request and invoke separately consented SSH services.
    #[command(subcommand)]
    Services(services::Command),
    /// Private encrypted mail, selected storage and device management.
    Mail(mail::Arguments),
    /// Agree, share, review and read explicitly federated Pages.
    #[command(subcommand)]
    Federation(federation::Command),
    /// Author, review and read inert HyperNet Pages.
    #[command(subcommand)]
    Pages(pages::Command),
    /// Generate a device key locally. The secret is written only to a new private file.
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    /// Write a new client profile after verifying the network fingerprint separately.
    Configure {
        #[arg(long)]
        network: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        client_certificate: Option<PathBuf>,
        #[arg(long)]
        client_key: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign a local host resource specification without contacting the network.
    HostConsent {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read current membership. Another device requires administration rights.
    Status {
        #[arg(long)]
        device_key: Option<String>,
    },
    /// Issue a single-use invitation bound to a device public key.
    Invite {
        #[arg(long)]
        device_key: String,
        #[arg(long, value_parser=grant_mask)]
        grants: u64,
        /// Absolute Unix expiry, no more than seven days ahead.
        #[arg(long)]
        expires: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Redeem an invitation file using this device's key.
    Redeem {
        #[arg(long)]
        invitation: PathBuf,
    },
    /// Replace a live device's network grant. Revoked keys cannot be restored.
    Grant {
        #[arg(long)]
        device_key: String,
        #[arg(long, value_parser=grant_mask)]
        grants: u64,
        #[arg(long)]
        expires: u64,
    },
    Revoke {
        #[arg(long)]
        device_key: String,
    },
    /// Record consent to an exact local hosting profile digest.
    Consent {
        #[arg(long)]
        profile: String,
        #[arg(long, value_parser=clap::value_parser!(u64).range(1..=7))]
        grants: u64,
        #[arg(long)]
        expires: u64,
        #[arg(long)]
        certificate: String,
        /// Exact signed local consent file; required for Pages hosting.
        #[arg(long)]
        document: Option<PathBuf>,
    },
    /// Withdraw network hosting consent. Stop the local host first for immediate withdrawal.
    Withdraw,
    /// Verify fresh authority for an exact hosting profile using mutual TLS.
    Heartbeat {
        #[arg(long)]
        profile: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    network: String,
    endpoint: String,
    ca_certificate: PathBuf,
    identity: PathBuf,
    #[serde(default)]
    client_certificate: Option<PathBuf>,
    #[serde(default)]
    client_key: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[zeroize(drop)]
struct Identity {
    secret_key: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Invitation {
    version: u32,
    network: String,
    device_key: String,
    secret: String,
    expires: u64,
    grants: u64,
    request_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostSpecification {
    grants: u64,
    expires: u64,
    memory_bytes: u64,
    pids: u64,
    cpu_quota: u64,
    cpu_period: u64,
    state_bytes: u64,
    authority_endpoint: String,
    authority_address: String,
    services: Option<Vec<String>>,
    namespaces: Option<Vec<String>>,
    page_cache_bytes: Option<u64>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "HyperNetSuite: {}",
            terminal_text(&format!("{error:#}"), false)
        );
        std::process::exit(1);
    }
}

fn grant_mask(value: &str) -> std::result::Result<u64, String> {
    match value.parse::<u64>() {
        Ok(mask @ (1 | 3 | 5 | 7 | 9)) => Ok(mask),
        _ => Err("grant must be 1, 3, 5, 7 or dedicated federation grant 9".into()),
    }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn random_hex<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn checked_key(value: &str) -> Result<()> {
    protocol::hex_bytes::<32>(value).map(|_| ())
}
fn print_value(value: &Value) -> Result<()> {
    let raw = serde_json::to_string_pretty(value)?;
    println!("{}", terminal_text(&raw, true));
    Ok(())
}

fn terminal_text(raw: &str, multiline: bool) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        // Only formatting newlines may pass. Imported text never supplies terminal controls.
        if (ch.is_control() && !(multiline && ch == '\n'))
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}')
            || ('\u{202a}'..='\u{202e}').contains(&ch)
            || ('\u{2066}'..='\u{2069}').contains(&ch)
        {
            use std::fmt::Write;
            write!(out, "\\u{:04x}", ch as u32).expect("writing to a string cannot fail");
        } else {
            out.push(ch);
        }
    }
    out
}

fn run() -> Result<()> {
    files::disable_dumps()?;
    let options = match Options::try_parse() {
        Ok(options) => options,
        Err(error) => {
            let text = terminal_text(&error.to_string(), true);
            if error.use_stderr() {
                eprint!("{text}");
            } else {
                print!("{text}");
            }
            std::process::exit(error.exit_code());
        }
    };
    match options.command {
        Command::Transfers(arguments) => {
            return transfers::run(options.config.as_deref(), arguments);
        }
        Command::Services(command) => return services::run(options.config.as_deref(), command),
        Command::Mail(arguments) => return mail::run(options.config.as_deref(), arguments),
        Command::Pages(command) => return pages::run(options.config.as_deref(), command),
        Command::Federation(command) => return federation::run(options.config.as_deref(), command),
        Command::Keygen { output } => {
            let key = SigningKey::generate(&mut OsRng);
            let identity = Identity {
                secret_key: hex::encode(key.to_bytes()),
                public_key: hex::encode(key.verifying_key().to_bytes()),
            };
            files::write_new(&output, &serde_json::to_vec_pretty(&identity)?)?;
            return print_value(&json!({"publicKey":identity.public_key,"identity":output}));
        }
        Command::Configure {
            network,
            endpoint,
            ca,
            identity,
            client_certificate,
            client_key,
            output,
        } => {
            checked_key(&network)?;
            protocol::endpoint(&endpoint)?;
            load_identity(&identity)?;
            if client_certificate.is_some() != client_key.is_some() {
                bail!("client certificate and key must be provided together");
            }
            let config = Config {
                network,
                endpoint,
                ca_certificate: ca.canonicalize()?,
                identity: identity.canonicalize()?,
                client_certificate: client_certificate.map(|p| p.canonicalize()).transpose()?,
                client_key: client_key.map(|p| p.canonicalize()).transpose()?,
            };
            protocol::client(&config)?;
            files::write_new(&output, &serde_json::to_vec_pretty(&config)?)?;
            return print_value(&json!({"profile":output,"network":config.network}));
        }
        command => {
            let config_path = options
                .config
                .context("--config is required for network commands")?;
            let config: Config =
                serde_json::from_slice(&files::read_bounded(&config_path, false)?)?;
            checked_key(&config.network)?;
            let identity = load_identity(&config.identity)?;
            let mut request_id = random_hex::<16>();
            let mut pending: Option<(PathBuf, Invitation)> = None;
            let body = match command {
                Command::HostConsent { spec, output } => {
                    let document: HostSpecification =
                        serde_json::from_slice(&files::read_bounded(&spec, false)?)?;
                    if document.grants != 2
                        || !(67108864..=8589934592).contains(&document.memory_bytes)
                        || !(16..=512).contains(&document.pids)
                        || !(1000..=800000).contains(&document.cpu_quota)
                        || document.cpu_period != 100000
                        || !(1048576..=268435456).contains(&document.state_bytes)
                        || document.expires <= now()?
                        || document.expires > now()?.saturating_add(604800)
                    {
                        bail!("host specification exceeds the supported consent bounds");
                    }
                    let endpoint = protocol::endpoint(&document.authority_endpoint)?;
                    let address: std::net::SocketAddr = document
                        .authority_address
                        .parse()
                        .context("authorityAddress must be a literal socket address")?;
                    if endpoint
                        .host_str()
                        .is_none_or(|name| name.parse::<std::net::IpAddr>().is_ok())
                        || endpoint.port_or_known_default() != Some(address.port())
                    {
                        bail!(
                            "host authority endpoint must use a DNS name and the pinned address port"
                        );
                    }
                    let version = match (
                        &document.services,
                        &document.namespaces,
                        document.page_cache_bytes,
                    ) {
                        (None, None, None) => 1,
                        (Some(services), Some(namespaces), Some(cache)) => {
                            if services != &["Pages"]
                                || namespaces.is_empty()
                                || namespaces.len() > 16
                                || namespaces.iter().any(|name| !markup::namespace(name))
                                || namespaces
                                    .iter()
                                    .collect::<std::collections::BTreeSet<_>>()
                                    .len()
                                    != namespaces.len()
                                || cache < 65536
                                || cache > document.state_bytes.saturating_sub(262144)
                            {
                                bail!("invalid Pages scope or cache allowance");
                            }
                            2
                        }
                        _ => bail!(
                            "Pages consent requires services, namespaces and pageCacheBytes together"
                        ),
                    };
                    let mut value = json!({
                        "version":version,"network":config.network,"deviceKey":identity.public_key,
                        "grants":document.grants,"expires":document.expires,
                        "memoryBytes":document.memory_bytes,"pids":document.pids,
                        "cpuQuota":document.cpu_quota,"cpuPeriod":document.cpu_period,
                        "stateBytes":document.state_bytes,"authorityEndpoint":document.authority_endpoint,
                        "authorityAddress":document.authority_address
                    });
                    if version == 2 {
                        value["services"] = json!(document.services);
                        value["namespaces"] = json!(document.namespaces);
                        value["pageCacheBytes"] = json!(document.page_cache_bytes);
                    }
                    let payload = serde_json::to_vec(&value)?;
                    protocol::endpoint(&document.authority_endpoint)?;
                    let mut bytes = protocol::sign_consent(&identity, &payload, version)?;
                    bytes.push(b'\n');
                    let profile = hex::encode(Sha256::digest(&bytes));
                    bytes.pop();
                    files::write_new(&output, &bytes)?;
                    return print_value(
                        &json!({"profile":profile,"consent":output,"deviceKey":identity.public_key,"hostMemoryBytes":document.memory_bytes,"relayMemoryBytes":134217728u64,"totalMemoryBytes":document.memory_bytes+134217728,"relayBytesPerSecond":1048576}),
                    );
                }
                Command::Status { device_key } => {
                    if let Some(key) = &device_key {
                        checked_key(key)?;
                    }
                    json!({"type":"Status","deviceKey":device_key})
                }
                Command::Invite {
                    device_key,
                    grants,
                    expires,
                    output,
                } => {
                    checked_key(&device_key)?;
                    let time = now()?;
                    if expires <= time || expires > time.saturating_add(604800) {
                        bail!("invitation expiry must be within the next seven days");
                    }
                    let invitation = if output.exists() {
                        let saved: Invitation =
                            serde_json::from_slice(&files::read_bounded(&output, true)?)?;
                        if saved.version != 1
                            || saved.network != config.network
                            || saved.device_key != device_key
                            || saved.grants != grants
                            || saved.expires != expires
                        {
                            bail!("existing invitation file does not match the requested grant");
                        }
                        saved
                    } else {
                        let saved = Invitation {
                            version: 1,
                            network: config.network.clone(),
                            device_key: device_key.clone(),
                            secret: random_hex::<32>(),
                            expires,
                            grants,
                            request_id: request_id.clone(),
                        };
                        // Persist before sending. Repeating this command retries the same invitation.
                        files::write_new(&output, &serde_json::to_vec_pretty(&saved)?)?;
                        saved
                    };
                    let verifier = hex::encode(Sha256::digest(protocol::hex_bytes::<32>(
                        &invitation.secret,
                    )?));
                    pending = Some((output, invitation));
                    json!({"type":"Invite","verifier":verifier,"deviceKey":device_key,"grants":grants,"expires":expires})
                }
                Command::Redeem { invitation } => {
                    let value: Invitation =
                        serde_json::from_slice(&files::read_bounded(&invitation, true)?)?;
                    if value.version != 1
                        || value.network != config.network
                        || value.device_key != identity.public_key
                    {
                        bail!("invitation does not match this network and device");
                    }
                    checked_key(&value.secret)?;
                    // Redemption is idempotent by invitation and signing key, independently of this request ID.
                    request_id = random_hex::<16>();
                    json!({"type":"Redeem","secret":value.secret})
                }
                Command::Grant {
                    device_key,
                    grants,
                    expires,
                } => {
                    checked_key(&device_key)?;
                    json!({"type":"Grant","deviceKey":device_key,"grants":grants,"expires":expires})
                }
                Command::Revoke { device_key } => {
                    checked_key(&device_key)?;
                    json!({"type":"Revoke","deviceKey":device_key})
                }
                Command::Consent {
                    profile,
                    grants,
                    expires,
                    certificate,
                    document,
                } => {
                    checked_key(&profile)?;
                    checked_key(&certificate)?;
                    let mut command = json!({"type":"Consent","profile":profile,"grants":grants,"expires":expires,"certificate":certificate});
                    if let Some(path) = document {
                        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                        let bytes = files::read_bounded(&path, false)?;
                        if bytes.len() > 16384 || hex::encode(Sha256::digest(&bytes)) != profile {
                            bail!("consent document does not match the profile or size bound");
                        }
                        command["document"] = json!(URL_SAFE_NO_PAD.encode(bytes));
                    }
                    command
                }
                Command::Withdraw => json!({"type":"Withdraw"}),
                Command::Heartbeat { profile } => {
                    checked_key(&profile)?;
                    json!({"type":"Heartbeat","profile":profile})
                }
                Command::Keygen { .. }
                | Command::Configure { .. }
                | Command::Pages(_)
                | Command::Federation(_)
                | Command::Mail(_)
                | Command::Transfers(_)
                | Command::Services(_) => {
                    unreachable!()
                }
            };
            let reply = protocol::send(&config, &identity, &request_id, now()?, body);
            if let Some((path, _invitation)) = &pending {
                eprintln!(
                    "Invitation material retained at {}. Only a successful response confirms issuance.",
                    terminal_text(&path.to_string_lossy(), false)
                );
            }
            print_value(&reply?)?;
        }
    }
    Ok(())
}

fn load_identity(path: &Path) -> Result<Identity> {
    let raw = zeroize::Zeroizing::new(files::read_bounded(path, true)?);
    let identity: Identity = serde_json::from_slice(&raw).context("invalid identity file")?;
    let key = SigningKey::from_bytes(&protocol::hex_bytes::<32>(&identity.secret_key)?);
    if hex::encode(key.verifying_key().to_bytes()) != identity.public_key {
        bail!("identity key pair does not match");
    }
    Ok(identity)
}

#[cfg(test)]
mod command_tests {
    use super::*;
    #[test]
    fn grant_arguments_keep_the_declared_unsigned_type() {
        for command in ["invite", "grant", "consent"] {
            let mut args = vec![
                "HyperNetSuite",
                command,
                "--grants",
                "3",
                "--expires",
                "1800000000",
            ];
            if command == "consent" {
                args.extend(["--profile", "00", "--certificate", "00"]);
            } else {
                args.extend(["--device-key", "00"]);
            }
            if command == "invite" {
                args.extend(["--output", "Invitation.json"]);
            }
            assert!(Options::try_parse_from(args).is_ok());
        }
    }
}
