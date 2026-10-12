// SPDX-License-Identifier: MIT
// Native OpenSSH signatures prove possession of the exact separately scoped SSH key.
use crate::{protocol, transfer_files as files};
use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};
use std::{
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const NAMESPACE: &[u8] = b"HyperNetSshKey1";
const MAXIMUM: usize = 16384;

pub fn executable(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "select an explicit absolute maintained OpenSSH path"
    );
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.mode() & 0o022 == 0
            && m.mode() & 0o111 != 0
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
        "OpenSSH executable must be owned without group or other write access"
    );
    Ok(())
}
pub fn client(binary: &Path) -> Result<()> {
    executable(binary)?;
    let output = run(Command::new(binary).arg("-V"), b"")?;
    let version = String::from_utf8_lossy(&output.1);
    let numeric = version
        .strip_prefix("OpenSSH_")
        .context("expected maintained OpenSSH")?;
    let mut parts = numeric.split('.');
    let major: u32 = parts
        .next()
        .context("missing OpenSSH major version")?
        .parse()?;
    let minor: u32 = parts
        .next()
        .context("missing OpenSSH minor version")?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()?;
    ensure!(
        major > 10 || (major == 10 && minor >= 6),
        "OpenSSH 10.6 or newer is required"
    );
    Ok(())
}
fn run(command: &mut Command, input: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut child = command
        .env_clear()
        .env("LANG", "C")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    fn read(reader: impl Read) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        reader.take((MAXIMUM + 1) as u64).read_to_end(&mut output)?;
        ensure!(
            output.len() <= MAXIMUM,
            "OpenSSH proof output exceeds its bound"
        );
        Ok(output)
    }
    let stdout = child
        .stdout
        .take()
        .context("OpenSSH output pipe unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("OpenSSH error pipe unavailable")?;
    let out = std::thread::spawn(move || read(stdout));
    let err = std::thread::spawn(move || read(stderr));
    let written = child
        .stdin
        .take()
        .context("OpenSSH input pipe unavailable")?
        .write_all(input);
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            other => {
                let _ = child.kill();
                let _ = child.wait();
                break match other {
                    Err(error) => Err(error.into()),
                    _ => Err(anyhow::anyhow!("OpenSSH proof operation timed out")),
                };
            }
        }
    };
    let stdout = out
        .join()
        .map_err(|_| anyhow::anyhow!("OpenSSH output reader failed"))??;
    let stderr = err
        .join()
        .map_err(|_| anyhow::anyhow!("OpenSSH error reader failed"))??;
    let status = status?;
    ensure!(
        status.success(),
        "OpenSSH proof operation failed; a matching unencrypted dedicated key is required: {}",
        crate::terminal_text(&String::from_utf8_lossy(&stderr), true)
    );
    written?;
    Ok((stdout, stderr))
}
fn public(key: &str) -> Result<Vec<u8>> {
    let value = key
        .strip_prefix("ssh-ed25519 ")
        .context("native Ed25519 SSH key required")?;
    let bytes = STANDARD.decode(value)?;
    ensure!(
        bytes.len() == 51
            && &bytes[..19] == b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
            && STANDARD.encode(&bytes) == value,
        "invalid canonical SSH public key"
    );
    Ok(bytes)
}
fn message(network: &str, member: &str, public: &[u8]) -> Result<Vec<u8>> {
    let mut message = b"HyperNet/SshKeyProof/1\0".to_vec();
    message.extend(protocol::hex_bytes::<32>(network)?);
    message.extend(protocol::hex_bytes::<32>(member)?);
    message.extend_from_slice(&public[19..]);
    Ok(message)
}
fn field<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8]> {
    ensure!(cursor.len() >= 4, "truncated SSH signature field");
    let length = u32::from_be_bytes(cursor[..4].try_into()?) as usize;
    *cursor = &cursor[4..];
    ensure!(length <= cursor.len(), "truncated SSH signature value");
    let value = &cursor[..length];
    *cursor = &cursor[length..];
    Ok(value)
}
fn append(value: &mut Vec<u8>, bytes: &[u8]) {
    value.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    value.extend_from_slice(bytes);
}
fn verify_blob(blob: &[u8], network: &str, member: &str, key: &str) -> Result<()> {
    let expected = public(key)?;
    ensure!(
        blob.len() <= MAXIMUM && blob.starts_with(b"SSHSIG\0\0\0\x01"),
        "unsupported SSH signature profile"
    );
    let mut cursor = &blob[10..];
    ensure!(
        field(&mut cursor)? == expected
            && field(&mut cursor)? == NAMESPACE
            && field(&mut cursor)?.is_empty()
            && field(&mut cursor)? == b"sha512",
        "SSH proof key, namespace or algorithm mismatch"
    );
    let mut signature = field(&mut cursor)?;
    ensure!(
        cursor.is_empty() && field(&mut signature)? == b"ssh-ed25519",
        "invalid SSH proof signature"
    );
    let bytes = field(&mut signature)?;
    ensure!(
        bytes.len() == 64 && signature.is_empty(),
        "invalid SSH proof signature bytes"
    );
    let mut signed = b"SSHSIG".to_vec();
    append(&mut signed, NAMESPACE);
    append(&mut signed, b"");
    append(&mut signed, b"sha512");
    append(
        &mut signed,
        &Sha512::digest(message(network, member, &expected)?),
    );
    VerifyingKey::from_bytes(expected[19..].try_into()?)?
        .verify_strict(&signed, &Signature::from_bytes(bytes.try_into()?))?;
    Ok(())
}
pub fn verify(proof: &str, network: &str, member: &str, key: &str) -> Result<()> {
    ensure!(proof.len() <= MAXIMUM, "SSH proof is oversized");
    let blob = URL_SAFE_NO_PAD.decode(proof)?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&blob) == proof,
        "noncanonical SSH proof encoding"
    );
    verify_blob(&blob, network, member, key)
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
pub fn generate(
    work_directory: &Path,
    binary: &Path,
    identity: &Path,
    network: &str,
    member: &str,
    key: &str,
) -> Result<String> {
    client(binary)?;
    let keygen = binary
        .parent()
        .context("OpenSSH directory missing")?
        .join("ssh-keygen");
    executable(&keygen)?;
    let public = public(key)?;
    let _parent = files::private_directory(work_directory)?;
    let root = work_directory.join(format!("SshProof{}", crate::random_hex::<16>()));
    files::create_directory(&root)?;
    let root = Temporary(root);
    let path = root.0.join("Identity");
    let secret = zeroize::Zeroizing::new(files::read(identity, MAXIMUM, true)?);
    files::write_new(&path, &secret)?;
    let output = run(
        Command::new(keygen)
            .args([
                "-Y",
                "sign",
                "-n",
                "HyperNetSshKey1",
                "-O",
                "hashalg=sha512",
                "-P",
                "",
                "-q",
                "-f",
            ])
            .arg(&path),
        &message(network, member, &public)?,
    )?;
    let text = std::str::from_utf8(&output.0)?.trim();
    let encoded = text
        .strip_prefix("-----BEGIN SSH SIGNATURE-----\n")
        .and_then(|s| s.strip_suffix("\n-----END SSH SIGNATURE-----"))
        .context("invalid armored OpenSSH signature")?;
    let encoded: String = encoded.lines().collect();
    let blob = STANDARD.decode(&encoded)?;
    verify_blob(&blob, network, member, key)?;
    Ok(URL_SAFE_NO_PAD.encode(blob))
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn standard_ssh_signature_binds_network_member_and_native_key() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let mut public = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        public.extend(signing.verifying_key().to_bytes());
        let key = format!("ssh-ed25519 {}", STANDARD.encode(&public));
        let network = "11".repeat(32);
        let member = "22".repeat(32);
        let mut signed = b"SSHSIG".to_vec();
        append(&mut signed, NAMESPACE);
        append(&mut signed, b"");
        append(&mut signed, b"sha512");
        append(
            &mut signed,
            &Sha512::digest(message(&network, &member, &public).unwrap()),
        );
        let mut signature = Vec::new();
        append(&mut signature, b"ssh-ed25519");
        append(&mut signature, &signing.sign(&signed).to_bytes());
        let mut blob = b"SSHSIG\0\0\0\x01".to_vec();
        append(&mut blob, &public);
        append(&mut blob, NAMESPACE);
        append(&mut blob, b"");
        append(&mut blob, b"sha512");
        append(&mut blob, &signature);
        verify_blob(&blob, &network, &member, &key).unwrap();
        assert!(verify_blob(&blob, &"33".repeat(32), &member, &key).is_err());
        assert!(verify_blob(&blob, &network, &"33".repeat(32), &key).is_err());
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(verify_blob(&blob, &network, &member, &key).is_err());
    }
}
