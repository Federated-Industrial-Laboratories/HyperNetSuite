// SPDX-License-Identifier: MIT
// Versioned signed requests over TLS 1.3 with explicit network trust roots.
use crate::{Config, Identity, files};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Url, blocking::Client, tls::Version};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};

const DOMAIN: &[u8] = b"HyperNet/Request/1\0";
pub fn hex_bytes<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!(
            "expected canonical lowercase hexadecimal value of {} bytes",
            N
        );
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}
pub fn endpoint(text: &str) -> Result<Url> {
    let url = Url::parse(text).context("invalid endpoint URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("endpoint must be an HTTPS origin without credentials, path, query or fragment");
    }
    Ok(url)
}
pub fn client(config: &Config) -> Result<Client> {
    let certificate =
        reqwest::Certificate::from_pem(&files::read_bounded(&config.ca_certificate, false)?)?;
    let mut builder = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(certificate)
        .min_tls_version(Version::TLS_1_3)
        .max_tls_version(Version::TLS_1_3)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));
    match (&config.client_certificate, &config.client_key) {
        (Some(cert), Some(key)) => {
            let mut pem = zeroize::Zeroizing::new(files::read_bounded(cert, false)?);
            pem.extend_from_slice(b"\n");
            pem.extend_from_slice(&files::read_bounded(key, true)?);
            builder = builder.identity(reqwest::Identity::from_pem(&pem)?);
        }
        (None, None) => {}
        _ => bail!("client certificate and key must be configured together"),
    }
    Ok(builder.build()?)
}
pub fn signed(
    config: &Config,
    identity: &Identity,
    request_id: &str,
    issued_at: u64,
    command: Value,
) -> Result<Value> {
    hex_bytes::<16>(request_id)?;
    let payload = serde_json::to_vec(
        &json!({"version":1,"requestId":request_id,"issuedAt":issued_at,"command":command}),
    )?;
    if payload.len() > 65536 {
        bail!("command exceeds protocol limit");
    }
    let mut message = Vec::from(DOMAIN);
    message.extend_from_slice(&hex_bytes::<32>(&config.network)?);
    message.extend_from_slice(&hex_bytes::<32>(&identity.public_key)?);
    message.extend_from_slice(&payload);
    let secret = zeroize::Zeroizing::new(hex_bytes::<32>(&identity.secret_key)?);
    let key = SigningKey::from_bytes(&secret);
    let signature = key.sign(&message);
    Ok(
        json!({"network":config.network,"publicKey":identity.public_key,"payload":URL_SAFE_NO_PAD.encode(payload),"signature":hex::encode(signature.to_bytes())}),
    )
}
pub fn sign_consent(identity: &Identity, payload: &[u8]) -> Result<Vec<u8>> {
    let mut message = b"HyperNet/Consent/3\0".to_vec();
    message.extend_from_slice(payload);
    let secret = zeroize::Zeroizing::new(hex_bytes::<32>(&identity.secret_key)?);
    let key = SigningKey::from_bytes(&secret);
    Ok(serde_json::to_vec(
        &json!({"payload":URL_SAFE_NO_PAD.encode(payload),"signature":hex::encode(key.sign(&message).to_bytes())}),
    )?)
}
pub fn send(
    config: &Config,
    identity: &Identity,
    request_id: &str,
    issued_at: u64,
    command: Value,
) -> Result<Value> {
    send_envelope(
        config,
        &signed(config, identity, request_id, issued_at, command)?,
    )
}

pub fn send_envelope(config: &Config, envelope: &Value) -> Result<Value> {
    if serde_json::to_vec(envelope)?.len() > 98304 {
        bail!("request exceeds protocol limit");
    }
    let url = endpoint(&config.endpoint)?.join("V1/Command")?;
    let response=client(config)?.post(url).json(envelope)
        .send().map_err(|_|anyhow::anyhow!("request failed; network availability, certificate trust or response time may be invalid"))?;
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .take(262145)
        .read_to_end(&mut bytes)
        .context("response read failed")?;
    if bytes.len() > 262144 {
        bail!("response exceeded protocol limit");
    }
    let value: Value = serde_json::from_slice(&bytes).context("invalid response JSON")?;
    let code = value
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("InvalidResponse");
    if !status.is_success() || value.get("ok") != Some(&Value::Bool(true)) {
        if code.len() <= 64 && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            bail!("authority refused request: {code}");
        }
        bail!("authority refused request");
    }
    if value.get("epoch").and_then(Value::as_u64).is_none() || value.get("result").is_none() {
        bail!("incomplete authority response");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    #[test]
    fn signatures_bind_network_actor_and_exact_payload() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let identity = Identity {
            secret_key: hex::encode(key.to_bytes()),
            public_key: hex::encode(key.verifying_key().to_bytes()),
        };
        let config = Config {
            application: false,
            network: "01".repeat(32),
            endpoint: "https://example.test".into(),
            ca_certificate: "Unused".into(),
            identity: "Unused".into(),
            client_certificate: None,
            client_key: None,
        };
        let envelope = signed(
            &config,
            &identity,
            &"02".repeat(16),
            42,
            json!({"type":"Status"}),
        )
        .unwrap();
        let payload = URL_SAFE_NO_PAD
            .decode(envelope["payload"].as_str().unwrap())
            .unwrap();
        let mut message = Vec::from(DOMAIN);
        message.extend([1; 32]);
        message.extend(key.verifying_key().to_bytes());
        message.extend(&payload);
        let signature = Signature::from_bytes(
            &hex_bytes::<64>(envelope["signature"].as_str().unwrap()).unwrap(),
        );
        key.verifying_key().verify(&message, &signature).unwrap();
        message[DOMAIN.len()] ^= 1;
        assert!(key.verifying_key().verify(&message, &signature).is_err());
    }
    #[test]
    fn endpoint_rejects_untrusted_url_components() {
        for url in [
            "http://example.test",
            "https://user@example.test",
            "https://example.test/path",
            "https://example.test/?secret=x",
            "https://example.test/#x",
        ] {
            assert!(endpoint(url).is_err());
        }
        assert!(endpoint("https://[::1]:8443").is_ok());
    }
}
