// SPDX-License-Identifier: MIT
// Standard MLS per-letter encryption and standard age local-state encryption.
use crate::mail_protocol as wire;
use anyhow::{Context, Result, bail, ensure};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, storage::StorageProvider};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use zeroize::Zeroize;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivatePackage {
    pub reference: String,
    pub expires: u64,
    pub bundle: String,
    pub published: bool,
    pub generation: u64,
}
impl Drop for PrivatePackage {
    fn drop(&mut self) {
        self.bundle.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Letter {
    pub route: wire::Route,
    pub subject: String,
    pub body: String,
}
impl Drop for Letter {
    fn drop(&mut self) {
        self.subject.zeroize();
        self.body.zeroize();
    }
}
pub fn signer() -> Result<(String, String)> {
    let key = SignatureKeyPair::new(SignatureScheme::ED25519)?;
    Ok((serde_json::to_string(&key)?, hex::encode(key.public())))
}
fn credential(network: &str, address: &str, device: &str) -> Result<Credential> {
    Ok(BasicCredential::new(serde_json::to_vec(
        &serde_json::json!({"version":1,"network":network,"addressId":address,"deviceId":device}),
    )?)
    .into())
}
fn bound_credential(
    network: &str,
    address: &str,
    device: &wire::Device,
) -> Result<CredentialWithKey> {
    Ok(CredentialWithKey {
        credential: credential(network, address, &device.device_id)?,
        signature_key: crate::protocol::hex_bytes::<32>(&device.mls_signature_key)?
            .to_vec()
            .into(),
    })
}
pub fn make_packages(
    network: &str,
    address: &str,
    device: &wire::Device,
    secret: &str,
    count: usize,
    expires: u64,
) -> Result<(Vec<PrivatePackage>, Vec<wire::Package>)> {
    ensure!(
        (1..=8).contains(&count) && expires > crate::now()? && expires <= device.expires,
        "invalid prekey lifetime or count"
    );
    let provider = OpenMlsRustCrypto::default();
    let signer: SignatureKeyPair = serde_json::from_str(secret)?;
    ensure!(
        hex::encode(signer.public()) == device.mls_signature_key,
        "MLS signer mismatch"
    );
    let mut private = Vec::new();
    let mut public = Vec::new();
    for _ in 0..count {
        let bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(crate::now()?, expires))
            .build(
                SUITE,
                &provider,
                &signer,
                bound_credential(network, address, device)?,
            )?;
        let reference = wire::encode(bundle.key_package().hash_ref(provider.crypto())?.as_slice());
        public.push(wire::Package {
            device_id: device.device_id.clone(),
            reference: reference.clone(),
            expires,
            package: wire::encode(&bundle.key_package().tls_serialize_detached()?),
        });
        private.push(PrivatePackage {
            reference,
            expires,
            bundle: serde_json::to_string(&bundle)?,
            published: false,
            generation: 0,
        });
    }
    Ok((private, public))
}
pub fn public_package(device: &str, private: &PrivatePackage) -> Result<wire::Package> {
    let bundle: KeyPackageBundle = serde_json::from_str(&private.bundle)?;
    Ok(wire::Package {
        device_id: device.into(),
        reference: private.reference.clone(),
        expires: private.expires,
        package: wire::encode(&bundle.key_package().tls_serialize_detached()?),
    })
}
fn receiving(manifest: &wire::Manifest, at: u64) -> Vec<&wire::Device> {
    manifest
        .devices
        .iter()
        .filter(|d| d.expires > at && d.permissions.iter().any(|p| p == "Read"))
        .collect()
}
fn expected(
    sender: &wire::Manifest,
    recipient: &wire::Manifest,
    route: &wire::Route,
    at: u64,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut result = BTreeMap::new();
    let d = sender
        .devices
        .iter()
        .find(|d| {
            d.device_id == route.sender_device
                && d.expires > at
                && d.permissions.iter().any(|p| p == "Send")
        })
        .context("mail sender lacks current Send grant")?;
    for (address, dev) in std::iter::once((&sender.address_id, d)).chain(
        receiving(recipient, at)
            .into_iter()
            .map(|d| (&recipient.address_id, d)),
    ) {
        let c = credential(&route.network, address, &dev.device_id)?;
        let key = BasicCredential::try_from(c)?.identity().to_vec();
        ensure!(
            result
                .insert(
                    key,
                    crate::protocol::hex_bytes::<32>(&dev.mls_signature_key)?.to_vec()
                )
                .is_none(),
            "duplicate MLS mail member"
        );
    }
    Ok(result)
}
fn check_members(group: &MlsGroup, expected: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<()> {
    let mut actual = BTreeMap::new();
    for member in group.members() {
        let cred = BasicCredential::try_from(member.credential)?;
        ensure!(
            actual
                .insert(cred.identity().to_vec(), member.signature_key)
                .is_none(),
            "duplicate MLS credential"
        );
    }
    ensure!(
        &actual == expected,
        "MLS membership differs from signed mailbox roster"
    );
    Ok(())
}
pub fn seal(
    secret: &str,
    claim: &wire::Claim,
    sender: &wire::Signed,
    recipient: &wire::Signed,
    letter: &Letter,
) -> Result<wire::Ciphertext> {
    let route = &letter.route;
    ensure!(
        letter.subject.len() <= 512 && letter.body.len() <= 32768,
        "mail text exceeds limit"
    );
    let a = wire::manifest(&route.network, sender)?;
    let b = wire::manifest(&route.network, recipient)?;
    let now = crate::now()?;
    ensure!(
        !a.deleted
            && !b.deleted
            && a.expires > now
            && b.expires >= route.expires
            && route.expires > now
            && route.version == 1
            && route.profile == wire::PROFILE
            && a.address_id == route.sender_address
            && b.address_id == route.recipient_address
            && b.generation == route.recipient_generation
            && wire::object_digest(recipient)? == route.recipient_manifest_digest,
        "mail route/manifest mismatch"
    );
    ensure!(
        claim.version == 1
            && claim.network == route.network
            && claim.sender_address == route.sender_address
            && claim.sender_device == route.sender_device
            && claim.recipient_address == route.recipient_address
            && claim.recipient_generation == route.recipient_generation
            && claim.recipient_manifest_digest == route.recipient_manifest_digest
            && claim.claim_id == route.claim_id
            && claim.expires == route.expires,
        "mail claim mismatch"
    );
    let provider = OpenMlsRustCrypto::default();
    let signer: SignatureKeyPair = serde_json::from_str(secret)?;
    let dev = a
        .devices
        .iter()
        .find(|d| d.device_id == route.sender_device)
        .context("sender device absent")?;
    ensure!(
        hex::encode(signer.public()) == dev.mls_signature_key,
        "sender MLS signature key mismatch"
    );
    let recipients = receiving(&b, now);
    ensure!(
        !(a.address_id == b.address_id
            && recipients
                .iter()
                .any(|d| d.device_id == route.sender_device)),
        "self delivery requires a separate Send-only device; MLS forbids duplicate signature keys"
    );
    ensure!(
        !recipients.is_empty() && claim.packages.len() == recipients.len(),
        "incomplete receiving-device package set"
    );
    let mut packages = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for p in &claim.packages {
        let dev = recipients
            .iter()
            .find(|d| d.device_id == p.device_id)
            .context("unexpected package device")?;
        ensure!(
            seen.insert(&p.device_id) && p.expires >= route.expires,
            "duplicate or expired package"
        );
        let raw = wire::decode(&p.package, 4096)?;
        let kp = KeyPackageIn::tls_deserialize_exact(&raw)?
            .validate(provider.crypto(), ProtocolVersion::Mls10)?;
        ensure!(
            kp.ciphersuite() == SUITE
                && wire::encode(kp.hash_ref(provider.crypto())?.as_slice()) == p.reference
                && kp.life_time().not_after() == p.expires
                && kp.leaf_node().credential()
                    == &credential(&route.network, &b.address_id, &dev.device_id)?
                && kp.leaf_node().signature_key().as_slice()
                    == crate::protocol::hex_bytes::<32>(&dev.mls_signature_key)?,
            "public KeyPackage binding mismatch"
        );
        packages.push(kp);
    }
    let mut group = MlsGroup::new(
        &provider,
        &signer,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        bound_credential(&route.network, &a.address_id, dev)?,
    )?;
    let (_, welcome, _) = group.add_members(&provider, &signer, &packages)?;
    group.merge_pending_commit(&provider)?;
    check_members(&group, &expected(&a, &b, route, now)?)?;
    let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(letter)?);
    let message = group
        .create_message(&provider, &signer, &plaintext)?
        .tls_serialize_detached()?;
    let ciphertext = wire::Ciphertext {
        route: route.clone(),
        sender_manifest: sender.clone(),
        recipient_manifest: recipient.clone(),
        welcome: wire::encode(&welcome.tls_serialize_detached()?),
        message: wire::encode(&message),
    };
    ensure!(
        serde_json::to_vec(&ciphertext)?.len() <= 131072,
        "encrypted mail exceeds store limit"
    );
    Ok(ciphertext)
}
pub fn open(
    cipher: &wire::Ciphertext,
    package: &PrivatePackage,
    recipient_device: &str,
    admitted: u64,
) -> Result<Letter> {
    let route = &cipher.route;
    let a = wire::manifest(&route.network, &cipher.sender_manifest)?;
    let b = wire::manifest(&route.network, &cipher.recipient_manifest)?;
    ensure!(
        a.address_id == route.sender_address
            && b.address_id == route.recipient_address
            && b.generation == route.recipient_generation
            && wire::object_digest(&cipher.recipient_manifest)? == route.recipient_manifest_digest
            && a.expires > admitted
            && b.expires > admitted
            && route.expires > admitted
            && !a.deleted
            && !b.deleted,
        "historical mail manifest mismatch"
    );
    ensure!(
        receiving(&b, admitted)
            .iter()
            .any(|d| d.device_id == recipient_device),
        "device was not a receiving member"
    );
    let provider = OpenMlsRustCrypto::default();
    let bundle: KeyPackageBundle = serde_json::from_str(&package.bundle)?;
    let reference = bundle.key_package().hash_ref(provider.crypto())?;
    ensure!(
        wire::encode(reference.as_slice()) == package.reference,
        "private package reference mismatch"
    );
    provider
        .storage()
        .write_key_package(&reference, &bundle)
        .map_err(|_| anyhow::anyhow!("cannot load private KeyPackage"))?;
    let welcome =
        match MlsMessageIn::tls_deserialize_exact(&wire::decode(&cipher.welcome, 131072)?)?
            .extract()
        {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => bail!("invalid MLS Welcome"),
        };
    let mut group =
        StagedWelcome::new_from_welcome(&provider, &MlsGroupJoinConfig::default(), welcome, None)?
            .into_group(&provider)?;
    ensure!(
        group.ciphersuite() == SUITE,
        "unexpected MLS mail ciphersuite"
    );
    check_members(&group, &expected(&a, &b, route, admitted)?)?;
    let message = MlsMessageIn::tls_deserialize_exact(&wire::decode(&cipher.message, 131072)?)?
        .try_into_protocol_message()?;
    let processed = group.process_message(&provider, message)?;
    ensure!(
        processed.credential() == &credential(&route.network, &a.address_id, &route.sender_device)?,
        "MLS application sender mismatch"
    );
    let plaintext = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => zeroize::Zeroizing::new(m.into_bytes()),
        _ => bail!("expected a mail application message"),
    };
    let letter: Letter = serde_json::from_slice(&plaintext)?;
    ensure!(
        letter.route == *route && letter.subject.len() <= 512 && letter.body.len() <= 32768,
        "encrypted route/content mismatch"
    );
    Ok(letter)
}
pub fn encrypt_age(recipient: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let recipient: age::x25519::Recipient = recipient
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid age recipient"))?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(bytes)?;
    writer.finish()?;
    Ok(out)
}
pub fn decrypt_age(
    identity: &age::x25519::Identity,
    bytes: &[u8],
    maximum: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let decryptor = age::Decryptor::new(bytes)?;
    let reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut out = zeroize::Zeroizing::new(Vec::new());
    reader.take((maximum + 1) as u64).read_to_end(&mut out)?;
    ensure!(out.len() <= maximum, "encrypted archive exceeds limit");
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn mailbox(
        network: &str,
        expires: u64,
        devices: usize,
    ) -> (wire::Signed, Vec<(wire::Device, String)>) {
        let owner = wire::new_identity();
        let address = wire::address_id(network, &owner.public_key).unwrap();
        let keys = (0..devices)
            .map(|_| {
                let request = wire::new_identity();
                let (secret, public) = signer().unwrap();
                (
                    wire::Device {
                        device_id: wire::device_id(&address, &request.public_key).unwrap(),
                        request_key: request.public_key.clone(),
                        mls_signature_key: public,
                        permissions: vec!["Read".into(), "Send".into()],
                        expires,
                    },
                    secret,
                )
            })
            .collect::<Vec<_>>();
        let m = wire::Manifest {
            version: 1,
            network: network.into(),
            address_id: address,
            owner_key: owner.public_key.clone(),
            generation: 1,
            previous_digest: None,
            expires,
            devices: keys.iter().map(|(d, _)| d.clone()).collect(),
            storage_hosts: vec!["33".repeat(32)],
            required_copies: 1,
            retention_seconds: 3600,
            deleted: false,
        };
        (
            wire::sign(wire::MANIFEST, network, &owner, &m).unwrap(),
            keys,
        )
    }
    #[test]
    fn offline_letter_checks_every_device_and_restores_only_its_prekey() {
        let network = "11".repeat(32);
        let expires = crate::now().unwrap() + 300;
        let (sender, skeys) = mailbox(&network, expires, 1);
        let (recipient, rkeys) = mailbox(&network, expires, 2);
        let a = wire::manifest(&network, &sender).unwrap();
        let b = wire::manifest(&network, &recipient).unwrap();
        let route = wire::Route {
            version: 1,
            profile: wire::PROFILE.into(),
            network: network.clone(),
            message_id: "22".repeat(16),
            replacement: 0,
            sender_address: a.address_id.clone(),
            sender_device: skeys[0].0.device_id.clone(),
            recipient_address: b.address_id.clone(),
            recipient_generation: 1,
            recipient_manifest_digest: wire::object_digest(&recipient).unwrap(),
            claim_id: "44".repeat(16),
            expires,
        };
        let mut claim = wire::Claim {
            version: 1,
            network: network.clone(),
            sender_address: route.sender_address.clone(),
            sender_device: route.sender_device.clone(),
            claim_id: route.claim_id.clone(),
            recipient_address: route.recipient_address.clone(),
            recipient_generation: 1,
            recipient_manifest_digest: route.recipient_manifest_digest.clone(),
            expires,
            packages: vec![],
        };
        let mut private = Vec::new();
        for (device, secret) in &rkeys {
            let (mut own, public) =
                make_packages(&network, &b.address_id, device, secret, 1, expires).unwrap();
            private.push(own.remove(0));
            claim.packages.extend(public);
        }
        let letter = Letter {
            route,
            subject: "Subject\u{1b}[2J".into(),
            body: "Private canary content".into(),
        };
        let cipher = seal(&skeys[0].1, &claim, &sender, &recipient, &letter).unwrap();
        for (i, p) in private.iter().enumerate() {
            let recovered: PrivatePackage =
                serde_json::from_slice(&serde_json::to_vec(p).unwrap()).unwrap();
            let got = open(
                &cipher,
                &recovered,
                &rkeys[i].0.device_id,
                crate::now().unwrap(),
            )
            .unwrap();
            assert_eq!(got.body, letter.body);
            assert!(got.route == letter.route);
        }
        let mut short = claim.clone();
        short.packages.pop();
        assert!(seal(&skeys[0].1, &short, &sender, &recipient, &letter).is_err());
        let mut wrong = claim.clone();
        wrong.packages[0].expires -= 1;
        assert!(seal(&skeys[0].1, &wrong, &sender, &recipient, &letter).is_err());
        let mut trailing = claim.clone();
        let mut raw = wire::decode(&trailing.packages[0].package, 4096).unwrap();
        raw.push(0);
        trailing.packages[0].package = wire::encode(&raw);
        assert!(seal(&skeys[0].1, &trailing, &sender, &recipient, &letter).is_err());
        let mut altered = cipher.clone();
        altered.route.message_id = "55".repeat(16);
        assert!(
            open(
                &altered,
                &private[0],
                &rkeys[0].0.device_id,
                crate::now().unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn standard_age_rejects_another_key_and_modified_ciphertext() {
        let identity = age::x25519::Identity::generate();
        let bytes = encrypt_age(&identity.to_public().to_string(), b"mail-private-canary").unwrap();
        assert!(!bytes.windows(19).any(|w| w == b"mail-private-canary"));
        assert_eq!(
            decrypt_age(&identity, &bytes, 64).unwrap().as_slice(),
            b"mail-private-canary"
        );
        assert!(decrypt_age(&age::x25519::Identity::generate(), &bytes, 64).is_err());
        let mut corrupt = bytes;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(decrypt_age(&identity, &corrupt, 64).is_err());
    }
}
