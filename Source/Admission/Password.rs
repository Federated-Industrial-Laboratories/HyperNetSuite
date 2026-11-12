// SPDX-License-Identifier: MIT
// Server passphrases use a bounded Argon2id verifier and never become account keys.
use anyhow::{Result, ensure};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

const MEMORY_KIB: u32 = 19456;
const PASSES: u32 = 2;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Verifier {
    version: u8,
    encoded: String,
}
impl Verifier {
    pub fn create(password: &[u8]) -> Result<Self> {
        ensure!(
            (12..=128).contains(&password.len()) && !password.iter().any(|b| b.is_ascii_control()),
            "use a passphrase of 12 to 128 bytes without control characters"
        );
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(MEMORY_KIB, PASSES, 1, Some(32))
            .map_err(|_| anyhow::anyhow!("password parameters unavailable"))?;
        let encoded = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password(password, &salt)
            .map_err(|_| anyhow::anyhow!("password verifier unavailable"))?
            .to_string();
        Ok(Self {
            version: 1,
            encoded,
        })
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.encoded.len() <= 256,
            "unsupported password verifier"
        );
        let hash = PasswordHash::new(&self.encoded)
            .map_err(|_| anyhow::anyhow!("invalid password verifier"))?;
        ensure!(
            hash.algorithm.as_str() == "argon2id"
                && hash.version == Some(19)
                && hash.params.iter().count() == 3
                && hash.params.get_decimal("m") == Some(MEMORY_KIB)
                && hash.params.get_decimal("t") == Some(PASSES)
                && hash.params.get_decimal("p") == Some(1)
                && hash.hash.is_some_and(|h| h.len() == 32),
            "password verifier exceeds fixed admission cost"
        );
        let mut salt = [0; 64];
        let salt = hash
            .salt
            .ok_or_else(|| anyhow::anyhow!("password salt missing"))?
            .decode_b64(&mut salt)
            .map_err(|_| anyhow::anyhow!("password salt invalid"))?;
        ensure!(salt.len() == 16, "password salt length differs");
        Ok(())
    }
    pub fn verify(&self, password: &[u8]) -> Result<bool> {
        self.validate()?;
        if !(12..=128).contains(&password.len()) {
            return Ok(false);
        }
        let hash = PasswordHash::new(&self.encoded)
            .map_err(|_| anyhow::anyhow!("invalid password verifier"))?;
        Ok(Argon2::default().verify_password(password, &hash).is_ok())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotating_password_does_not_accept_old_secret_or_imported_cost() {
        let old = Verifier::create(b"separate admission phrase").unwrap();
        let changed = Verifier::create(b"replacement admission phrase").unwrap();
        assert!(old.verify(b"separate admission phrase").unwrap());
        assert!(!changed.verify(b"separate admission phrase").unwrap());
        assert!(changed.verify(b"replacement admission phrase").unwrap());
        let mut malicious = old.clone();
        malicious.encoded = malicious.encoded.replace("m=19456", "m=4294967295");
        assert!(malicious.verify(b"separate admission phrase").is_err());
    }
}
