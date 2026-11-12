// SPDX-License-Identifier: MIT
// Join locations carry bounded trust pins and optional private invitation fragments.
use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub const MAX_LOCATION_BYTES: usize = 2048;
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Application {
    Native,
    Hrc,
}
impl Application {
    pub fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Hrc => "hrc",
        }
    }
}
/// Neither Debug nor Display is implemented: fragments can contain bearer secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct Location {
    pub origin: Url,
    pub identity_pin: Option<[u8; 32]>,
    pub certificate_authority_pin: Option<[u8; 32]>,
    pub invitation: Option<[u8; 32]>,
    pub secret: Option<String>,
    pub application: Application,
}
impl Drop for Location {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
fn pin(value: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| anyhow::anyhow!("invalid join pin"))?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&bytes) == value,
        "noncanonical join pin"
    );
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("join pin must contain 32 bytes"))
}
impl Location {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        ensure!(
            !input.is_empty()
                && input.len() <= MAX_LOCATION_BYTES
                && !input.chars().any(|c| c.is_control() || c.is_whitespace()),
            "invalid server address or invitation"
        );
        let native = input.starts_with("hypernet-join://");
        let selected = if native {
            input.replacen("hypernet-join://", "https://", 1)
        } else if !input.contains("://") {
            format!("https://{input}")
        } else {
            input.to_owned()
        };
        let mut origin =
            Url::parse(&selected).map_err(|_| anyhow::anyhow!("invalid server address"))?;
        ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.port() != Some(0)
                && origin.query().is_none(),
            "join requires an HTTPS origin without credentials or query parameters"
        );
        ensure!(
            if native {
                origin.path() == "/v1"
            } else {
                matches!(origin.path(), "/" | "/join")
            },
            "unsupported join path or version"
        );
        let mut fields = BTreeMap::new();
        if let Some(fragment) = origin.fragment() {
            ensure!(fragment.len() <= 768, "join fragment exceeds its bound");
            // Parse as form data without accepting a remote redirect or executable target.
            let mut query = Url::parse("https://localhost/")?;
            query.set_query(Some(fragment));
            for (key, value) in query.query_pairs() {
                ensure!(
                    matches!(
                        key.as_ref(),
                        "v" | "pin" | "ca" | "invite" | "secret" | "app"
                    ) && fields.insert(key.to_string(), value.to_string()).is_none(),
                    "unknown or duplicate join field"
                );
            }
            ensure!(
                fields.get("v").map(String::as_str) == Some("1"),
                "unsupported join version"
            );
        } else {
            ensure!(!native, "native invitation requires a versioned fragment");
        }
        let field_pin = |key: &str| fields.get(key).map(|s| pin(s)).transpose();
        let identity_pin = field_pin("pin")?;
        let certificate_authority_pin = field_pin("ca")?;
        let invitation = field_pin("invite")?;
        let secret = fields.remove("secret");
        if let Some(secret) = &secret {
            pin(secret)?;
        }
        ensure!(
            invitation.is_some() == secret.is_some(),
            "invitation identifier and secret must appear together"
        );
        ensure!(
            certificate_authority_pin.is_none() || identity_pin.is_some(),
            "private certificate trust requires a native identity pin"
        );
        ensure!(
            !native || identity_pin.is_some(),
            "native invitation requires an identity pin"
        );
        let application = match fields.get("app").map(String::as_str) {
            None | Some("native") => Application::Native,
            Some("hrc") => Application::Hrc,
            _ => bail!("unsupported application selection"),
        };
        origin.set_fragment(None);
        origin.set_path("/");
        Ok(Self {
            origin,
            identity_pin,
            certificate_authority_pin,
            invitation,
            secret,
            application,
        })
    }
    pub fn url(&self, native: bool) -> Result<String> {
        ensure!(
            !native || self.identity_pin.is_some(),
            "native invitation requires an identity pin"
        );
        let mut url = self.origin.clone();
        url.set_path(if native { "/v1" } else { "/join" });
        let mut fields = Url::parse("https://localhost/")?;
        {
            let mut query = fields.query_pairs_mut();
            query.append_pair("v", "1");
            for (name, value) in [
                ("pin", self.identity_pin),
                ("ca", self.certificate_authority_pin),
                ("invite", self.invitation),
            ] {
                if let Some(value) = value {
                    query.append_pair(name, &URL_SAFE_NO_PAD.encode(value));
                }
            }
            if let Some(secret) = &self.secret {
                query.append_pair("secret", secret);
            }
            query.append_pair("app", self.application.name());
        }
        url.set_fragment(fields.query());
        let value = if native {
            url.as_str().replacen("https://", "hypernet-join://", 1)
        } else {
            url.to_string()
        };
        ensure!(
            value.len() <= MAX_LOCATION_BYTES,
            "join location exceeds its bound"
        );
        Ok(value)
    }
    pub fn endpoint(&self, path: &str) -> Result<Url> {
        ensure!(
            matches!(
                path,
                "/join"
                    | "/v1/admission/descriptor"
                    | "/v1/admission/challenge"
                    | "/v1/admission/request"
            ),
            "unknown admission endpoint"
        );
        let mut value = self.origin.clone();
        value.set_path(path);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_location_roundtrip_keeps_secrets_out_of_request_urls() {
        let value = format!(
            "https://127.0.0.1:25444/join#v=1&pin={}&ca={}&invite={}&secret={}&app=hrc",
            URL_SAFE_NO_PAD.encode([1; 32]),
            URL_SAFE_NO_PAD.encode([2; 32]),
            URL_SAFE_NO_PAD.encode([3; 32]),
            URL_SAFE_NO_PAD.encode([4; 32])
        );
        let location = Location::parse(&value).unwrap();
        assert_eq!(
            location
                .endpoint("/v1/admission/descriptor")
                .unwrap()
                .as_str(),
            "https://127.0.0.1:25444/v1/admission/descriptor"
        );
        let round = Location::parse(&location.url(true).unwrap()).unwrap();
        assert!(round == location);
    }
    #[test]
    fn hostile_or_ambiguous_locations_are_refused() {
        for input in [
            "http://example.org/join",
            "https://user:password@example.org/join",
            "file:///etc/passwd",
            "https://example.org/redirect",
            "https://example.org/join?url=https://evil.invalid",
            "https://example.org/join#v=1&v=1",
            "https://example.org/join#v=1&exec=sh",
            "https://example.org/join#v=1&app=unknown",
            "https://example.org/join#v=2",
            "hypernet-join://example.org/v1#v=1",
        ] {
            assert!(Location::parse(input).is_err(), "{input}");
        }
        assert!(Location::parse("example.org:443").is_ok());
    }
}
