// SPDX-License-Identifier: MIT
// A single bounded HTTP/1 request exposes only the fixed admission endpoints.
use anyhow::{Result, ensure};
use std::io::{BufRead, Read, Write};

pub const BODY_BYTES: usize = 65536;
const HEADER_BYTES: usize = 8192;
pub enum Request {
    Landing,
    Script,
    Descriptor,
    Challenge(zeroize::Zeroizing<Vec<u8>>),
    Claim(zeroize::Zeroizing<Vec<u8>>),
}
fn line(reader: &mut impl BufRead, remaining: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(remaining as u64 + 1)
        .read_until(b'\n', &mut bytes)?;
    ensure!(
        bytes.len() <= remaining && bytes.ends_with(b"\r\n"),
        "invalid bounded HTTP header"
    );
    bytes.truncate(bytes.len() - 2);
    Ok(bytes)
}
pub fn request(reader: &mut impl BufRead, origin: &reqwest::Url) -> Result<Request> {
    let first = line(reader, HEADER_BYTES)?;
    let mut remaining = HEADER_BYTES - first.len() - 2;
    let first = std::str::from_utf8(&first)?;
    let fields = first.split(' ').collect::<Vec<_>>();
    ensure!(
        fields.len() == 3 && fields[2] == "HTTP/1.1" && matches!(fields[0], "GET" | "POST"),
        "unsupported admission HTTP method"
    );
    let mut headers = std::collections::BTreeMap::new();
    loop {
        let bytes = line(reader, remaining)?;
        remaining = remaining.saturating_sub(bytes.len() + 2);
        if bytes.is_empty() {
            break;
        }
        ensure!(headers.len() < 32, "HTTP header count exceeds bound");
        let header = std::str::from_utf8(&bytes)?;
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid header"))?;
        ensure!(
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && value.bytes().all(|b| b == b'\t' || (32..=126).contains(&b)),
            "invalid header characters"
        );
        ensure!(
            headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_none(),
            "duplicate HTTP header"
        );
    }
    let host = match origin.port() {
        Some(port) => format!("{}:{port}", origin.host_str().unwrap_or_default()),
        None => origin.host_str().unwrap_or_default().to_owned(),
    };
    ensure!(
        headers
            .get("host")
            .is_some_and(|v| v.eq_ignore_ascii_case(&host)),
        "HTTP host differs from server origin"
    );
    ensure!(
        !headers.contains_key("transfer-encoding")
            && !headers.contains_key("expect")
            && !headers.contains_key("upgrade"),
        "unsupported admission body framing"
    );
    if let Some(value) = headers.get("origin") {
        ensure!(
            value == origin.origin().ascii_serialization().as_str(),
            "cross-origin admission refused"
        );
    }
    let length = match headers.get("content-length") {
        Some(value) => {
            ensure!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "invalid content length"
            );
            value.parse::<usize>()?
        }
        None => 0,
    };
    ensure!(length <= BODY_BYTES, "admission request exceeds bound");
    if fields[0] == "GET" {
        ensure!(length == 0, "GET body is not accepted");
        return match fields[1] {
            "/" | "/join" => Ok(Request::Landing),
            "/join.js" => Ok(Request::Script),
            "/v1/admission/descriptor" => Ok(Request::Descriptor),
            _ => Err(anyhow::anyhow!("unknown admission endpoint")),
        };
    }
    ensure!(
        matches!(
            fields[1],
            "/v1/admission/challenge" | "/v1/admission/request"
        ),
        "unknown admission endpoint"
    );
    ensure!(
        length > 0
            && headers
                .get("content-type")
                .is_some_and(|v| v == "application/json"),
        "admission requires a bounded JSON body"
    );
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    Ok(if fields[1].ends_with("/challenge") {
        Request::Challenge(bytes)
    } else {
        Request::Claim(bytes)
    })
}
pub fn response(
    writer: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    ensure!(
        body.len() <= super::transport::RESPONSE_BYTES,
        "admission response exceeds bound"
    );
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        409 => "Conflict",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => return Err(anyhow::anyhow!("invalid response status")),
    };
    ensure!(
        matches!(
            content_type,
            "application/json" | "text/html; charset=utf-8" | "text/javascript; charset=utf-8"
        ),
        "unsupported response type"
    );
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\r\n",
        body.len()
    )?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn previews_cannot_claim_and_ambiguous_frames_are_refused() {
        let origin = reqwest::Url::parse("https://example.org:8443/").unwrap();
        let parse = |value: &str| request(&mut std::io::Cursor::new(value.as_bytes()), &origin);
        assert!(matches!(
            parse("GET /join HTTP/1.1\r\nHost: example.org:8443\r\n\r\n").unwrap(),
            Request::Landing
        ));
        for request in [
            "GET /v1/admission/request HTTP/1.1\r\nHost: example.org:8443\r\n\r\n",
            "POST /v1/admission/request HTTP/1.1\r\nHost: example.org:8443\r\nContent-Length: 2\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
            "POST /v1/admission/request HTTP/1.1\r\nHost: example.org:8443\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /v1/admission/request HTTP/1.1\r\nHost: example.org:8443\r\nOrigin: https://elsewhere.invalid\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
        ] {
            assert!(parse(request).is_err());
        }
        assert!(matches!(parse("POST /v1/admission/request HTTP/1.1\r\nHost: example.org:8443\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}").unwrap(),Request::Claim(_)));
    }
}
