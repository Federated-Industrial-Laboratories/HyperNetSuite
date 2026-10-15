// SPDX-License-Identifier: MIT
// Discovery can omit certified unavailable Pages but cannot hide stale or unverifiable authority.
use super::*;
use crate::authority_inspection::domain_client::Refusal;

#[test]
fn discovery_skips_only_certified_page_context_unavailability() {
    let pages = [[1; 16], [2; 16], [3; 16]];
    let mut seen = Vec::new();
    hydrate_inventory(&pages, |raw| {
        seen.push(raw);
        if raw == pages[1] {
            Err(Refusal { code: 3 }.into())
        } else {
            Ok(())
        }
    })
    .unwrap();
    assert_eq!(seen, pages);
    for code in [2, 7, 12] {
        let mut seen = Vec::new();
        let error = hydrate_inventory(&pages, |raw| {
            seen.push(raw);
            Err(Refusal { code }.into())
        })
        .unwrap_err();
        assert_eq!(error.downcast_ref::<Refusal>().unwrap().code, code);
        assert_eq!(seen, [pages[0]], "a refusal must stop discovery");
    }
    for text in [
        "authority domain refused with code 3",
        "invalid quorum proof",
        "connection closed",
    ] {
        let error = hydrate_inventory(&pages, |_| Err(anyhow::anyhow!(text))).unwrap_err();
        assert_eq!(error.to_string(), text);
    }
}
