// SPDX-License-Identifier: MIT
// Context for recipient-bound encrypted file metadata.
use serde::{Deserialize, Serialize};
pub const MAX_FILE: u64 = 8 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Offer {
    pub version: u32,
    pub network: String,
    pub transfer_id: String,
    pub sender_key: String,
    pub recipient_key: String,
    pub recipient_encryption_key: String,
    pub payload_bytes: u64,
    pub payload_digest: String,
    pub file_bytes: u64,
    pub label: String,
    pub expires: u64,
}
