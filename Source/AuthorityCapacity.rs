// SPDX-License-Identifier: MIT
//! Coupled retained-state bounds; network frame limits are independent.
pub const MAX_RECORDS: usize = 2048;
#[cfg(test)]
pub const MAX_STREAMS: usize = 256;
pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
