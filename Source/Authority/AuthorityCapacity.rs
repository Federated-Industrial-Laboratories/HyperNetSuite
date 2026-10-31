// SPDX-License-Identifier: MIT
//! Coupled retained-state bounds; network frame limits are independent.
pub const MAX_RECORDS: usize = 2048;

pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;

#[cfg(test)]
include!("../../Tests/Support/Authority/AuthorityCapacity.rs");
