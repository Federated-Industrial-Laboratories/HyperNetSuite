// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub(crate) use proof::{descriptor, genesis, ready_statement};

#[cfg(test)]
pub use assembly::terminal_checkpoint;
