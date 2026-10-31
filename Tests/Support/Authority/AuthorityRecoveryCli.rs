// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
use crate::authority_epoch::archive::Activated;

#[cfg(test)]
use crate::authority_history;

#[cfg(test)]
fn predecessor(
    bootstrap: &[u8],
    checkpoint: Option<&[u8]>,
    epochs: &[Activated],
) -> Result<recovery::Predecessor> {
    let checked = trust::inspect(bootstrap, true)?;
    let current = archive::resolve(checked.descriptor(), epochs)?.descriptor;
    let prefix = if let Some(proof) = checkpoint {
        authority_history::verify_checkpoint(&current, proof)?.prefix()
    } else {
        current.genesis()?
    };
    recovery::Predecessor::new(&checked, &prefix)
}
