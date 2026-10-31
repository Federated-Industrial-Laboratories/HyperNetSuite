// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn build(
    document: &Document,
    columns: usize,
    offsets: &BTreeMap<usize, usize>,
    ascii: bool,
) -> Result<Layout> {
    build_with_values(document, columns, offsets, ascii, &BTreeMap::new())
}
