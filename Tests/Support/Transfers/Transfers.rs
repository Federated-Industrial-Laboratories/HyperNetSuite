// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Transport {
    #[cfg(test)]
    pub(crate) fn socket(path: PathBuf) -> Self {
        Self {
            service_socket: Some(path),
            service_directory: None,
            core: PathBuf::new(),
        }
    }
}
