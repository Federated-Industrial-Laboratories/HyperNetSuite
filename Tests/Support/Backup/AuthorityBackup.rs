// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Profile {
    #[cfg(test)]
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("BackupDestination".into()),
            b(&self.manifest.encode()?),
            b(&self.id),
            V::Text(self.name.clone()),
            b(&self.volume),
            V::Uint(self.bytes),
            V::Uint(self.objects),
            V::Uint(self.retention_ms),
            a(self.recipients.iter().map(|k| b(k)).collect()),
            a(self.owners.iter().map(|k| b(k)).collect()),
            V::Bool(self.opaque),
        ]))
    }
}
