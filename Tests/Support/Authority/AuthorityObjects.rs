// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
/// Evaluation dependencies may only come from the signed operation and exact prior state.
#[cfg(test)]
pub fn validate_required(
    required: &[Reference],
    command: &[Reference],
    retained: &[Reference],
) -> Result<()> {
    validate_references(required)?;
    validate_references(command)?;
    validate_references(retained)?;
    ensure!(
        required
            .iter()
            .all(|r| command.binary_search(r).is_ok() || retained.binary_search(r).is_ok()),
        "evaluation requested an input outside its command and prior state"
    );
    Ok(())
}

/// The accepted terminal state independently determines this complete export index.
#[derive(Clone, Debug)]
#[cfg(test)]
pub struct EpochIndex {
    state: Digest,
    references: Vec<Reference>,
}

#[cfg(test)]
impl EpochIndex {
    pub fn new(state: &[u8], references: &[Reference]) -> Result<Self> {
        validate_references(references)?;
        wire::decode_state(state)?;
        let index = Self {
            state: wire::digest(state),
            references: references.to_vec(),
        };
        index.canonical()?;
        Ok(index)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = wire::decode_state(bytes)?;
        let fields = value.array(4)?;
        ensure!(
            fields[0].text()? == "HyperNetEpochObjects" && fields[1].uint()? == 1,
            "invalid epoch object index"
        );
        let references = fields[3]
            .list(4096)?
            .iter()
            .map(Reference::parse)
            .collect::<Result<Vec<_>>>()?;
        validate_references(&references)?;
        Ok(Self {
            state: fields[2].fixed()?,
            references,
        })
    }
    pub fn canonical(&self) -> Result<Vec<u8>> {
        wire::encode_state(&V::Array(vec![
            V::Text("HyperNetEpochObjects".into()),
            V::Uint(1),
            V::Bytes(self.state.to_vec()),
            V::Array(self.references.iter().map(Reference::value).collect()),
        ]))
    }
    pub fn verify(&self, terminal_state: &[u8], required: &[Reference]) -> Result<()> {
        validate_references(required)?;
        ensure!(
            self.state == wire::digest(terminal_state) && self.references == required,
            "epoch object index differs from the complete accepted terminal state"
        );
        Ok(())
    }
    pub fn references(&self) -> &[Reference] {
        &self.references
    }
}

impl Resolved {
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}
