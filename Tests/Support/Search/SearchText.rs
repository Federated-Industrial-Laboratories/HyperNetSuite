// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
fn identifier(value: &V) -> Result<Digest> {
    let value = value.fixed()?;
    ensure!(value != [0; 32], "zero search identifier");
    Ok(value)
}

#[cfg(test)]
pub fn response(request: &Request, source: &[u8]) -> Result<Vec<u8>> {
    let found = matching(request, source)?;
    wire::encode(&V::Array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("PageSearchResult".into()),
        bytes(&request.digest()?),
        V::Bytes(source.to_vec()),
        found.as_ref().map_or(V::Null, Match::value),
    ]))
}

impl Request {
    #[cfg(test)]
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAXIMUM_REQUEST,
            "search request exceeds its bound"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(15)?;
        ensure!(
            f[0].uint()? == 119 && f[1].uint()? == 1 && f[4].uint()? == 0,
            "search request format differs"
        );
        f[5].null()?;
        let out = Self {
            network: identifier(&f[2])?,
            incarnation: identifier(&f[3])?,
            operation: identifier(&f[6])?,
            scope: f[7].uint()?,
            terms: f[8]
                .list(16)?
                .iter()
                .map(|v| Ok(v.text()?.to_owned()))
                .collect::<Result<_>>()?,
            combination: f[9].uint()?,
            namespaces: f[10]
                .list(64)?
                .iter()
                .map(identifier)
                .collect::<Result<_>>()?,
            limit: usize::try_from(f[11].uint()?)?,
            cursor: if f[12] == V::Null {
                None
            } else {
                Some(identifier(&f[12])?)
            },
            historical: match f[13].uint()? {
                0 => false,
                1 => true,
                _ => anyhow::bail!("invalid retained search view"),
            },
            snapshot: f[14].clone(),
        };
        out.validate()?;
        Ok(out)
    }
}
