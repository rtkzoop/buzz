//! Immutable OCI image reference validation for the Box provider.

/// A validated, digest-qualified image reference in canonical tagless form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef(String);

impl ImageRef {
    /// Return the canonical `name@sha256:<digest>` reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ImageRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Parse and normalize a digest-pinned image reference.
pub fn parse(raw: &str) -> Result<ImageRef, String> {
    let reference = raw.trim();
    if reference.is_empty() {
        return Err(
            "provider_config.image must be a non-empty digest-pinned reference".to_string(),
        );
    }

    let mut parts = reference.split('@');
    let name_and_tag = parts.next().unwrap_or_default();
    let digest = match (parts.next(), parts.next()) {
        (Some(value), None) => value,
        (None, _) => {
            return Err(format!(
                "provider_config.image {reference:?} is not digest-pinned: use name@sha256:<64 hex chars>"
            ));
        }
        (Some(_), Some(_)) => {
            return Err(format!(
                "provider_config.image {reference:?} contains more than one '@'"
            ));
        }
    };

    let digest_hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        format!("provider_config.image digest {digest:?} must start with 'sha256:'")
    })?;
    if digest_hex.len() != 64
        || !digest_hex
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(format!(
            "provider_config.image digest {digest:?} must be exactly 64 lowercase hex characters"
        ));
    }

    let name = match name_and_tag.rfind(':') {
        Some(colon) if !name_and_tag[colon + 1..].contains('/') => &name_and_tag[..colon],
        _ => name_and_tag,
    };
    if name.is_empty() {
        return Err(format!(
            "provider_config.image {reference:?} has no repository name"
        ));
    }

    Ok(ImageRef(format!("{name}@sha256:{digest_hex}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_normalizes_digest_reference() {
        let digest = "a".repeat(64);
        let tagged = parse(&format!("ghcr.io/block/buzz-sprig:v1@sha256:{digest}"))
            .expect("valid image should parse");
        let plain = parse(&format!("ghcr.io/block/buzz-sprig@sha256:{digest}"))
            .expect("valid image should parse");
        assert_eq!(tagged, plain);
    }

    #[test]
    fn rejects_non_immutable_references() {
        for reference in [
            "ghcr.io/block/buzz-sprig:latest",
            "ghcr.io/block/buzz-sprig",
            "image@sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "image@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(parse(reference).is_err(), "accepted {reference:?}");
        }
    }
}
