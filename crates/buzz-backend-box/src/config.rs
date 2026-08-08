//! `provider_config` parsing and the `info` JSON Schema for ASCII Box.

use crate::image::{self, ImageRef};

/// Default Box machine size.
pub const DEFAULT_MACHINE_TYPE: &str = "small";
/// Default inactivity timeout in seconds.
pub const DEFAULT_INACTIVITY_SECONDS: u64 = 7200;
/// Default non-secret deployment scope.
pub const DEFAULT_SCOPE: &str = "default";
/// Default workspace behavior.
pub const DEFAULT_WORKSPACE_MODE: &str = "persistent";
/// Catalog image prefilled by the provider's `info` schema.
pub const DEFAULT_IMAGE: &str = "ghcr.io/block/buzz-sprig:sha-6530b58@sha256:17facfc7608d8ddb33bc056c9aaba1098f4ef6abe5655702fbfd7584d1f74d76";

/// Supported Box machine sizes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MachineType {
    /// Smallest supported machine.
    #[default]
    Small,
    /// Box's default machine size.
    Default,
    /// Larger machine for heavier workloads.
    Large,
}

impl MachineType {
    /// Return the wire/schema spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Default => "default",
            Self::Large => "large",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "small" => Ok(Self::Small),
            "default" => Ok(Self::Default),
            "large" => Ok(Self::Large),
            _ => Err(format!(
                "provider_config.machine_type must be one of small, default, or large, got {value:?}"
            )),
        }
    }
}

/// Controls whether the Box workspace is retained across restarts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WorkspaceMode {
    /// Keep the Box workspace persistent.
    #[default]
    Persistent,
    /// Use a fresh workspace for a new Box.
    Fresh,
}

impl WorkspaceMode {
    /// Return the wire/schema spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::Fresh => "fresh",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "persistent" => Ok(Self::Persistent),
            "fresh" => Ok(Self::Fresh),
            _ => Err(format!(
                "provider_config.workspace_mode must be one of persistent or fresh, got {value:?}"
            )),
        }
    }
}

/// Validated Box provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    /// Box machine size.
    pub machine_type: MachineType,
    /// Canonical immutable Buzz runtime image.
    pub image: ImageRef,
    /// Inactivity timeout, always at least 60 seconds.
    pub inactivity_seconds: u64,
    /// Non-secret deployment namespace used in deterministic naming.
    pub scope: String,
    /// Workspace persistence policy.
    pub workspace_mode: WorkspaceMode,
}

const ALLOWED_FIELDS: [&str; 5] = [
    "machine_type",
    "image",
    "inactivity_seconds",
    "scope",
    "workspace_mode",
];

fn object(
    cfg: &serde_json::Value,
) -> Result<Option<&serde_json::Map<String, serde_json::Value>>, String> {
    match cfg {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Object(value) => Ok(Some(value)),
        _ => Err("provider_config must be a JSON object".to_string()),
    }
}

fn optional_string(
    cfg: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<String>, String> {
    match cfg.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.trim().to_string())),
        Some(other) => Err(format!(
            "provider_config.{field} must be a string, got {other}"
        )),
    }
}

fn optional_u64(
    cfg: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    match cfg.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            format!("provider_config.{field} must be a non-negative integer, got {value}")
        }),
        Some(other) => Err(format!(
            "provider_config.{field} must be a non-negative integer, got {other}"
        )),
    }
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 64
        && scope.starts_with(|character: char| {
            character.is_ascii_lowercase() || character.is_ascii_digit()
        })
        && scope.ends_with(|character: char| {
            character.is_ascii_lowercase() || character.is_ascii_digit()
        })
        && !scope.contains("--")
        && scope.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// Parse and validate provider configuration, rejecting unknown fields.
pub fn parse(cfg: &serde_json::Value) -> Result<ProviderConfig, String> {
    let Some(object) = object(cfg)? else {
        return Ok(ProviderConfig {
            machine_type: MachineType::default(),
            image: image::parse(DEFAULT_IMAGE)?,
            inactivity_seconds: DEFAULT_INACTIVITY_SECONDS,
            scope: DEFAULT_SCOPE.to_string(),
            workspace_mode: WorkspaceMode::default(),
        });
    };

    for field in object.keys() {
        if !ALLOWED_FIELDS.contains(&field.as_str()) {
            return Err(format!("provider_config contains unknown field {field:?}"));
        }
    }

    let machine_type = optional_string(object, "machine_type")?
        .map(|value| MachineType::parse(&value))
        .transpose()?
        .unwrap_or_default();
    let image = match optional_string(object, "image")? {
        Some(value) => image::parse(&value)?,
        None => image::parse(DEFAULT_IMAGE)?,
    };
    let inactivity_seconds =
        optional_u64(object, "inactivity_seconds")?.unwrap_or(DEFAULT_INACTIVITY_SECONDS);
    if inactivity_seconds < 60 {
        return Err(
            "provider_config.inactivity_seconds must be at least 60 seconds; 0 is not supported"
                .to_string(),
        );
    }
    let scope = optional_string(object, "scope")?.unwrap_or_else(|| DEFAULT_SCOPE.to_string());
    if !valid_scope(&scope) {
        return Err(format!(
            "provider_config.scope {scope:?} must be 1-64 lowercase letters, digits, or single hyphens"
        ));
    }
    let workspace_mode = optional_string(object, "workspace_mode")?
        .map(|value| WorkspaceMode::parse(&value))
        .transpose()?
        .unwrap_or_default();

    Ok(ProviderConfig {
        machine_type,
        image,
        inactivity_seconds,
        scope,
        workspace_mode,
    })
}

/// Return the non-secret JSON Schema exposed by the `info` operation.
pub fn config_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "machine_type": {
                "type": "string",
                "enum": ["small", "default", "large"],
                "default": DEFAULT_MACHINE_TYPE,
                "title": "Machine type"
            },
            "image": {
                "type": "string",
                "default": DEFAULT_IMAGE,
                "pattern": "^[^@\\s]+@sha256:[0-9a-f]{64}$",
                "title": "Immutable agent image"
            },
            "inactivity_seconds": {
                "type": "integer",
                "minimum": 60,
                "default": DEFAULT_INACTIVITY_SECONDS,
                "title": "Stop after inactivity (seconds)"
            },
            "scope": {
                "type": "string",
                "default": DEFAULT_SCOPE,
                "pattern": "^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$",
                "title": "Deployment scope"
            },
            "workspace_mode": {
                "type": "string",
                "enum": ["persistent", "fresh"],
                "default": DEFAULT_WORKSPACE_MODE,
                "title": "Workspace mode"
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "a".repeat(64)
    }

    #[test]
    fn applies_all_defaults() {
        let config = parse(&serde_json::json!({})).expect("empty config uses defaults");
        assert_eq!(config.machine_type, MachineType::Small);
        assert_eq!(
            config.image.as_str(),
            DEFAULT_IMAGE.replace(":sha-6530b58", "")
        );
        assert_eq!(config.inactivity_seconds, DEFAULT_INACTIVITY_SECONDS);
        assert_eq!(config.scope, DEFAULT_SCOPE);
        assert_eq!(config.workspace_mode, WorkspaceMode::Persistent);
    }

    #[test]
    fn accepts_all_supported_values() {
        let config = parse(&serde_json::json!({
            "machine_type": "large",
            "image": format!("ghcr.io/block/buzz-sprig@sha256:{}", digest()),
            "inactivity_seconds": 60,
            "scope": "production-1",
            "workspace_mode": "fresh"
        }))
        .expect("valid config should parse");
        assert_eq!(config.machine_type, MachineType::Large);
        assert_eq!(config.inactivity_seconds, 60);
        assert_eq!(config.scope, "production-1");
        assert_eq!(config.workspace_mode, WorkspaceMode::Fresh);
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = parse(&serde_json::json!({"api_key": "secret"})).unwrap_err();
        assert!(error.contains("unknown field"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_inactivity_below_minimum() {
        for value in [0, 59] {
            let error = parse(&serde_json::json!({"inactivity_seconds": value})).unwrap_err();
            assert!(error.contains("at least 60"), "unexpected error: {error}");
        }
    }

    #[test]
    fn rejects_non_integer_inactivity() {
        for value in [
            serde_json::json!(-1),
            serde_json::json!(60.5),
            serde_json::json!("60"),
        ] {
            assert!(parse(&serde_json::json!({"inactivity_seconds": value})).is_err());
        }
    }

    #[test]
    fn rejects_invalid_image_references() {
        for image in [
            "ghcr.io/block/buzz-sprig:latest",
            "ghcr.io/block/buzz-sprig@sha256:abc",
            "ghcr.io/block/buzz-sprig@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(parse(&serde_json::json!({"image": image})).is_err());
        }
    }

    #[test]
    fn rejects_invalid_scope_and_modes() {
        for scope in [
            "",
            "Upper",
            "-leading",
            "trailing-",
            "double--hyphen",
            "has_underscore",
        ] {
            assert!(parse(&serde_json::json!({"scope": scope})).is_err());
        }
        assert!(parse(&serde_json::json!({"machine_type": "medium"})).is_err());
        assert!(parse(&serde_json::json!({"workspace_mode": "temporary"})).is_err());
    }

    #[test]
    fn schema_is_closed_and_matches_parser_defaults() {
        let schema = config_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["machine_type"]["default"], "small");
        assert_eq!(schema["properties"]["inactivity_seconds"]["minimum"], 60);
        assert_eq!(schema["properties"]["scope"]["default"], "default");
        assert_eq!(
            schema["properties"]["workspace_mode"]["default"],
            "persistent"
        );
    }
}
