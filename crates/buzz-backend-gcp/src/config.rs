//! `provider_config` schema, parsing, and the two closed value grammars
//! (spec §`provider_config` v1 fields, §Value grammars for the drop-in fields).
//!
//! Every field here is non-secret by construction: I2 forbids a provider from
//! accepting credentials through config, and the desktop independently rejects
//! any key that looks like one
//! (`desktop/src-tauri/src/managed_agents/backend.rs:536-566`).

use serde_json::json;

pub const DEFAULT_PROJECT: &str = "zoop-innovation";
pub const DEFAULT_ZONE: &str = "asia-south1-a";
pub const DEFAULT_INSTANCE: &str = "buzz-agent";
pub const DEFAULT_MEMORY_MAX: &str = "2G";
pub const DEFAULT_CPU_QUOTA: &str = "150%";
/// Two hours, matching the Kubernetes binding's default.
pub const DEFAULT_INACTIVITY_SECONDS: u64 = 7200;

/// The instance has 2 vCPU, so a quota above this is unenforceable: it is
/// always either a typo or an attempt to probe the parser, and both deserve
/// the same refusal.
#[allow(dead_code)] // Read by parse_cpu_quota, wired into respond's Deploy arm by Task 5.
const MAX_CPU_QUOTA_PERCENT: u32 = 200;

/// The JSON Schema the desktop renders into the "Where to run" form.
pub fn config_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "project": {
                "type": "string", "default": DEFAULT_PROJECT,
                "pattern": "^[a-z][a-z0-9-]{0,61}[a-z0-9]$",
                "description": "GCP project containing the instance"
            },
            "zone": {
                "type": "string", "default": DEFAULT_ZONE,
                "pattern": "^[a-z][a-z0-9-]{0,61}[a-z0-9]$",
                "description": "Compute zone of the instance"
            },
            "instance": {
                "type": "string", "default": DEFAULT_INSTANCE,
                "pattern": "^[a-z][a-z0-9-]{0,61}[a-z0-9]$",
                "description": "Instance the agent runs on"
            },
            "memory_max": {
                "type": "string", "default": DEFAULT_MEMORY_MAX,
                "pattern": r"^[0-9]{1,6}(\.[0-9]{1,3})?[KMGT]?$",
                "description": "systemd MemoryMax for this agent, e.g. 512M, 2G, 1.5G"
            },
            "cpu_quota": {
                "type": "string", "default": DEFAULT_CPU_QUOTA,
                "pattern": "^[0-9]{1,3}%$",
                "description":
                    "systemd CPUQuota for this agent, 1% to 200% (the instance has 2 vCPU)"
            },
            "inactivity_seconds": {
                "type": "integer", "minimum": 0,
                "default": DEFAULT_INACTIVITY_SECONDS,
                "description":
                    "Exit after this many seconds with no dispatched events. 0 means no bound."
            }
        },
        "required": ["project", "zone", "instance"],
        "additionalProperties": false
    })
}

/// Parsed, defaulted, validated provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Constructed by ProviderConfig::parse, wired into respond's Deploy arm by Task 5.
pub struct ProviderConfig {
    pub project: String,
    pub zone: String,
    pub instance: String,
    /// The validated `MemoryMax` spelling, written verbatim into the drop-in.
    pub memory_max: String,
    /// `memory_max` resolved to bytes, for the capacity arithmetic.
    pub memory_max_bytes: u64,
    /// The validated `CPUQuota` spelling, written verbatim into the drop-in.
    pub cpu_quota: String,
    /// `None` encodes the indefinite opt-in (`inactivity_seconds: 0`).
    pub inactivity_seconds: Option<u64>,
}

/// Refuse any string value carrying CR, LF, or NUL.
///
/// A belt for the next field added to the schema: `memory_max` and
/// `cpu_quota` have closed grammars that already exclude these, but a field
/// added later would not, and this class of defect must not be able to recur
/// by omission. The refusal names the field and the character class and
/// **never echoes the value** — an attacker-supplied value could itself be
/// secret material, which `docs/remote-agents.md:1477-1478` forbids emitting.
#[allow(dead_code)] // Called by ProviderConfig::parse, wired into respond's Deploy arm by Task 5.
fn reject_control_characters(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    for (key, value) in fields {
        let Some(text) = value.as_str() else { continue };
        let Some(bad) = text.chars().find(|c| matches!(c, '\r' | '\n' | '\0')) else {
            continue;
        };
        let class = match bad {
            '\r' => "a carriage return",
            '\n' => "a newline",
            _ => "a NUL byte",
        };
        return Err(format!(
            "provider_config.{key} contains {class}. This binding writes \
             configuration into a root-installed systemd drop-in, where a line \
             break becomes an additional unit directive, so such a value is \
             refused rather than sanitized. The value is not echoed."
        ));
    }
    Ok(())
}

/// Parse `memory_max` against its closed grammar and resolve it to bytes.
///
/// `^[0-9]{1,6}(\.[0-9]{1,3})?[KMGT]?$`, suffix case-**sensitive**, result
/// required `> 0`. Lowercase suffixes are refused rather than folded: systemd
/// reads a bare number as bytes, so quietly accepting `512m` would hand the
/// operator 512 bytes when they asked for 512 mebibytes.
#[allow(dead_code)] // Called by ProviderConfig::parse, wired into respond's Deploy arm by Task 5.
pub fn parse_memory_max(value: &str) -> Result<u64, String> {
    let refuse = || {
        "provider_config.memory_max is not a size this binding accepts \
         (one to six digits, an optional '.' and up to three more digits, and \
         an optional uppercase K, M, G or T — for example 512M, 2G or 1.5G — \
         resolving to more than zero bytes). It is refused rather than \
         sanitized because it is interpolated into a root-installed systemd \
         drop-in. The value is not echoed."
            .to_string()
    };

    // `chars().last()`, not `as_bytes().last()`: on a value ending in a
    // multi-byte character the byte form matches `Some(_)` and the byte slice
    // below would split a code point and panic. Every accepted suffix is one
    // ASCII byte, so `len() - 1` is only reached where it is sound.
    let (digits, unit) = match value.chars().last() {
        Some('K') => (&value[..value.len() - 1], 1024_u64),
        Some('M') => (&value[..value.len() - 1], 1024_u64 * 1024),
        Some('G') => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024),
        Some('T') => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024 * 1024),
        Some(_) => (value, 1_u64),
        None => return Err(refuse()),
    };

    let (whole_text, frac_text) = match digits.split_once('.') {
        // A trailing '.' with no fraction is not in the grammar.
        Some((_, "")) => return Err(refuse()),
        Some((whole, frac)) => (whole, frac),
        None => (digits, ""),
    };
    if whole_text.is_empty()
        || whole_text.len() > 6
        || !whole_text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(refuse());
    }
    if !frac_text.is_empty()
        && (frac_text.len() > 3 || !frac_text.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(refuse());
    }

    // Bounds make this arithmetic total: whole <= 999_999 and unit <= 2^40, so
    // whole * unit <= 1.1e18 < u64::MAX; frac <= 999, so frac * unit <= 1.1e15.
    // Integer throughout — no float rounding to reason about.
    let whole: u64 = whole_text.parse().map_err(|_| refuse())?;
    let mut bytes = whole * unit;
    if !frac_text.is_empty() {
        let frac: u64 = frac_text.parse().map_err(|_| refuse())?;
        bytes += frac * unit / 10_u64.pow(frac_text.len() as u32);
    }
    if bytes == 0 {
        return Err(refuse());
    }
    Ok(bytes)
}

/// Parse `cpu_quota` against its closed grammar: `^[0-9]{1,3}%$`, with the
/// integer in `1..=MAX_CPU_QUOTA_PERCENT`.
#[allow(dead_code)] // Called by ProviderConfig::parse, wired into respond's Deploy arm by Task 5.
pub fn parse_cpu_quota(value: &str) -> Result<u32, String> {
    let refuse = || {
        format!(
            "provider_config.cpu_quota is not a percentage this binding accepts \
             (one to three digits followed by '%', from 1% to \
             {MAX_CPU_QUOTA_PERCENT}% — the instance has 2 vCPU, so a higher \
             quota is unenforceable). It is refused rather than sanitized \
             because it is interpolated into a root-installed systemd drop-in. \
             The value is not echoed."
        )
    };
    let Some(digits) = value.strip_suffix('%') else {
        return Err(refuse());
    };
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refuse());
    }
    let percent: u32 = digits.parse().map_err(|_| refuse())?;
    if percent == 0 || percent > MAX_CPU_QUOTA_PERCENT {
        return Err(refuse());
    }
    Ok(percent)
}

/// The longest resource name this binding will interpolate. 63 is the RFC 1035
/// label limit GCE enforces on instance names, and the tightest of the three.
#[allow(dead_code)] // Read by parse_resource_name, wired into respond's Deploy arm by Task 5.
const MAX_RESOURCE_NAME_LEN: usize = 63;

/// Parse `project`, `zone` or `instance` against a closed grammar:
/// `^[a-z][a-z0-9-]{0,61}[a-z0-9]$`.
///
/// `project` is not decoration. It is interpolated into
/// `Environment=BUZZ_GCP_PROJECT=<value>` inside a **root-installed** drop-in
/// on the one unit deliberately allowed to reach the metadata server and Secret
/// Manager. systemd's `Environment=` is whitespace- and quote-parsed and
/// expands `%` specifiers, so a value carrying a space, a quote, an `=` or a
/// `%` appends a second assignment to that unit's environment —
/// `BUZZ_GCP_SECRET`, `CLOUDSDK_CONFIG`, `HTTPS_PROXY`. `zone` and `instance`
/// reach `gcloud` argv rather than a unit file, a weaker exposure, but they are
/// the same class of caller-supplied name and get the same rule rather than a
/// second one somebody has to remember.
///
/// The grammar is the intersection of what GCE and Secret Manager accept for
/// project ids, zones and instance names, so nothing legitimate is excluded.
/// Byte-wise throughout, so a multi-byte character fails the character-class
/// check rather than splitting a code point.
#[allow(dead_code)] // Called by ProviderConfig::parse, wired into respond's Deploy arm by Task 5.
pub fn parse_resource_name(field: &str, value: &str) -> Result<(), String> {
    let refuse = || {
        format!(
            "provider_config.{field} is not a name this binding accepts (2 to \
             {MAX_RESOURCE_NAME_LEN} characters: a lowercase letter, then \
             lowercase letters, digits or '-', ending in a lowercase letter or \
             digit — for example zoop-innovation, asia-south1-a, buzz-agent). \
             It is refused rather than sanitized because it is interpolated \
             into a root-installed systemd drop-in, where a space, a quote, an \
             '=' or a '%' becomes a second unit directive. The value is not \
             echoed."
        )
    };
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.len() > MAX_RESOURCE_NAME_LEN {
        return Err(refuse());
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(refuse());
    }
    let last = bytes[bytes.len() - 1];
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return Err(refuse());
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(refuse());
    }
    Ok(())
}

impl ProviderConfig {
    /// Parse with defaults.
    ///
    /// An absent or null object is not an error: the desktop sends one when
    /// the user accepted every schema default. Keys this binding does not know
    /// are ignored rather than refused — the desktop does not validate
    /// `provider_config` against `config_schema`, and the same agent record is
    /// redeployable across bindings, so a Kubernetes key must not brick a GCE
    /// deploy. A key this binding *does* know always has its value validated.
    #[allow(dead_code)] // Wired into respond's Deploy arm by Task 5; only this module's tests call it today.
    pub fn parse(value: &serde_json::Value) -> Result<Self, String> {
        let empty = serde_json::Map::new();
        let fields = match value {
            serde_json::Value::Null => &empty,
            serde_json::Value::Object(map) => map,
            _ => return Err("provider_config must be a JSON object".to_string()),
        };

        // Before any trimming: `str::trim` strips a trailing newline, so a
        // scan placed after it would accept `"2G\n"`.
        reject_control_characters(fields)?;

        let text = |key: &str, default: &str| -> String {
            fields
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .unwrap_or(default)
                .to_string()
        };

        let inactivity_seconds = match fields.get("inactivity_seconds") {
            None | Some(serde_json::Value::Null) => Some(DEFAULT_INACTIVITY_SECONDS),
            Some(value) => {
                let seconds = value.as_u64().ok_or_else(|| {
                    "provider_config.inactivity_seconds must be a non-negative integer".to_string()
                })?;
                // 0 is the blessed indefinite opt-in and must parse; the
                // refusal for it lives in `render::plan`, with a message
                // naming the prerequisite.
                (seconds > 0).then_some(seconds)
            }
        };

        let project = text("project", DEFAULT_PROJECT);
        parse_resource_name("project", &project)?;
        let zone = text("zone", DEFAULT_ZONE);
        parse_resource_name("zone", &zone)?;
        let instance = text("instance", DEFAULT_INSTANCE);
        parse_resource_name("instance", &instance)?;

        let memory_max = text("memory_max", DEFAULT_MEMORY_MAX);
        let memory_max_bytes = parse_memory_max(&memory_max)?;
        let cpu_quota = text("cpu_quota", DEFAULT_CPU_QUOTA);
        parse_cpu_quota(&cpu_quota)?;

        Ok(Self {
            project,
            zone,
            instance,
            memory_max,
            memory_max_bytes,
            cpu_quota,
            inactivity_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_config_takes_every_default() {
        let c = ProviderConfig::parse(&json!({})).unwrap();
        assert_eq!(c.project, DEFAULT_PROJECT);
        assert_eq!(c.zone, DEFAULT_ZONE);
        assert_eq!(c.instance, DEFAULT_INSTANCE);
        assert_eq!(c.memory_max, DEFAULT_MEMORY_MAX);
        assert_eq!(c.memory_max_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(c.cpu_quota, DEFAULT_CPU_QUOTA);
        assert_eq!(c.inactivity_seconds, Some(DEFAULT_INACTIVITY_SECONDS));
    }

    /// A null `provider_config` is what the desktop sends when the user
    /// accepted every default; it must not be a parse error.
    #[test]
    fn a_null_config_is_an_empty_config() {
        assert_eq!(
            ProviderConfig::parse(&serde_json::Value::Null).unwrap(),
            ProviderConfig::parse(&json!({})).unwrap()
        );
    }

    /// `inactivity_seconds: 0` is the blessed indefinite opt-in and MUST parse
    /// (spec §`provider_config` v1 fields). Whether this binding can *honor*
    /// it is a separate question, answered by `render::plan`.
    #[test]
    fn zero_inactivity_parses_as_the_indefinite_opt_in() {
        let c = ProviderConfig::parse(&json!({"inactivity_seconds": 0})).unwrap();
        assert_eq!(c.inactivity_seconds, None);
    }

    #[test]
    fn a_non_integer_inactivity_is_refused() {
        assert!(ProviderConfig::parse(&json!({"inactivity_seconds": "soon"})).is_err());
        assert!(ProviderConfig::parse(&json!({"inactivity_seconds": -5})).is_err());
    }

    #[test]
    fn memory_sizes_resolve_to_bytes() {
        assert_eq!(parse_memory_max("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory_max("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory_max("1.5G").unwrap(), 1_610_612_736);
        assert_eq!(parse_memory_max("1024").unwrap(), 1024);
        assert_eq!(parse_memory_max("4K").unwrap(), 4096);
    }

    #[test]
    fn memory_sizes_outside_the_grammar_are_refused() {
        for bad in [
            "infinity", "", "2 G", "-1", "0", "1e9", "2GB", "2g", "2.", ".5G", "2.5555G",
            "1234567", "G", "2G ", "0K",
        ] {
            assert!(
                parse_memory_max(bad).is_err(),
                "accepted out-of-grammar memory_max {bad:?}"
            );
        }
    }

    #[test]
    fn cpu_quotas_inside_the_bound_parse() {
        assert_eq!(parse_cpu_quota("150%").unwrap(), 150);
        assert_eq!(parse_cpu_quota("1%").unwrap(), 1);
        assert_eq!(parse_cpu_quota("200%").unwrap(), 200);
    }

    #[test]
    fn cpu_quotas_outside_the_bound_are_refused() {
        // 200% is the ceiling because the instance has 2 vCPU: anything above
        // is unenforceable, so it is either a typo or a parser probe.
        for bad in [
            "150", "150%%", "0%", "201%", "400%", "%", "", " 150%", "1.5%",
        ] {
            assert!(
                parse_cpu_quota(bad).is_err(),
                "accepted out-of-grammar cpu_quota {bad:?}"
            );
        }
    }

    /// The named injection payloads from design §Testing. Each must be a
    /// refusal, and the refusal must not echo the value.
    #[test]
    fn systemd_injection_payloads_are_refused_without_echoing_them() {
        let cases = [
            ("memory_max", "2G\nExecStart=/bin/sh -c id"),
            ("cpu_quota", "150%\nEnvironmentFile=/tmp/x"),
            ("memory_max", "2G\rMemoryMax=1K"),
            ("cpu_quota", "150%\u{0}"),
            ("project", "zoop-innovation\nExecStart=/bin/sh"),
        ];
        for (field, payload) in cases {
            let err = ProviderConfig::parse(&json!({ field: payload }))
                .expect_err("an embedded control character must be refused");
            assert!(
                err.contains(field),
                "{field}: the refusal must name the field: {err}"
            );
            assert!(
                !err.contains("ExecStart")
                    && !err.contains("EnvironmentFile")
                    && !err.contains("MemoryMax=1K"),
                "{field}: the refusal echoed the value, which L2 item 5 forbids: {err}"
            );
        }
    }

    #[test]
    fn resource_names_inside_the_grammar_parse() {
        let c = ProviderConfig::parse(&json!({
            "project": "zoop-innovation",
            "zone": "asia-south1-a",
            "instance": "buzz-agent"
        }))
        .unwrap();
        assert_eq!(c.project, "zoop-innovation");
        assert_eq!(c.zone, "asia-south1-a");
        assert_eq!(c.instance, "buzz-agent");
    }

    /// P1-3: `project` is interpolated into `Environment=BUZZ_GCP_PROJECT=…`
    /// in a **root-installed** drop-in on the one unit allowed to reach the
    /// metadata server. systemd's `Environment=` is whitespace- and
    /// quote-parsed and expands `%` specifiers, so anything outside the closed
    /// grammar can append a second assignment. `zone` and `instance` get the
    /// same grammar rather than a second, weaker rule.
    #[test]
    fn resource_names_that_could_inject_a_systemd_directive_are_refused() {
        let cases = [
            // A second assignment on the same Environment= line.
            ("project", "zoop BUZZ_GCP_SECRET=evil"),
            ("project", "zoop CLOUDSDK_CONFIG=/tmp/x"),
            // systemd unquotes Environment= values, so quotes are structural.
            ("project", "\"zoop\""),
            ("project", "zoop'q"),
            // `%` is a specifier prefix, expanded before the value is used.
            ("project", "%i"),
            ("project", "zoop%n"),
            // Shape rules, so a typo is a refusal rather than a lookup failure
            // against a project that happens to exist.
            ("project", "-leading-hyphen"),
            ("project", "trailing-hyphen-"),
            ("project", "UPPERCASE"),
            ("project", "under_score"),
            ("project", "dot.separated"),
            ("project", "sl/ash"),
            ("zone", "asia-south1-a EnvironmentFile=/tmp/x"),
            ("instance", "buzz agent"),
            ("instance", "../../etc/passwd"),
        ];
        for (field, payload) in cases {
            let err = ProviderConfig::parse(&json!({ field: payload }))
                .err()
                .unwrap_or_else(|| panic!("accepted out-of-grammar {field} {payload:?}"));
            assert!(
                err.contains(field),
                "{field}: the refusal must name the field: {err}"
            );
            assert!(
                !err.contains(payload),
                "{field}: the refusal echoed the value, which L2 item 5 forbids: {err}"
            );
        }
    }

    /// Both length bounds, kept out of the refusal test above because a
    /// one-character payload appears in any English sentence and would trip
    /// that test's does-not-echo assertion for the wrong reason. 64 is one over
    /// the RFC 1035 label limit GCE enforces on instance names.
    #[test]
    fn resource_name_length_bounds_are_enforced() {
        assert!(parse_resource_name("project", "a").is_err());
        assert!(parse_resource_name("project", "").is_err());
        assert!(parse_resource_name("project", "ab").is_ok());
        assert!(parse_resource_name("project", &"a".repeat(63)).is_ok());
        assert!(parse_resource_name("project", &"a".repeat(64)).is_err());
    }

    /// The control-character scan runs before trimming for **every** string
    /// field, not only the two with closed size grammars — and neither refusal
    /// echoes the value.
    #[test]
    fn a_resource_name_carrying_a_control_character_is_refused_not_trimmed() {
        for payload in [
            "zoop-innovation\n",
            "zoop-innovation\r",
            "zoop-innovation\u{0}",
        ] {
            let err = ProviderConfig::parse(&json!({"project": payload}))
                .expect_err("a control character must be refused, never trimmed away");
            assert!(err.contains("project"), "{err}");
            assert!(
                !err.contains("zoop-innovation"),
                "the refusal echoed the value: {err}"
            );
        }
    }

    /// The control-character scan must run **before** trimming. `str::trim`
    /// removes a trailing newline, so a scan placed after it would accept
    /// `"2G\n"` — and teach the next reviewer that trimming is a defense.
    #[test]
    fn a_trailing_newline_is_refused_not_trimmed_away() {
        let err = ProviderConfig::parse(&json!({"memory_max": " 2G\n"}))
            .expect_err("trim must not sanitize a control character away");
        assert!(err.contains("memory_max"), "{err}");
    }

    /// Padding with ordinary spaces is still accepted, and the trimmed form is
    /// what gets written — validator and writer must never disagree.
    #[test]
    fn ordinary_padding_is_trimmed_and_accepted() {
        let c = ProviderConfig::parse(&json!({"memory_max": "  512M  "})).unwrap();
        assert_eq!(c.memory_max, "512M");
        assert_eq!(c.memory_max_bytes, 512 * 1024 * 1024);
    }

    /// A key belonging to another binding must not be a hard refusal: the
    /// desktop does not validate `provider_config` against `config_schema`
    /// (backend.rs:536-566 checks shape and key names only), and the same
    /// agent record is redeployable across bindings.
    #[test]
    fn a_foreign_binding_key_is_ignored_not_refused() {
        let c = ProviderConfig::parse(&json!({
            "namespace": "buzz-agents-test",
            "image": "ghcr.io/block/buzz-sprig@sha256:aa",
            "memory_max": "512M"
        }))
        .unwrap();
        assert_eq!(c.memory_max, "512M");
        assert_eq!(c.instance, DEFAULT_INSTANCE);
    }

    #[test]
    fn a_non_object_config_is_refused() {
        assert!(ProviderConfig::parse(&json!("2G")).is_err());
        assert!(ProviderConfig::parse(&json!([1, 2])).is_err());
    }
}
