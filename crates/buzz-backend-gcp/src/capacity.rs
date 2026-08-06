//! Memory headroom arithmetic and the durable deploy trail (spec §Capacity).
//!
//! Overcommit is a **warning, not a refusal**: the operator asked for the risk
//! to be reported, not vetoed, and a provider that vetoes a deploy the
//! operator understands is a provider they will work around. The hard part is
//! not computing the warning; it is putting it somewhere the operator will
//! actually see it — see `reconcile`, which writes it, and `operator::list`,
//! which reads it back.

/// One gibibyte, the unit the warning quotes and the instance is sized in.
pub const GIB: u64 = 1024 * 1024 * 1024;

/// Parse a size **systemd itself reported**: always a plain byte count, or the
/// literal `infinity` when no bound is set.
///
/// Deliberately separate from `config::parse_memory_max`, which is the closed
/// grammar for *operator input* and caps at six digits. Different jobs on
/// different data: one guards a root-installed drop-in against injection, the
/// other reads back a ten-digit number systemd printed.
pub fn parse_reported_bytes(value: &str) -> Option<u64> {
    let text = value.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("infinity") {
        return None;
    }
    text.parse().ok()
}

/// Render a byte count the way the warning quotes it.
fn human(bytes: u64) -> String {
    if bytes.is_multiple_of(GIB) {
        format!("{}G", bytes / GIB)
    } else {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    }
}

/// The overcommit warning, or an empty vector when the new agent fits.
///
/// Three lines rather than one: the arithmetic, the consequence, and the
/// remedy. They are appended verbatim to the deploy trail and each is
/// individually greppable, which is what `list` relies on.
#[allow(dead_code)] // Called once reconcile::deploy computes the capacity warning before a create.
pub fn warning_lines(
    available_bytes: u64,
    reserved_bytes: u64,
    unit: &str,
    requested_bytes: u64,
) -> Vec<String> {
    if reserved_bytes.saturating_add(requested_bytes) <= available_bytes {
        return Vec::new();
    }
    vec![
        format!(
            "warning capacity: the instance has {} available; existing units reserve {}.",
            human(available_bytes),
            human(reserved_bytes)
        ),
        format!(
            "warning capacity: adding {unit} ({}) may cause OOM kills.",
            human(requested_bytes)
        ),
        "warning capacity: lower memory_max or resize the instance to e2-standard-4.".to_string(),
    ]
}

/// One deploy-trail record: the deploy line, then one line per warning.
///
/// Carries timestamps, the generation, the create-intent digest, and capacity
/// arithmetic — **never an environment value**. The trail is a 0644 file on a
/// shared host, so treating it as public is the only safe reading.
#[allow(dead_code)] // Called once reconcile::deploy appends a record to the deploy trail.
pub fn trail_record(
    timestamp: &str,
    generation: &str,
    create_intent: &str,
    warnings: &[String],
) -> String {
    // The intent is 64 hex characters; 12 is enough to correlate and short
    // enough to read at a glance. Taken by `chars()` so the function is total
    // for any input, not only the hex its callers happen to pass.
    let short_intent: String = create_intent.chars().take(12).collect();
    let mut record = format!("deploy {timestamp} generation={generation} intent={short_intent}\n");
    for warning in warnings {
        record.push_str(warning);
        record.push('\n');
    }
    record
}

/// The current UTC instant, second precision, as the trail spells it.
#[allow(dead_code)] // Called once reconcile::deploy timestamps a deploy-trail record.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_reported_sizes_parse() {
        assert_eq!(parse_reported_bytes("2147483648"), Some(2 * GIB));
        assert_eq!(parse_reported_bytes("  1024  "), Some(1024));
        // `infinity` is systemd's "no bound", which reserves nothing.
        assert_eq!(parse_reported_bytes("infinity"), None);
        assert_eq!(parse_reported_bytes(""), None);
        assert_eq!(parse_reported_bytes("[not set]"), None);
    }

    #[test]
    fn an_agent_that_fits_produces_no_warning() {
        assert!(warning_lines(2_899_102_924, 0, "buzz-acp@abc.service", 2 * GIB).is_empty());
        // Exactly filling the headroom is not overcommit.
        assert!(warning_lines(2 * GIB, GIB, "buzz-acp@abc.service", GIB).is_empty());
    }

    #[test]
    fn an_overcommit_names_the_numbers_the_unit_and_the_remedy() {
        let w = warning_lines(2_899_102_924, 2 * GIB, "buzz-acp@abc.service", 2 * GIB);
        assert_eq!(w.len(), 3);
        assert!(w.iter().all(|l| l.starts_with("warning capacity: ")));
        assert!(w[0].contains("2.7G available"));
        assert!(w[0].contains("reserve 2G"));
        assert!(w[1].contains("buzz-acp@abc.service"));
        assert!(
            w[2].contains("e2-standard-4"),
            "the warning must name a remedy"
        );
    }

    #[test]
    fn a_trail_record_carries_the_correlators_and_every_warning() {
        let warnings = warning_lines(GIB, GIB, "buzz-acp@abc.service", GIB);
        let record = trail_record(
            "2026-08-05T09:14:02Z",
            "3f9c1a04",
            "8d1e77c2b0a4deadbeef0000000000000000000000000000000000000000cafe",
            &warnings,
        );
        let lines: Vec<&str> = record.lines().collect();
        assert_eq!(
            lines[0],
            "deploy 2026-08-05T09:14:02Z generation=3f9c1a04 intent=8d1e77c2b0a4"
        );
        assert_eq!(lines.len(), 1 + warnings.len());
        assert!(record.ends_with('\n'), "records must append cleanly");
    }

    #[test]
    fn a_clean_deploy_still_leaves_a_record() {
        let record = trail_record("2026-08-05T09:14:02Z", "3f9c1a04", &"a".repeat(64), &[]);
        assert_eq!(record.lines().count(), 1);
    }

    /// The reader greps the trail for lines beginning `warning `
    /// (`operator::listing_script`), so that prefix is a contract between two
    /// modules rather than an incidental spelling. Task 13 Step 1 feeds this
    /// function's real output through the real reader; this asserts the shape
    /// that grep depends on, at the source.
    #[test]
    fn every_warning_line_carries_the_prefix_the_reader_greps_for() {
        let warnings = warning_lines(GIB, GIB, "buzz-acp@abc.service", GIB);
        assert!(!warnings.is_empty(), "this fixture must overcommit");
        let record = trail_record(
            "2026-08-05T09:14:02Z",
            "3f9c1a04",
            &"a".repeat(64),
            &warnings,
        );
        let recorded: Vec<&str> = record.lines().skip(1).collect();
        assert_eq!(recorded.len(), warnings.len(), "one line per warning");
        for line in &recorded {
            assert!(
                line.starts_with("warning "),
                "the reader's grep would drop {line:?}"
            );
        }
    }

    #[test]
    fn the_timestamp_is_second_precision_utc() {
        let now = now_rfc3339();
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(now.len(), 20, "{now}");
    }
}
