//! Pure YARA-X logic — no Arrow, no VGI. Everything here works on `&[u8]` data
//! blobs / `&str` rule source and plain Rust types so it can be unit-tested
//! directly. The Arrow adapters in `scalar/` and `table/` call into these.
//!
//! ## Robustness / security (this is a defensive malware-scanning tool)
//!
//! The *scanned data* is UNTRUSTED — by definition it may be live malware. A
//! hostile blob must never crash the worker:
//!
//! * Compilation of the *rule source* is the only thing that errors out (an
//!   invalid rule is a user mistake → a clear DuckDB error). `compile_rules`
//!   returns a [`YaraError`] carrying the compiler's diagnostic.
//! * *Scanning* is total: any scanner error (timeout, internal limit, …) is
//!   mapped to "no matches", never propagated and never a panic. A bad blob
//!   beside a good one still yields the good one's matches.
//! * Input size is bounded ([`MAX_DATA_LEN`]); oversized data is truncated to
//!   the cap before scanning so a giant blob cannot exhaust memory.

use yara_x::{Compiler, Rules, Scanner};

/// A processing error, rendered to a string for the worker to surface to DuckDB.
/// In practice this is only ever a *rule-compilation* error — scanning never
/// errors out (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraError(pub String);

impl std::fmt::Display for YaraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for YaraError {}

type Result<T> = std::result::Result<T, YaraError>;

/// Upper bound on the data we will scan in a single call (64 MiB). Anything
/// larger is truncated to this before scanning so an enormous (possibly
/// adversarial) blob cannot blow up memory. Malware signatures are tiny relative
/// to this, so truncation is safe for the matching use case.
pub const MAX_DATA_LEN: usize = 64 * 1024 * 1024;

/// One matching rule: its identifier, namespace, and tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
}

/// One pattern (string) hit within a matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringMatch {
    /// The rule this hit belongs to.
    pub rule: String,
    /// The pattern identifier, e.g. `$a`.
    pub identifier: String,
    /// Byte offset of the match within the scanned data.
    pub offset: u64,
    /// Matched bytes, rendered for SQL as UTF-8 if printable, else a hex string.
    pub matched: String,
}

/// Compile a YARA rule source string into a reusable [`Rules`]. The ONLY entry
/// point that returns an error: an invalid rule source produces a [`YaraError`]
/// carrying the compiler's diagnostic message (surfaced as a DuckDB error).
pub fn compile_rules(source: &str) -> Result<Rules> {
    let mut compiler = Compiler::new();
    compiler
        .add_source(source)
        .map_err(|e| YaraError(format!("invalid YARA rule: {e}")))?;
    Ok(compiler.build())
}

/// Do the given rules compile? Pure validation — `true` if the source is a valid
/// ruleset, `false` otherwise (never errors, never panics).
pub fn rules_compile(source: &str) -> bool {
    compile_rules(source).is_ok()
}

/// Truncate untrusted data to [`MAX_DATA_LEN`] before handing it to the scanner.
fn bounded(data: &[u8]) -> &[u8] {
    if data.len() > MAX_DATA_LEN {
        &data[..MAX_DATA_LEN]
    } else {
        data
    }
}

/// Render matched bytes for SQL: the UTF-8 text if the bytes are valid,
/// printable UTF-8; otherwise a lowercase hex string (e.g. `deadbeef`). Keeps the
/// output a clean VARCHAR regardless of how binary the matched bytes are.
fn render_matched(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.chars().all(|c| !c.is_control() || c == '\t') => s.to_string(),
        _ => bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// Scan `data` against compiled `rules`, returning every matching rule
/// (identifier, namespace, tags). Total: any scanner error → empty vec.
pub fn scan_rules(rules: &Rules, data: &[u8]) -> Vec<RuleMatch> {
    let mut scanner = Scanner::new(rules);
    let results = match scanner.scan(bounded(data)) {
        Ok(r) => r,
        // Untrusted data: a scan failure (limit/timeout/internal) is treated as
        // "no matches", never propagated.
        Err(_) => return Vec::new(),
    };
    results
        .matching_rules()
        .map(|r| RuleMatch {
            rule: r.identifier().to_string(),
            namespace: r.namespace().to_string(),
            tags: r.tags().map(|t| t.identifier().to_string()).collect(),
        })
        .collect()
}

/// Scan `data` against compiled `rules`, returning one [`StringMatch`] per
/// pattern hit (offset + rendered matched bytes). Total: scanner error → empty.
pub fn scan_strings(rules: &Rules, data: &[u8]) -> Vec<StringMatch> {
    let mut scanner = Scanner::new(rules);
    let results = match scanner.scan(bounded(data)) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for r in results.matching_rules() {
        let rule = r.identifier().to_string();
        for p in r.patterns() {
            let identifier = p.identifier().to_string();
            for m in p.matches() {
                let range = m.range();
                out.push(StringMatch {
                    rule: rule.clone(),
                    identifier: identifier.clone(),
                    offset: range.start as u64,
                    matched: render_matched(m.data()),
                });
            }
        }
    }
    out
}

/// Convenience: compile `source` and scan `data`, returning matching rules.
/// Compilation errors propagate; scanning is total. (Used by the test suites and
/// the path-included integration tests; the worker binary calls the lower-level
/// `compile_rules` + `scan_rules` directly so it can reuse the `Rules` per batch.)
#[allow(dead_code)]
pub fn compile_and_scan_rules(source: &str, data: &[u8]) -> Result<Vec<RuleMatch>> {
    let rules = compile_rules(source)?;
    Ok(scan_rules(&rules, data))
}

/// Convenience: compile `source` and scan `data`, returning per-pattern hits.
#[allow(dead_code)]
pub fn compile_and_scan_strings(source: &str, data: &[u8]) -> Result<Vec<StringMatch>> {
    let rules = compile_rules(source)?;
    Ok(scan_strings(&rules, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = r#"rule demo { strings: $a = "malware" condition: $a }"#;

    #[test]
    fn demo_rule_matches_data_containing_malware() {
        let m = compile_and_scan_rules(DEMO, b"this is malware data").unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "demo");
        assert_eq!(m[0].namespace, "default");
    }

    #[test]
    fn non_matching_data_yields_no_rules() {
        let m = compile_and_scan_rules(DEMO, b"perfectly clean bytes").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn string_match_reports_offset_and_text() {
        let hits = compile_and_scan_strings(DEMO, b"xxmalwarexx").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "demo");
        assert_eq!(hits[0].identifier, "$a");
        assert_eq!(hits[0].offset, 2);
        assert_eq!(hits[0].matched, "malware");
    }

    #[test]
    fn multi_rule_set_matches_each() {
        let src = r#"
            rule alpha : malicious { strings: $a = "evil" condition: $a }
            rule beta  { strings: $b = "worm" condition: $b }
        "#;
        let mut m = compile_and_scan_rules(src, b"evil worm present").unwrap();
        m.sort_by(|a, b| a.rule.cmp(&b.rule));
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].rule, "alpha");
        assert_eq!(m[0].tags, vec!["malicious".to_string()]);
        assert_eq!(m[1].rule, "beta");
        assert!(m[1].tags.is_empty());
    }

    #[test]
    fn rules_compile_true_and_false() {
        assert!(rules_compile(DEMO));
        assert!(rules_compile(r#"rule r { condition: true }"#));
        assert!(!rules_compile("rule broken { condition: }"));
        assert!(!rules_compile("this is not yara at all"));
    }

    #[test]
    fn invalid_rule_source_errors_clearly() {
        let err = compile_rules("rule broken { condition: }").unwrap_err();
        assert!(err.0.contains("invalid YARA rule"));
    }

    #[test]
    fn garbage_empty_and_binary_blobs_do_not_crash() {
        let rules = compile_rules(DEMO).unwrap();
        // Empty.
        assert!(scan_rules(&rules, b"").is_empty());
        assert!(scan_strings(&rules, b"").is_empty());
        // Pure binary / NUL-laden bytes.
        let binary: Vec<u8> = (0u16..512).map(|x| (x & 0xff) as u8).collect();
        assert!(scan_rules(&rules, &binary).is_empty());
        // Random-ish garbage.
        assert!(scan_rules(&rules, b"\x00\xff\x00\xfe\x7f\x80garbage").is_empty());
    }

    #[test]
    fn bad_blob_beside_good_still_matches_the_good() {
        // Scanning a hostile blob then a good one must keep working — the rules
        // object is reusable and scanning is total.
        let rules = compile_rules(DEMO).unwrap();
        let hostile: Vec<u8> = (0u32..100_000).map(|x| (x % 256) as u8).collect();
        assert!(scan_rules(&rules, &hostile).is_empty());
        // The good blob still matches afterwards.
        let m = scan_rules(&rules, b"contains malware now");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "demo");
    }

    #[test]
    fn binary_pattern_matched_bytes_render_as_hex() {
        // A hex pattern matching non-printable bytes → hex render, not garbage.
        let src = r#"rule h { strings: $a = { DE AD BE EF } condition: $a }"#;
        let hits = compile_and_scan_strings(src, b"\xde\xad\xbe\xef tail").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched, "deadbeef");
        assert_eq!(hits[0].offset, 0);
    }

    #[test]
    fn oversized_data_is_bounded() {
        // `bounded` caps the slice handed to the scanner.
        let big = vec![0u8; MAX_DATA_LEN + 1024];
        assert_eq!(bounded(&big).len(), MAX_DATA_LEN);
        let small = vec![0u8; 10];
        assert_eq!(bounded(&small).len(), 10);
    }

    #[test]
    fn multiple_hits_of_same_pattern() {
        let hits = compile_and_scan_strings(DEMO, b"malware and malware").unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[1].offset, 12);
    }
}
