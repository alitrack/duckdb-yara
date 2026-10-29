//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full function surface (1 scalar + 2 tables).
//!
//! Run: `cargo test --release` (after the cdylib is built and stamped).
//!
//! Note: the `offset` column name is a reserved word in newer DuckDB, so every
//! reference to it is double-quoted. Multi-column rows are read back as a
//! single concatenated VARCHAR column (`a || '|' || b || ...`) via `query_one`
//! so the test stays independent of `query_map` row-destructure ergonomics.

use quack_rs::testing::InMemoryDb;

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/yara.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display())).expect("load extension");
    d
}

fn rules() -> &'static str {
    r#"rule MZ { strings: $mz = "MZ" condition: $mz }"#
}

#[test]
fn check_valid_true_invalid_false_null() {
    let d = db();
    // A trivially-valid ruleset compiles -> true.
    let ok: bool = d.query_one("SELECT yara_check('rule R { condition: true }')").unwrap();
    assert!(ok);

    // The real MZ ruleset compiles -> true.
    let mz_ok: bool = d.query_one(&format!("SELECT yara_check('{r}')", r = rules())).unwrap();
    assert!(mz_ok);

    // An invalid ruleset -> false (never an error).
    let bad: bool = d.query_one("SELECT yara_check('rule x { not a rule }')").unwrap();
    assert!(!bad);

    // NULL in -> NULL out.
    let nul: Option<bool> = d.query_one("SELECT yara_check(NULL)").unwrap();
    assert!(nul.is_none());
}

#[test]
fn string_matches_hit() {
    let d = db();
    // data "MZ90abc" -> one hit: rule MZ, identifier $mz, offset 0, matched MZ.
    let row: String = d
        .query_one(&format!(
            "SELECT rule || '|' || identifier || '|' || \"offset\" || '|' || matched
             FROM yara_string_matches(CAST('MZ90abc' AS BLOB), '{r}')",
            r = rules()
        ))
        .unwrap();
    assert_eq!(row, "MZ|$mz|0|MZ");
}

#[test]
fn string_matches_miss() {
    let d = db();
    // "helloworld" has no "MZ" -> zero rows (count = 0).
    let n: i64 = d
        .query_one(&format!(
            "SELECT count(*) FROM yara_string_matches(CAST('helloworld' AS BLOB), '{r}')",
            r = rules()
        ))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn string_matches_multiple_hits() {
    let d = db();
    // Two occurrences of "AB" in "xxAByyAB" -> exactly two hits at offsets 2 and 6.
    let r = r#"rule AB { strings: $x = "AB" condition: $x }"#;
    let n: i64 = d
        .query_one(&format!(
            "SELECT count(*) FROM yara_string_matches(CAST('xxAByyAB' AS BLOB), '{r}')",
            r = r
        ))
        .unwrap();
    assert_eq!(n, 2);
    let mn: i64 = d
        .query_one(&format!(
            "SELECT min(\"offset\") FROM yara_string_matches(CAST('xxAByyAB' AS BLOB), '{r}')",
            r = r
        ))
        .unwrap();
    let mx: i64 = d
        .query_one(&format!(
            "SELECT max(\"offset\") FROM yara_string_matches(CAST('xxAByyAB' AS BLOB), '{r}')",
            r = r
        ))
        .unwrap();
    assert_eq!((mn, mx), (2, 6));
}

#[test]
fn modules_table_lists_seven() {
    let d = db();
    let n: i64 = d.query_one("SELECT count(*) FROM yara_modules()").unwrap();
    assert_eq!(n, 7);
    // Exactly the 7 expected modules, nothing else.
    let all: bool = d
        .query_one(
            "SELECT count(DISTINCT module) = 7
             FROM yara_modules()
             WHERE module IN ('console','elf','hash','math','pe','string','time')",
        )
        .unwrap();
    assert!(all);
}
