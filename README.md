# duckdb-yara

**YARA rule validation + scanning, in SQL.** A pure-Rust `yara-x` (no native
`libyara`/C dependency) lets you validate YARA rulesets and scan data for
malware-signature pattern hits directly in DuckDB — one row per matched pattern
with its identifier and byte offset.

Built with the [quack-rs] C-API extension template. The engine
(`scanning.rs`) is a verbatim port of the pure-compute core of Query-farm's
`vgi-yara` worker (MIT) — only the Arrow IPC transport was swapped for direct
C-API vector I/O.

```sql
-- Install into your local extension dir (once), then:
INSTALL 'yara' FROM 'target/release/yara.duckdb_extension';
LOAD 'yara';

-- Pure validation: do these rules compile? (never errors)
SELECT yara_check('rule bad { strings: $a = "abc" }');            -- false

-- The yara-x modules a rule may `import`
SELECT * FROM yara_modules();                                      -- 7 modules

-- Scan data (BLOB or raw text) against a ruleset — one row per pattern hit
SELECT * FROM yara_string_matches(
    'MZ...' ,                          -- data (BLOB or VARCHAR)
    'rule MZ { strings: $mz = "MZ" condition: $mz }'
);
-- rule | identifier | offset | matched
```

## Functions

| Function | Returns | Notes |
|----------|---------|-------|
| `yara_check(rules)` | `BOOLEAN` | Pure validation — do the rules compile? `NULL` in → `NULL` out. Never errors. |
| `yara_modules()` | `table(module, description)` | The 7 yara-x modules compiled in (for `import "<module>"` discovery). |
| `yara_string_matches(data, rules)` | `table(rule, identifier, offset, matched)` | One row per pattern (string) hit. `data` is a BLOB or raw text; `rules` is a source string. Both are **bind-time constant** arguments. |

`data`/`rules` are **constant** arguments (DuckDB table functions bind positional
constants, not row columns): pass a literal or `CAST(... AS VARCHAR/BLOB)`.
`data` accepts a BLOB (scanned as raw bytes) or a VARCHAR (scanned as its UTF-8
bytes).

## Semantics

- **Scanning is total** — a scan failure (limit/timeout) is treated as *no
  matches*, never an error; the only thing that can fail is *compiling an
  invalid rules source* (surfaced as a clean SQL error).
- `yara_check` is the fast pre-flight: it compiles the ruleset and reports
  `TRUE`/`FALSE` without touching any data.
- A match row reports the **rule name**, the **pattern identifier** (e.g.
  `$a`), the **byte offset** of the hit, and the **matched bytes** (rendered as
  UTF-8 if printable, else hex).

## Deferred (documented)

`yara_scan(data, rules) -> table(rule, namespace, tags LIST(VARCHAR))` — the
rule-level (not pattern-level) scan with a `tags` list column. The engine
(`scanning::scan_rules`) already produces this shape; only the quack-rs
LIST-in-table-scan binding is outstanding.

## Building

```bash
make            # requires a local duckdb build (see the quack-rs template)
make test       # SQL-level integration tests (LOAD the built extension in-memory)
```

[quack-rs]: https://github.com/duckdb/quack-rs
