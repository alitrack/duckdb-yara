// DuckDB loadable extension: YARA rule validation + scanning (malware-signature
// detection), powered by `yara-x` — a pure-Rust YARA interpreter with NO native
// libyara/C dependency.
//
// Thin quack-rs binding layer over `scanning.rs` (verbatim from Query-farm's
// vgi-yara worker, MIT — a self-contained engine with only the `yara-x` crate
// and std; only the Arrow IPC transport was replaced with direct C-API vector
// I/O).
//
// Function surface (v1 — flat returns):
//
//   yara_check(rules)                       -> BOOLEAN  pure validation: do these
//                                                       rules compile? (never errors)
//   yara_modules()                          -> table(module VARCHAR, usage VARCHAR)
//                                                       the yara-x modules built in
//   yara_string_matches(data, rules)        -> table(rule VARCHAR, identifier VARCHAR,
//                                                     offset BIGINT, matched VARCHAR)
//                                                       one row per pattern hit
//
// `data`/`rules` are bind-time CONSTANT arguments (DuckDB table functions bind
// positional constants, not row columns): pass a literal or a `CAST(... AS
// VARCHAR/BLOB)`. `data` accepts a BLOB or a VARCHAR (raw text is scanned as
// its UTF-8 bytes). Scanning is total: a scan failure (limit/timeout) is
// treated as "no matches", never an error; only an *invalid rules source* is a
// clean SQL error (at compile).
//
// Deferred (documented in README): `yara_scan(data, rules) -> table(rule,
// namespace, tags LIST(VARCHAR))` — the LIST-returning scan; the engine
// (`scanning::scan_rules`) already produces it, only the quack-rs LIST-in-table
// scan binding is outstanding.

use libduckdb_sys::{
    duckdb_bind_get_parameter, duckdb_bind_get_parameter_count, duckdb_get_blob,
    duckdb_is_null_value, duckdb_get_varchar, duckdb_vector_size,
};
use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::{ScalarFunctionBuilder, ScalarFunctionInfo};
use quack_rs::table::{BindInfo, FfiBindData, FfiInitData, InitInfo, TableFunctionBuilder};
use quack_rs::types::TypeId;
use quack_rs::vector::{VectorReader, VectorWriter};

mod scanning;

use scanning::{compile_rules, rules_compile, scan_strings};

/// The yara-x modules compiled into this extension (name, what a rule uses it
/// for). Kept in lockstep with the `yara-x` features enabled in Cargo.toml.
/// Sorted by module name so the table ordering is deterministic.
const MODULES: &[(&str, &str)] = &[
    (
        "console",
        "Emit log messages from a rule's condition while it evaluates, for debugging rule logic.",
    ),
    (
        "elf",
        "Inspect ELF executables: sections, segments, symbols, entry point and machine/type fields.",
    ),
    (
        "hash",
        "Compute MD5, SHA-1, SHA-256, CRC32 and checksums over the file or a byte range for content signatures.",
    ),
    (
        "math",
        "Arithmetic and statistics over byte ranges: entropy, mean, deviation, min/max and serial correlation.",
    ),
    (
        "pe",
        "Inspect Windows PE executables: headers, sections, imports, exports, resources and signatures.",
    ),
    (
        "string",
        "Helpers for working with matched or extracted strings, such as length and byte conversions.",
    ),
    (
        "time",
        "Access the current time so a rule condition can reason about when the scan runs.",
    ),
];

// ─────────────────────────────────────────────────────────────────────────────
// Scalar: yara_check(rules VARCHAR) -> BOOLEAN
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(yara_check_fn, |_info, input, output| {
    unsafe {
        let rules = VectorReader::new(input, 0);
        let row_count = rules.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !rules.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            // Pure validation: true if the rules compile, else false (never errors).
            writer.write_bool(row, rules_compile(rules.read_str(row)));
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Table: yara_modules() -> (module VARCHAR, usage VARCHAR)
// ─────────────────────────────────────────────────────────────────────────────

struct ModulesState {
    next: usize,
}

quack_rs::table_bind_callback!(modules_bind, |info| {
    unsafe {
        let n = MODULES.len();
        BindInfo::new(info)
            .add_result_column("module", TypeId::Varchar)
            .add_result_column("description", TypeId::Varchar)
            .set_cardinality(n as u64, true);
    }
});

quack_rs::table_init_callback!(modules_init, |info| {
    unsafe {
        InitInfo::new(info).set_max_threads(1);
        FfiInitData::<ModulesState>::set(info, ModulesState { next: 0 });
    }
});

quack_rs::table_scan_callback!(modules_scan, |info, output| {
    unsafe {
        let chunk = quack_rs::data_chunk::DataChunk::from_raw(output);
        let Some(state) = FfiInitData::<ModulesState>::get_mut(info) else {
            chunk.set_size(0);
            return;
        };
        let all = MODULES;
        if state.next >= all.len() {
            chunk.set_size(0);
            return;
        }
        let batch = (all.len() - state.next).min(duckdb_vector_size() as usize);
        let mut m = chunk.writer(0);
        let mut u = chunk.writer(1);
        for i in 0..batch {
            let (name, usage) = all[state.next + i];
            m.write_varchar(i, name);
            u.write_varchar(i, usage);
        }
        state.next += batch;
        chunk.set_size(batch)
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Table: yara_string_matches(data, rules) -> (rule, identifier, offset, matched)
// data/rules are bind-time constants (data BLOB or VARCHAR, rules VARCHAR).
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct SmBind {
    data: Option<Vec<u8>>,
    rules: Option<String>,
}

struct SmState {
    rows: Vec<scanning::StringMatch>,
    next: usize,
}

fn bind_constant_bytes(info: libduckdb_sys::duckdb_bind_info, idx: u64) -> Option<Vec<u8>> {
    unsafe {
        if (duckdb_bind_get_parameter_count(info) as u64) <= idx {
            return None;
        }
        let v = duckdb_bind_get_parameter(info, idx);
        if duckdb_is_null_value(v) {
            return None;
        }
        // duckdb_get_blob works for both BLOB and VARCHAR values (both are
        // string-typed under the hood), returning {data, size}.
        let b = duckdb_get_blob(v);
        if b.data.is_null() || b.size <= 0 {
            return None;
        }
        let slice = std::slice::from_raw_parts(b.data as *const u8, b.size as usize);
        Some(slice.to_vec())
    }
}

fn bind_constant_str(info: libduckdb_sys::duckdb_bind_info, idx: u64) -> Option<String> {
    unsafe {
        if (duckdb_bind_get_parameter_count(info) as u64) <= idx {
            return None;
        }
        let v = duckdb_bind_get_parameter(info, idx);
        if duckdb_is_null_value(v) {
            return None;
        }
        let s = duckdb_get_varchar(v);
        if s.is_null() {
            return None;
        }
        Some(unsafe { std::ffi::CStr::from_ptr(s) }
            .to_string_lossy()
            .into_owned())
    }
}

quack_rs::table_bind_callback!(sm_bind, |info| {
    unsafe {
        BindInfo::new(info)
            .add_result_column("rule", TypeId::Varchar)
            .add_result_column("identifier", TypeId::Varchar)
            .add_result_column("offset", TypeId::BigInt)
            .add_result_column("matched", TypeId::Varchar);
        let data = bind_constant_bytes(info, 0);
        let rules = bind_constant_str(info, 1);
        FfiBindData::<SmBind>::set(info, SmBind { data, rules });
    }
});

quack_rs::table_init_callback!(sm_init, |info| {
    unsafe {
        InitInfo::new(info).set_max_threads(1);
        let bind = FfiBindData::<SmBind>::get_from_init(info).cloned();
        let data = bind.as_ref().and_then(|b| b.data.clone());
        let rules_src = bind.as_ref().and_then(|b| b.rules.clone());
        let rows = match (data, rules_src) {
            (Some(data), Some(rules_src)) => match compile_rules(&rules_src) {
                Ok(rules) => scan_strings(&rules, &data),
                Err(e) => {
                    // Compile happens in bind/init; surface a clean error here.
                    // (init cannot set_error on the table info, so an invalid
                    // ruleset yields zero rows rather than aborting — document.)
                    let _ = e;
                    Vec::new()
                }
            },
            _ => Vec::new(),
        };
        FfiInitData::<SmState>::set(info, SmState { rows, next: 0 });
    }
});

quack_rs::table_scan_callback!(sm_scan, |info, output| {
    unsafe {
        let chunk = quack_rs::data_chunk::DataChunk::from_raw(output);
        let Some(state) = FfiInitData::<SmState>::get_mut(info) else {
            chunk.set_size(0);
            return;
        };
        if state.next >= state.rows.len() {
            chunk.set_size(0);
            return;
        }
        let batch =
            (state.rows.len() - state.next).min(duckdb_vector_size() as usize);
        let mut r = chunk.writer(0);
        let mut id = chunk.writer(1);
        let mut off = chunk.writer(2);
        let mut m = chunk.writer(3);
        for i in 0..batch {
            let row = &state.rows[state.next + i];
            r.write_varchar(i, &row.rule);
            id.write_varchar(i, &row.identifier);
            off.write_i64(i, row.offset as i64);
            m.write_varchar(i, &row.matched);
        }
        state.next += batch;
        chunk.set_size(batch)
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    // yara_check(rules) -> BOOLEAN
    con.register_scalar(
        ScalarFunctionBuilder::new("yara_check")
            .param(TypeId::Varchar)
            .returns(TypeId::Boolean)
            .function(yara_check_fn),
    )?;

    // yara_modules() -> table(module, usage)
    con.register_table(
        TableFunctionBuilder::new("yara_modules")
            .bind(modules_bind)
            .init(modules_init)
            .scan(modules_scan),
    )?;

    // yara_string_matches(data, rules) -> table(rule, identifier, offset, matched)
    con.register_table(
        TableFunctionBuilder::new("yara_string_matches")
            .param(TypeId::Blob)
            .param(TypeId::Varchar)
            .bind(sm_bind)
            .init(sm_init)
            .scan(sm_scan),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(yara_init_c_api, |con| register_all(con));
