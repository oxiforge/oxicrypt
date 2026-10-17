//! The probe scripts under `.github/probes` read integrity slots with their
//! own copies of the slot layout. Each copy is checked here against the
//! constants the signer and the verifier use, so a layout change that misses
//! a probe fails in CI rather than in a probe run that reads the wrong bytes.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use oxicrypt_integrity::slot::{
    OFF_FILE_LEN, OFF_FTR, OFF_KEY_ID, OFF_SIG, OFF_SLOT_FILE_OFF, OFF_SLOT_RVA, OFF_VERSION,
};
use oxicrypt_integrity::{SLOT_SIZE, SLOT_VERSION};

fn probe(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/probes")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The values of a Python assignment that names `names` on its left, as
/// in `A, B = 1, 2` or `A = 1  # comment`.
fn python_assignment(text: &str, names: &[&str]) -> Result<Vec<usize>, String> {
    let lhs = names.join(", ");
    let line = text
        .lines()
        .find(|l| l.split_once(" = ").is_some_and(|(left, _)| left == lhs))
        .ok_or_else(|| format!("no assignment to {lhs}"))?;
    let rhs = line.split_once(" = ").map(|(_, r)| r).unwrap_or_default();
    let rhs = rhs.split('#').next().unwrap_or_default();
    let values: Result<Vec<usize>, _> = rhs.split(',').map(|v| v.trim().parse()).collect();
    let values = values.map_err(|e| format!("{lhs}: {e}"))?;
    if values.len() == names.len() {
        Ok(values)
    } else {
        Err(format!("{lhs}: {} values", values.len()))
    }
}

/// Requires the Python assignment to `names` to hold `want`.
fn check_python(text: &str, names: &[&str], want: &[usize]) -> Result<(), String> {
    let got = python_assignment(text, names)?;
    if got == want {
        Ok(())
    } else {
        Err(format!("{names:?} = {got:?}, the slot layout is {want:?}"))
    }
}

/// The value of `#define name value` in a C probe.
fn c_define(text: &str, name: &str) -> Result<usize, String> {
    let prefix = format!("#define {name} ");
    let line = text
        .lines()
        .find(|l| l.starts_with(&prefix))
        .ok_or_else(|| format!("no #define {name}"))?;
    line.get(prefix.len()..)
        .unwrap_or_default()
        .trim()
        .parse()
        .map_err(|e| format!("{name}: {e}"))
}

/// Requires each `#define` to hold its value.
fn check_c(text: &str, want: &[(&str, usize)]) -> Result<(), String> {
    for (name, value) in want {
        let got = c_define(text, name)?;
        if got != *value {
            return Err(format!("#define {name} {got}, the slot layout is {value}"));
        }
    }
    Ok(())
}

/// Lines that add a number literal to one of `bases`: a slot offset written
/// in place rather than through a checked constant.
fn literal_offsets(text: &str, bases: &[&str]) -> Vec<String> {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.lines()
        .filter(|l| {
            bases.iter().any(|b| {
                l.match_indices(b).any(|(i, _)| {
                    // The whole identifier, then `+` with or without spaces,
                    // then a digit.
                    let whole = !l[..i].ends_with(ident);
                    let rest = l[i + b.len()..].trim_start();
                    whole
                        && !rest.starts_with(ident)
                        && rest.strip_prefix('+').is_some_and(|r| {
                            r.trim_start().starts_with(|c: char| c.is_ascii_digit())
                        })
                })
            })
        })
        .map(str::to_owned)
        .collect()
}

/// The slot-relative literal offsets left in each probe: every slot read
/// must go through a named, checked constant.
#[test]
fn no_probe_adds_a_literal_offset_to_a_slot() {
    for (name, bases) in [
        ("reservation.py", &["slot", "SLOT_AT"][..]),
        ("macho-tamper.py", &["slot"][..]),
        ("pe-tamper.py", &["slot"][..]),
        ("slot-stamp.py", &["slot"][..]),
        ("extent-v2-probe.c", &["slot_mem", "k"][..]),
    ] {
        assert_eq!(
            literal_offsets(&probe(name), bases),
            Vec::<String>::new(),
            "{name}"
        );
    }
}

/// `slot-stamp.py` is a version-2 probe for `elf-fixture.c`'s slot: its
/// size is version 2's, which the fixture reserves, and the offsets it
/// shares with every version are the current ones.
#[test]
fn slot_stamp_py_writes_the_shared_slot_rva_of_a_v2_slot() {
    let text = probe("slot-stamp.py");
    check_python(&text, &["V2_SLOT_SIZE"], &[16_384]).unwrap();
    check_python(&text, &["MAGIC_LEN"], &[SLOT_SIZE - OFF_FTR]).unwrap();
    check_python(&text, &["OFF_SLOT_RVA"], &[OFF_SLOT_RVA]).unwrap();
    check_c(&probe("elf-fixture.c"), &[("SLOT_SIZE", 16_384)]).unwrap();
}

#[test]
fn reservation_py_reads_the_current_slot_layout() {
    let text = probe("reservation.py");
    check_python(
        &text,
        &["OFF_SIG", "OFF_KEY_ID", "OFF_SLOT_FILE_OFF", "OFF_FILE_LEN"],
        &[OFF_SIG, OFF_KEY_ID, OFF_SLOT_FILE_OFF, OFF_FILE_LEN],
    )
    .unwrap();
    check_python(&text, &["OFF_VERSION"], &[OFF_VERSION]).unwrap();
    let sizes = format!("SLOT_SIZES = {{2: 16384, {SLOT_VERSION}: {SLOT_SIZE}}}");
    assert!(
        text.lines().any(|l| l == sizes),
        "reservation.py lacks {sizes}"
    );
}

#[test]
fn the_tamper_probes_flip_the_current_signature_and_key_id() {
    for name in ["macho-tamper.py", "pe-tamper.py"] {
        check_python(
            &probe(name),
            &["OFF_SIG", "OFF_KEY_ID"],
            &[OFF_SIG, OFF_KEY_ID],
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// `macho-chained.py` takes the slot budget from the signer rather than
/// keeping a copy of the layout, and reads the line the signer prints.
#[test]
fn macho_chained_py_reads_the_signers_budget() {
    let text = probe("macho-chained.py");
    for stale in ["SLOT_HEADER", "SLOT_BYTES", "BIND_RECORD_HEADER", "ENTRY ="] {
        assert!(!text.contains(stale), "macho-chained.py keeps {stale}");
    }
    let signer = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../oxicrypt-integrity-sign/src/main.rs"),
    )
    .unwrap();
    let printed = "\"  slot budget: stored {} string-table {} capacity {} fits {}\",";
    assert!(
        signer.contains(printed),
        "the signer does not print {printed}"
    );
    let parsed = r"^  slot budget: stored (\d+) string-table (\d+) capacity (\d+) fits (yes|no)$";
    assert!(
        text.contains(parsed),
        "macho-chained.py does not parse {parsed}"
    );
}

#[test]
fn extent_v2_probe_c_reads_the_current_slot_fields() {
    let text = probe("extent-v2-probe.c");
    check_c(
        &text,
        &[
            ("SLOT_MAGIC_LEN", SLOT_SIZE - OFF_FTR),
            ("SLOT_VERSION", usize::try_from(SLOT_VERSION).unwrap()),
            ("SLOT_SIZE", SLOT_SIZE),
            ("OFF_VERSION", OFF_VERSION),
            ("OFF_SLOT_RVA", OFF_SLOT_RVA),
            ("OFF_KEY_ID", OFF_KEY_ID),
            ("OFF_SLOT_FILE_OFF", OFF_SLOT_FILE_OFF),
            ("OFF_FILE_LEN", OFF_FILE_LEN),
        ],
    )
    .unwrap();
    // Every slot read goes through those constants.
    assert_eq!(
        literal_offsets(&text, &["slot_mem", "k"]),
        Vec::<String>::new()
    );
}

/// Control: each check fires on a probe whose offset is wrong.
#[test]
fn the_checks_fire_on_a_wrong_offset() {
    let good = "OFF_SIG, OFF_KEY_ID = 32, 4659  # fields\n";
    assert!(check_python(good, &["OFF_SIG", "OFF_KEY_ID"], &[32, 4659]).is_ok());
    let stale = "OFF_SIG, OFF_KEY_ID = 32, 96\n";
    assert!(check_python(stale, &["OFF_SIG", "OFF_KEY_ID"], &[32, 4659]).is_err());
    assert!(check_python("", &["OFF_SIG"], &[32]).is_err());

    let c = "#define OFF_KEY_ID 96\n#define OFF_SLOT_RVA 28\n";
    assert!(check_c(c, &[("OFF_SLOT_RVA", 28)]).is_ok());
    assert!(check_c(c, &[("OFF_KEY_ID", OFF_KEY_ID)]).is_err());
    assert!(check_c(c, &[("OFF_FILE_LEN", OFF_FILE_LEN)]).is_err());

    let read = "read_mem(slot_mem + 28, &slot_rva, 4)";
    assert_eq!(literal_offsets(read, &["slot_mem"]).len(), 1);
    // Spellings without spaces, and Python, are caught too.
    assert_eq!(
        literal_offsets("read_mem(slot_mem+28, &v, 4)", &["slot_mem"]).len(),
        1
    );
    assert_eq!(literal_offsets("x = data[slot +4659]", &["slot"]).len(), 1);
    // A longer identifier that starts with the base is not the base.
    assert!(literal_offsets("slot_rva + 1", &["slot"]).is_empty());
    let named = "read_mem(slot_mem + OFF_SLOT_RVA, &v, 4)";
    assert!(literal_offsets(named, &["slot_mem"]).is_empty());
}
