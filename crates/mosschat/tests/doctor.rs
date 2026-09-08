//! WO-1.4b: `mosschat doctor` against a gate that is not there.
//!
//! Section 8's WO-1.4 verify line, second half: "`doctor` against an
//! unreachable gate exits non-zero and prints which step failed". These run
//! the real binary rather than calling a function, because the exit code
//! and what reaches stdout and stderr are the thing under test.
//!
//! Every run points `HOME` and `XDG_STATE_HOME` at a temporary directory,
//! so a test never writes into the developer's own diagnostics log
//! (section 7's location rules resolve from exactly those two variables).

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use mosschat_net::diag::{DiagRecord, Step};

const COMMUNITY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const IDENTITY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// A unique temporary state directory, removed first so one run never sees
/// another's records.
fn state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("jerome14b-doctor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs the built binary with `HOME` and `XDG_STATE_HOME` pointed at `dir`.
fn doctor(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mosschat"))
        .arg("doctor")
        .args(args)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir)
        .output()
        .unwrap()
}

/// The diagnostics directory `doctor` will have used under `dir`, whichever
/// platform this test runs on (section 7's Location paragraph).
fn diagnostics_dir(dir: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        dir.join("Library").join("Logs").join("mosschat")
    } else {
        dir.join("mosschat").join("diagnostics")
    }
}

fn records_written(dir: &Path) -> Vec<DiagRecord> {
    let mut out = Vec::new();
    let diagnostics = diagnostics_dir(dir);
    for entry in std::fs::read_dir(&diagnostics).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        for outcome in mosschat_net::diag::read_records(&path).unwrap() {
            if let mosschat_net::diag::ReadOutcome::Record(record) = outcome {
                out.push(*record);
            }
        }
    }
    out
}

/// A gate whose name does not resolve at all: the fast half of "against an
/// unreachable gate", and the one case that does not wait out a handshake.
///
/// Deliberate break to fail this test: in `main.rs::exit_for`, return
/// `std::process::exit(0)` for every record. The report still prints and
/// the record is still written; the exit code stops distinguishing a house
/// that connected from one that never found its gate.
#[test]
fn a_gate_whose_name_does_not_resolve_exits_non_zero_naming_the_step() {
    let dir = state_dir("unresolvable");
    let out = doctor(
        &dir,
        &[
            "--gate",
            "gate.invalid.example.:443",
            "--community",
            COMMUNITY,
            "--identity",
            IDENTITY,
        ],
    );
    assert!(
        !out.status.success(),
        "an unreachable gate must exit non-zero"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.starts_with(mosschat_net::diag::PRIVACY_NOTICE),
        "the first line says the report carries IP addresses: {stdout:?}"
    );
    assert!(
        stderr.contains("failed at step gate_dial"),
        "it must print which step failed: {stderr:?}"
    );
    assert!(stdout.contains("reason gate_unreachable"), "{stdout:?}");

    let records = records_written(&dir);
    assert_eq!(records.len(), 1, "one attempt is one record");
    assert_eq!(records[0].failed_step, Some(Step::GateDial));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A gate address that resolves and never answers, which is the case
/// section 7 says cannot be told from UDP being blocked without a second
/// gate or a TCP probe: the record's detail says so rather than pretending
/// otherwise, and `--json` prints the record the log holds.
///
/// Deliberate break to fail this test: in `main.rs::print_record`, print
/// `record.to_human_report()` regardless of `json`. The exit code and the
/// written record are unchanged; the `--json` parse back through
/// `DiagRecord::from_json_line` fails.
#[test]
fn an_unreachable_gate_exits_non_zero_and_its_json_parses_back() {
    let dir = state_dir("unreachable");
    // Port 9 (discard) on loopback with nothing bound: it resolves, and no
    // QUIC handshake ever completes.
    let out = doctor(
        &dir,
        &[
            "--gate",
            "127.0.0.1:9",
            "--community",
            COMMUNITY,
            "--identity",
            IDENTITY,
            "--json",
        ],
    );
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next().expect("one JSON object on stdout");
    let parsed = DiagRecord::from_json_line(line).expect("--json output must parse back");
    assert_eq!(parsed.failed_step, Some(Step::GateDial));
    assert_eq!(parsed.reason, mosschat_net::diag::Reason::GateUnreachable);
    // Konrad's must 1: `at_ms` is stamped when the step finished, so the
    // dial that waited out the 10 s deadline is stamped past it and the
    // report prints that as its duration rather than as 0 ms.
    assert!(
        parsed.steps[0].at_ms >= 9_000,
        "the dial step's at_ms must carry the time it waited: {:?}",
        parsed.steps[0]
    );
    assert!(
        parsed
            .steps
            .iter()
            .any(|step| step.detail.contains("UDP being blocked")),
        "section 7: the detail says what cannot be told apart: {:?}",
        parsed.steps
    );

    // The same record is what `--last` reports, without running anything.
    let last = doctor(&dir, &["--last", "--json"]);
    assert!(!last.status.success());
    let last_stdout = String::from_utf8_lossy(&last.stdout);
    let last_line = last_stdout.lines().next().unwrap();
    let last_record = DiagRecord::from_json_line(last_line).unwrap();
    assert_eq!(last_record.attempt, parsed.attempt);
    assert_eq!(last_record.failed_step, Some(Step::GateDial));
    std::fs::remove_dir_all(&dir).unwrap();
}
