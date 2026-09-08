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

// ----------------------------------------------------------------------
// Against a gate that is really there (2026-09-08 fault matrix)
// ----------------------------------------------------------------------
//
// The nine failing rows of that matrix each recorded `gate_dial` ok, then
// nothing at all: no failed step, reason `internal`, exit 0. Neither the
// netem condition each row applied nor any deadline caused it. A `doctor`
// run left its registration seated at the gate (it ends through
// `std::process::exit`, which runs no destructor, so nothing closed the
// QUIC connection), section 1's sub-cap is two live connections per key,
// and so the third run inside quinn's 30 s idle timeout was refused before
// it could register -- while the report said nothing was wrong.
//
// These two tests are that pair of defects, reproduced with no netem, no
// root and no shaped network: a gate in this process, and the real binary
// run against it.
//
// Which refusal is proven where, precisely (Yseult's item 5 on PR 69). At
// binary level these cover the refusal that arrives as a **connection
// close** carrying section 7's code: an empty member list, refused in the
// handshake before any stream exists. The refusal that arrives as **frame
// 12**, which is the per-key capacity one the fault matrix actually hit,
// is covered in process by `mosschat-net`'s
// `third_connection_for_one_key_is_refused_not_evicted`, which asserts the
// house receives the code. Both shapes reach `run_doctor_steps` through
// the same `Err` arm.

const IDENTITY_BYTES: [u8; 32] = [0x22; 32];
const COMMUNITY_BYTES: [u8; 32] = [0x11; 32];

/// The public key `IDENTITY` proves in the TLS handshake, which is what the
/// gate's member list and slot table are keyed by.
fn doctor_public_key() -> [u8; 32] {
    mosschat_core::identity::AuthorKey::from_bytes(&IDENTITY_BYTES).public_bytes()
}

/// A gate on loopback serving exactly `members`, on ports the OS picks.
fn start_gate(members: &[[u8; 32]]) -> mosschat_net::gate::server::GateServer {
    let bind = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
    mosschat_net::gate::server::GateServer::bind(mosschat_net::gate::server::GateServerConfig {
        community: COMMUNITY_BYTES,
        identity_seed: [0x44; 32],
        members: mosschat_net::gate::MemberList::from_keys(members.iter().copied()),
        primary_bind: bind,
        secondary_bind: bind,
        max_registrations: mosschat_net::gate::limits::MAX_REGISTRATIONS,
    })
    .unwrap()
}

/// Runs the binary off the runtime's worker threads: it blocks until the
/// child exits, and the gate under test is being served by this same
/// runtime.
async fn doctor_against(dir: &Path, gate: std::net::SocketAddr) -> Output {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        doctor(
            &dir,
            &[
                "--gate",
                &gate.to_string(),
                "--community",
                COMMUNITY,
                "--identity",
                IDENTITY,
                "--json",
            ],
        )
    })
    .await
    .unwrap()
}

/// The record a `--json` run printed on stdout.
fn json_record(out: &Output) -> DiagRecord {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next().expect("one JSON object on stdout");
    DiagRecord::from_json_line(line).expect("--json output must parse back")
}

/// Whether `record` has `step` recorded with an `ok` outcome.
fn step_ok(record: &DiagRecord, step: Step) -> bool {
    record
        .steps
        .iter()
        .any(|s| s.step == step && s.outcome == mosschat_net::diag::StepOutcome::Ok)
}

/// A gate that refuses the registration is reported as a failure and exits
/// non-zero, even though the refusal arrives as a connection close rather
/// than as frame 12.
///
/// This is the exact shape the fault matrix hit: the dial succeeds, the
/// gate closes the connection before the `Registered` frame, and `connect`
/// returns an error. It used to record no step for that at all, so
/// `failed_step` stayed null, the reason fell to `internal`, and `exit_for`
/// exited **0** on a doctor that never registered.
///
/// Deliberate break to fail this test, run for real: in
/// `client.rs::connect_with_recorder`, put the three `register_step`
/// `map_err`s back to bare `?`, and in `main.rs` take the `else` arm that
/// records the in-flight step back out. The run then exits 0 with no failed
/// step, confirmed by an actual run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gate_that_refuses_the_registration_exits_non_zero_naming_the_step() {
    let dir = state_dir("refused");
    // An empty member list: section 1 refuses a non-member "in the
    // handshake ... before a slot is touched", which is before any stream
    // exists to answer on.
    let gate = start_gate(&[]);
    let out = doctor_against(&dir, gate.primary_addr()).await;

    assert!(
        !out.status.success(),
        "a doctor that could not register must not exit 0: {out:?}"
    );
    let record = json_record(&out);
    assert_eq!(
        record.failed_step,
        Some(Step::GateRegister),
        "the step in flight when the gate closed is the one recorded: {:?}",
        record.steps
    );
    assert!(
        step_ok(&record, Step::GateDial),
        "the dial itself succeeded: {:?}",
        record.steps
    );
    assert_eq!(
        record.reason,
        mosschat_net::diag::Reason::GateRefusedNotMember,
        "the gate named its refusal in the close; the record says so too: {:?}",
        record.steps
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed at step gate_register"),
        "it must print which step failed: {stderr:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A `doctor` run deregisters before it exits, so the runs after it still
/// register: three in a row, with no wait between them, all reach
/// `gate_register` ok and the gate holds no connection for that key
/// afterwards.
///
/// The third run does not exit 0: section 1's `Reflect` limit is 2 per
/// minute and this implementation tracks it per key, so the third run's
/// secondary-port reflection is refused `gate_rate_limited`. That is a
/// separate finding (see the PR), and what this test pins is that the
/// refusal is now the *reflection*, not the registration, and that it is
/// reported rather than swallowed.
///
/// Deliberate break to fail this test, run for real: remove the
/// `deregister(&client).await` call from the gate-only path of
/// `run_doctor_steps`. The third run is then refused `gate_at_capacity`
/// before it can register, which is what the matrix recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_doctor_run_deregisters_so_the_next_one_still_registers() {
    let dir = state_dir("deregisters");
    let key = doctor_public_key();
    let gate = start_gate(&[key]);

    for run in 1..=3 {
        let out = doctor_against(&dir, gate.primary_addr()).await;
        let record = json_record(&out);
        assert!(
            step_ok(&record, Step::GateRegister),
            "run {run} must register: {:?}",
            record.steps
        );
        assert_eq!(
            out.status.success(),
            record.failed_step.is_none(),
            "run {run} exited {:?} with failed_step {:?}: the exit code and the record must agree",
            out.status.code(),
            record.failed_step
        );
        // The gate lets go as soon as it has read the `Goodbye`, and the
        // house waits for that close before returning, so this is already
        // true when the child exits; polled anyway, briefly, rather than
        // asserting on the timing of another task's teardown.
        let mut held = gate.connections_for_key(&key);
        for _ in 0..100 {
            if held == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            held = gate.connections_for_key(&key);
        }
        assert_eq!(
            held, 0,
            "run {run} left its registration seated at the gate"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
