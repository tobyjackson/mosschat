//! WO-1.5a: the row command WO-1.5 and WO-1.6 actually run, end to end
//! over three real processes on loopback.
//!
//! `tests/doctor.rs` covers the command's failure paths against a gate
//! that is not there. This covers the opposite: a gatehouse, a headless
//! house and a `doctor --friend --hold` between them, each a separate
//! process started from the built binary, because the thing under test is
//! the command line a person types on a second machine and the record it
//! leaves behind, not a library call that resembles it.
//!
//! Every process here is killed by its own pid through [`Child`]'s handle,
//! never by name, and every one of them is a child of this test, so a run
//! that fails part way leaves nothing behind: [`Process`]'s `Drop` kills
//! and reaps whatever is still alive.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mosschat_net::diag::{DiagRecord, PathChoice, Reason, VisitEventKind};

/// The string value of `key` in one of the house's JSON lines.
///
/// A scan rather than a parser: this crate does not depend on a JSON
/// library and a test is not the place to add one, the lines are this
/// workspace's own four-field output, and what is being asserted is that
/// a field is there and says what it should.
fn string_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = line.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)
}

/// The unsigned number value of `key` in one of the house's JSON lines.
fn number_field(line: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let rest = line.get(start..)?;
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..end)?.parse().ok()
}

/// A child process this test started, killed by its pid when the test
/// ends however it ends.
struct Process {
    what: &'static str,
    child: Child,
}

impl Drop for Process {
    fn drop(&mut self) {
        // `kill` on an already-exited child is an error, not a problem:
        // the point is that nothing this test started outlives it.
        let _ = self.child.kill();
        match self.child.wait() {
            Ok(_) => {}
            Err(e) => eprintln!("could not reap the {}: {e}", self.what),
        }
    }
}

/// A unique temporary directory for one test.
fn work_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("konrad15a-visit-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A random 32 byte seed and the public key it presents.
fn identity(dir: &Path, name: &str) -> (PathBuf, String) {
    let mut seed = [0u8; 32];
    // The OS CSPRNG through the same crate the binaries use, so a test
    // never reuses an identity between runs and the gate's per key limits
    // never bite one test because of another.
    {
        use rand::RngExt;
        rand::rng().fill(&mut seed);
    }
    let path = dir.join(format!("{name}.seed"));
    std::fs::write(&path, hex(&seed)).unwrap();
    let public = mosschat_core::identity::AuthorKey::from_bytes(&seed).public_bytes();
    (path, hex(&public))
}

/// Reads lines from `reader` into `into` until it ends, so a child's
/// stdout pipe never fills and blocks the child.
fn drain(reader: impl std::io::Read + Send + 'static, into: Arc<Mutex<Vec<String>>>) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else { return };
            into.lock().unwrap().push(line);
        }
    });
}

/// Waits up to `within` for a collected line matching `wanted`.
fn wait_for_line(
    lines: &Arc<Mutex<Vec<String>>>,
    within: Duration,
    wanted: impl Fn(&str) -> bool,
) -> Option<String> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(found) = lines.lock().unwrap().iter().find(|line| wanted(line)) {
            return Some(found.clone());
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The gatehouse, the house, and everything they need.
struct Community {
    _gatehouse: Process,
    _house: Process,
    house_lines: Arc<Mutex<Vec<String>>>,
    dir: PathBuf,
    community: String,
    gate: String,
    house_key: String,
}

impl Community {
    /// Starts a gatehouse on loopback and a headless house registered at
    /// it. Nothing upgrades in this shape: see [`Community::start_on`].
    fn start(name: &str, house_no_punch: bool) -> Self {
        Self::start_on(name, house_no_punch, "127.0.0.1")
    }

    /// The same, with the gatehouse bound to `bind_ip`.
    ///
    /// **Which address the gate binds decides whether anything can
    /// upgrade**, which is not obvious and cost a whole fault matrix to
    /// learn. Section 2 step 1 drops loopback from what a house *offers*
    /// (telling a peer to probe 127.0.0.1 tells it to probe itself), so
    /// with the gate on loopback the only candidate either side offers is
    /// its own private LAN address, which the other refuses because
    /// nothing vouches for it, and the exchange settles at "0 probed" with
    /// reason `no_candidates`. With the gate on a routed address the
    /// reflection is that address, `peer_observed` vouches for it, and the
    /// pair probes and upgrades exactly as two houses behind NATs do.
    fn start_on(name: &str, house_no_punch: bool, bind_ip: &str) -> Self {
        let dir = work_dir(name);
        let mut community = [0u8; 32];
        {
            use rand::RngExt;
            rand::rng().fill(&mut community);
        }
        let community = hex(&community);

        let (gate_seed, _gate_key) = identity(&dir, "gate");
        let (house_seed, house_key) = identity(&dir, "house");
        // Both doctor identities are members from the start: the gate
        // reads its member list once at boot, and a run this test adds
        // later would be refused as a non-member.
        let (caller_seed, caller_key) = identity(&dir, "caller");
        let (second_seed, second_key) = identity(&dir, "second");
        let members = dir.join("members.txt");
        std::fs::write(
            &members,
            format!("{house_key}\n{caller_key}\n{second_key}\n"),
        )
        .unwrap();
        let friends = dir.join("friends.txt");
        std::fs::write(&friends, format!("{caller_key}\n{second_key}\n")).unwrap();
        // Named here so the seeds are on disk before either doctor run
        // asks for them.
        std::fs::write(dir.join("caller.path"), caller_seed.display().to_string()).unwrap();
        std::fs::write(dir.join("second.path"), second_seed.display().to_string()).unwrap();

        let mut gatehouse = Command::new(env!("CARGO_BIN_EXE_mosschat"))
            .args([
                "gatehouse",
                "--bind",
                &format!("{bind_ip}:0"),
                "--secondary-bind",
                &format!("{bind_ip}:0"),
                "--community",
                &community,
                "--identity-file",
                &gate_seed.display().to_string(),
                "--members",
                &members.display().to_string(),
            ])
            .env("HOME", &dir)
            .env("XDG_STATE_HOME", &dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let gate_stdout = gatehouse.stdout.take().unwrap();
        let gatehouse = Process {
            what: "gatehouse",
            child: gatehouse,
        };
        // The gatehouse prints its bound addresses on its second line,
        // which is how anything learns an ephemeral port.
        let gate_lines = Arc::new(Mutex::new(Vec::new()));
        drain(gate_stdout, Arc::clone(&gate_lines));
        let bound = wait_for_line(&gate_lines, Duration::from_secs(20), |line| {
            line.contains("primary=")
        })
        .expect("the gatehouse must print the addresses it bound");
        let gate = bound
            .split("primary=")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .expect("primary=<addr> on the gatehouse's own line")
            .to_string();

        let mut house_args = vec![
            "house".to_string(),
            "--headless".to_string(),
            "--gate".to_string(),
            gate.clone(),
            "--community".to_string(),
            community.clone(),
            "--identity-file".to_string(),
            house_seed.display().to_string(),
            "--friends".to_string(),
            friends.display().to_string(),
        ];
        if house_no_punch {
            house_args.push("--no-punch".to_string());
        }
        let mut house = Command::new(env!("CARGO_BIN_EXE_mosschat"))
            .args(&house_args)
            .env("HOME", &dir)
            .env("XDG_STATE_HOME", &dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let house_stdout = house.stdout.take().unwrap();
        let house = Process {
            what: "house",
            child: house,
        };
        let house_lines = Arc::new(Mutex::new(Vec::new()));
        drain(house_stdout, Arc::clone(&house_lines));
        wait_for_line(&house_lines, Duration::from_secs(20), |line| {
            line.contains("\"event\":\"registered\"")
        })
        .expect("the house must print that it registered");

        Self {
            _gatehouse: gatehouse,
            _house: house,
            house_lines,
            dir,
            community,
            gate,
            house_key,
        }
    }

    /// Runs one `doctor --friend` visit with the given identity and extra
    /// flags, returning its exit status and the record it printed.
    fn doctor(&self, identity: &str, extra: &[&str]) -> (std::process::ExitStatus, DiagRecord) {
        let seed = std::fs::read_to_string(self.dir.join(format!("{identity}.path"))).unwrap();
        let mut args = vec![
            "doctor",
            "--gate",
            &self.gate,
            "--community",
            &self.community,
            "--identity-file",
            seed.trim(),
            "--friend",
            &self.house_key,
            "--json",
        ];
        args.extend_from_slice(extra);
        let out = Command::new(env!("CARGO_BIN_EXE_mosschat"))
            .args(&args)
            .env("HOME", &self.dir)
            .env("XDG_STATE_HOME", &self.dir)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout
            .lines()
            .find(|line| line.starts_with('{'))
            .unwrap_or_else(|| {
                panic!(
                    "doctor printed no record: stdout {stdout:?} stderr {:?}",
                    String::from_utf8_lossy(&out.stderr)
                )
            });
        let record = DiagRecord::from_json_line(line).unwrap();
        (out.status, record)
    }

    /// Kills the gatehouse by its pid and reaps it, which is WO-1.6's
    /// `gatehouse-killed` row in one call.
    fn kill_gatehouse(&mut self) {
        self._gatehouse.child.kill().unwrap();
        let _ = self._gatehouse.child.wait();
    }

    /// Waits up to `within` for the house process to exit, returning its
    /// status.
    fn wait_for_house_exit(&mut self, within: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + within;
        loop {
            match self._house.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                Err(_) => return None,
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Every JSON line the house has printed so far.
    fn house_events(&self) -> Vec<String> {
        self.house_lines
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with('{'))
            .cloned()
            .collect()
    }
}

impl Drop for Community {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The row command WO-1.5 and WO-1.6 run: a real gatehouse, a real
/// headless house, and `doctor --friend <key> --hold <seconds> --json`
/// between them, all from the built binary.
///
/// This is the test that says the harness's long-lived row is runnable at
/// all: before this order the same command opened a visit and abandoned it
/// inside a second, and the gate would have deregistered a house that
/// tried to hold one for 90.
///
/// Deliberate break to fail this test: drop the `if args.hold_s > 0`
/// branch from `run_doctor_steps`, so a held run closes the peer
/// connection at the old deadline. The record comes back with no round
/// trip samples and the `rtt_samples` assertion fails.
#[test]
fn a_held_visit_between_three_processes_measures_and_reports_itself() {
    let community = Community::start("hold", false);
    let (status, record) = community.doctor("caller", &["--hold", "4"]);

    assert!(
        status.success(),
        "a visit that went live exits 0: reason {}, failed step {:?}",
        record.reason.as_str(),
        record.failed_step
    );
    assert!(
        record
            .events
            .iter()
            .any(|event| event.event == VisitEventKind::VisitOpen),
        "the record carries the visit's own events: {:?}",
        record.events
    );
    assert!(
        record.rtt_samples >= 2,
        "a 4 second hold samples the round trip about once a second, not {} times",
        record.rtt_samples
    );
    assert!(
        record.rtt_median_us > 0 && record.rtt_p95_us >= record.rtt_median_us,
        "median {} us, p95 {} us",
        record.rtt_median_us,
        record.rtt_p95_us
    );
    assert!(
        record
            .steps
            .iter()
            .any(|step| step.step == mosschat_net::diag::Step::Live),
        "the visit reached live: {:?}",
        record.steps
    );

    // The house's own account of the same visit, in the same vocabulary.
    let events = community.house_events();
    let names: Vec<&str> = events
        .iter()
        .filter_map(|line| string_field(line, "event"))
        .collect();
    assert!(names.contains(&"registered"), "{names:?}");
    assert!(names.contains(&"knock"), "{names:?}");
    assert!(names.contains(&"visit_open"), "{names:?}");
    for line in &events {
        // Section 7's redaction on every line a house prints.
        if let Some(peer) = string_field(line, "peer") {
            assert_eq!(peer.len(), 8, "a peer is a fingerprint, not a key: {line}");
        }
        assert!(
            number_field(line, "ts_ms").unwrap_or(0) > 0,
            "every line carries the UTC millisecond it happened at: {line}"
        );
    }
}

/// WO-1.5 case (e) from the command line: `--no-punch` on both ends keeps
/// the visit on the relay and the record says so in a word.
///
/// Deliberate break to fail this test: ignore `--no-punch` when building
/// `DoorbellParams` in `run_doctor_steps`. The visit then upgrades and the
/// reason is `ok` rather than `punch_disabled`.
#[test]
fn no_punch_from_the_command_line_stays_relayed_and_says_why() {
    let community = Community::start("nopunch", true);
    let (status, record) = community.doctor("caller", &["--hold", "3", "--no-punch"]);

    assert!(
        status.success(),
        "a relayed visit is a result, not a failure: reason {}",
        record.reason.as_str()
    );
    assert_eq!(record.reason, Reason::PunchDisabled);
    assert!(
        matches!(record.path, PathChoice::Relay(_)),
        "{:?}",
        record.path
    );
    assert_eq!(record.failed_step, None);
    assert!(
        !community
            .house_events()
            .iter()
            .any(|line| string_field(line, "event") == Some("upgraded")),
        "the house upgraded a visit nobody probed"
    );
}

/// Run 3, finding 2 of issue 84: a headless house whose gate is killed
/// says `gate_lost` on its own stdout and exits non-zero, rather than
/// running on as a callee no knock can ever reach.
///
/// This is the silence the run 3 matrix hit. After the `blackout-60s` row,
/// house-b's log stopped dead at that row's `visit_open`: no goodbye, no
/// path event, nothing ever again, and the two rows after it failed at
/// `introduce` against a process that was still running and no longer
/// registered anywhere. A run cannot be allowed to keep measuring against
/// a callee that is gone.
///
/// **It takes about half a minute, and that is the mechanism, not
/// slack.** A killed gatehouse sends no close frame, so the house learns
/// of it through QUIC's own 30 second idle timeout
/// (`live::MAX_IDLE_TIMEOUT`), which is the same way the blackout row's
/// house learned of it. Shortening the wait would test something else.
///
/// Deliberate break to fail this test: delete the `gate_connection.closed()`
/// arm from `house::run`'s select, which is the code this fixes. The house
/// then sits in its loop with nothing to wake it, prints no `gate_lost`,
/// never exits, and both assertions below fail on a house that is, as far
/// as anything can tell, fine.
#[test]
fn a_house_whose_gate_is_killed_says_gate_lost_and_exits_non_zero() {
    let mut community = Community::start("gatelost", false);
    community.kill_gatehouse();

    let lost = wait_for_line(&community.house_lines, Duration::from_secs(60), |line| {
        line.contains("\"event\":\"gate_lost\"")
    })
    .expect("the house must say it lost its gate");
    assert!(
        lost.contains("no longer reachable"),
        "the line says what it means for anyone reading the log: {lost}"
    );

    let status = community
        .wait_for_house_exit(Duration::from_secs(20))
        .expect("the house must leave rather than run on unreachable");
    assert!(
        !status.success(),
        "a run must not be able to keep going against a dead callee: {status:?}"
    );
}

/// This machine's own routed address, the one `punch::local_addresses`
/// gathers and the gate reflects, or `None` on a machine with no route for
/// IPv4 at all.
///
/// The same route lookup the library does, repeated here rather than
/// exported: a `connect`ed UDP socket sends nothing, it only resolves a
/// route, and its local address is the source the kernel would use.
fn routed_ipv4() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let local = socket.local_addr().ok()?;
    if local.ip().is_loopback() || local.ip().is_unspecified() {
        return None;
    }
    Some(local.ip().to_string())
}

/// Run 3, finding 1 of issue 84: two processes on a real address reach a
/// **direct** path, and both say so.
///
/// This is the assertion nothing in this workspace made. Every existing
/// three-process test binds the gate to loopback, where no candidate
/// survives the exchange at all, so a run in which the probe burst answers
/// nothing and the visit relays for its whole hold passed every test and
/// exited 0. Twelve fault-matrix rows on a real two-NAT lab then did
/// exactly that, twelve times, and the matrix reported success.
///
/// What this covers is section 2 steps 4 to 6 end to end between separate
/// processes: the gate fires both sides, each probes the address the gate
/// reflected for the other, and the first to answer three consecutive
/// probes wins. It does not cover a NAT, which needs the harness.
///
/// Deliberate break to fail this test: in `Attempt::add_candidate`, drop
/// the `|| self.vouched.contains(&addr)` from the peer-reported check. The
/// peer's reflected private address is then refused, the table is empty,
/// and the record comes back relayed with `no_candidates` rather than
/// direct. That is the shape of every row of run 3.
#[test]
fn two_processes_on_a_routed_address_upgrade_to_a_direct_path() {
    let Some(bind_ip) = routed_ipv4() else {
        panic!(
            "this test needs one routed IPv4 address to bind the gate to; a machine with no \
             default route cannot punch a hole to itself and cannot run it"
        );
    };
    let community = Community::start_on("direct", false, &bind_ip);
    let (status, record) = community.doctor("caller", &["--hold", "4"]);

    assert!(
        status.success(),
        "reason {}, failed step {:?}",
        record.reason.as_str(),
        record.failed_step
    );
    assert!(
        matches!(record.path, PathChoice::Direct(_)),
        "the visit must end on a direct path, not the relay: reason {}, steps {:?}",
        record.reason.as_str(),
        record.steps
    );
    assert_eq!(
        record.reason,
        Reason::Ok,
        "a visit that upgraded and kept its path has nothing to explain: {:?}",
        record.steps
    );
    assert!(
        record
            .events
            .iter()
            .any(|event| event.event == VisitEventKind::Upgraded),
        "the caller records the upgrade as an event: {:?}",
        record.events
    );
    assert!(
        community
            .house_events()
            .iter()
            .any(|line| string_field(line, "event") == Some("upgraded")),
        "the callee upgraded too, which is what makes the path direct in both directions: {:?}",
        community.house_events()
    );
}
