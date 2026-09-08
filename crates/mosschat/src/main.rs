//! The mosschat binary: one artefact, three roles (D1). Plain `mosschat` starts the
//! house if needed and attaches the terminal client; `mosschat --headless` runs the
//! house alone so a machine can stay home with no window open; the same binary can also
//! run the gatehouse role for a community. The house and client roles land in later work
//! orders; `gatehouse` (WO-1.3a) is the first role wired here, and `doctor` (WO-1.4b,
//! `docs/dev/gatehouse-design.md` section 7) the first command.

#![forbid(unsafe_code)]

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("gatehouse") => {
            if let Err(err) = run_gatehouse(args) {
                eprintln!("mosschat gatehouse: error: {err}");
                std::process::exit(1);
            }
        }
        Some("doctor") => {
            if let Err(err) = run_doctor(args) {
                eprintln!("mosschat doctor: error: {err}");
                std::process::exit(1);
            }
        }
        _ => {
            println!(
                "mosschat: workspace scaffold; the `gatehouse` role (WO-1.3a) and `doctor` \
                 (WO-1.4b) are wired up"
            );
        }
    }
}

struct GatehouseArgs {
    community: [u8; 32],
    members: PathBuf,
    primary_bind: std::net::SocketAddr,
    secondary_bind: std::net::SocketAddr,
    identity_seed: Option<[u8; 32]>,
}

impl GatehouseArgs {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut community = None;
        let mut members = None;
        let mut primary_bind = None;
        let mut secondary_bind = None;
        let mut identity_seed = None;
        let mut identity_arg_given = false;
        let mut identity_file_given = false;
        let mut it = args;
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--community" => community = Some(decode_hex32(&value()?)?),
                "--members" => members = Some(PathBuf::from(value()?)),
                "--bind" => {
                    primary_bind = Some(
                        value()?
                            .parse()
                            .map_err(|_| "bad --bind address".to_string())?,
                    );
                }
                "--secondary-bind" => {
                    secondary_bind = Some(
                        value()?
                            .parse()
                            .map_err(|_| "bad --secondary-bind address".to_string())?,
                    );
                }
                // Yseult finding 9: a `--identity <hex>` value is visible to
                // any local user via `ps`. `--identity-file` is the
                // preferred form: the seed never touches argv, only a file
                // this process reads once. `--identity` stays for scripts
                // and tests that already depend on it; a real deployment
                // should prefer the file form.
                "--identity" => {
                    identity_arg_given = true;
                    identity_seed = Some(decode_hex32(&value()?)?);
                }
                "--identity-file" => {
                    identity_file_given = true;
                    let path = value()?;
                    let contents = std::fs::read_to_string(&path)
                        .map_err(|e| format!("reading --identity-file {path:?}: {e}"))?;
                    identity_seed = Some(decode_hex32(contents.trim())?);
                }
                other => return Err(format!("unknown flag {other}")),
            }
        }
        if identity_arg_given && identity_file_given {
            return Err("--identity and --identity-file are mutually exclusive".into());
        }
        Ok(Self {
            community: community.ok_or("--community <64 hex chars> is required")?,
            members: members.ok_or("--members <path> is required")?,
            primary_bind: primary_bind
                .unwrap_or_else(|| "0.0.0.0:443".parse().unwrap_or_else(|_| unreachable_addr())),
            secondary_bind: secondary_bind
                .unwrap_or_else(|| "0.0.0.0:444".parse().unwrap_or_else(|_| unreachable_addr())),
            identity_seed,
        })
    }
}

/// A fallback that only runs if the hardcoded default literal above somehow
/// fails to parse, which it cannot; kept so the `unwrap_or_else` branch has
/// no `unwrap`/`expect` in it (invariant 1) rather than asserting the
/// literal is infallible by fiat.
fn unreachable_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
}

fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let chunk = s.get(i * 2..i * 2 + 2).ok_or("hex string ended early")?;
        *byte = u8::from_str_radix(chunk, 16).map_err(|_| format!("{chunk:?} is not hex"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run_gatehouse(args: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = GatehouseArgs::parse(args)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(serve_gatehouse(parsed))
}

async fn serve_gatehouse(args: GatehouseArgs) -> Result<(), Box<dyn std::error::Error>> {
    use rand::RngExt;

    let members = mosschat_net::gate::MemberList::load(&args.members)?;
    let identity_seed = args.identity_seed.unwrap_or_else(|| rand::rng().random());

    let config = mosschat_net::gate::server::GateServerConfig {
        community: args.community,
        identity_seed,
        members,
        primary_bind: args.primary_bind,
        secondary_bind: args.secondary_bind,
        max_registrations: mosschat_net::gate::limits::MAX_REGISTRATIONS,
    };
    let server = mosschat_net::gate::server::GateServer::bind(config)?;

    // Section 1: "Its stdout carries counts and error codes, never a key,
    // an address or a payload byte." The community id is a shared,
    // non-secret configuration value (every member already holds it), but
    // the gate's own identity key is not printed here.
    println!("mosschat gatehouse: community={}", hex(&args.community));
    println!(
        "mosschat gatehouse: primary={} secondary={}",
        server.primary_addr(),
        server.secondary_addr()
    );

    #[cfg(unix)]
    {
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = hangup.recv() => {
                    match server.reload_members(&args.members) {
                        Ok(()) => println!("mosschat gatehouse: member list reloaded"),
                        Err(err) => eprintln!("mosschat gatehouse: member list reload failed: {err}"),
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }
    Ok(())
}

// ----------------------------------------------------------------------
// `mosschat doctor` (WO-1.4b, gatehouse design section 7)
// ----------------------------------------------------------------------

/// How long `doctor` waits for a gate's QUIC handshake before calling the
/// gate unreachable. Chosen, not measured: the gate is one round trip plus
/// a handshake away on a working path, and 10 s is section 2's own probe
/// give-up, the longest this design waits for anything else.
const DIAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// What `doctor` was asked to check.
struct DoctorArgs {
    /// The gate to run the steps against, as given on the command line
    /// (`host:port`), resolved at dial time.
    gate: Option<String>,
    community: Option<[u8; 32]>,
    identity_seed: Option<[u8; 32]>,
    gate_key: Option<[u8; 32]>,
    /// The friend to reach: their 64 hex character public key, or, with
    /// `--last`, the 8 hex character fingerprint the log names them by.
    friend: Option<String>,
    json: bool,
    last: bool,
}

impl DoctorArgs {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut parsed = Self {
            gate: None,
            community: None,
            identity_seed: None,
            gate_key: None,
            friend: None,
            json: false,
            last: false,
        };
        let mut identity_arg_given = false;
        let mut identity_file_given = false;
        let mut it = args;
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--gate" => parsed.gate = Some(value()?),
                "--community" => parsed.community = Some(decode_hex32(&value()?)?),
                "--gate-key" => parsed.gate_key = Some(decode_hex32(&value()?)?),
                "--friend" => parsed.friend = Some(value()?),
                // Same rule as the gatehouse role: a seed on the command
                // line is visible to any local user through `ps`, so the
                // file form is the preferred one (Yseult finding 9).
                "--identity" => {
                    identity_arg_given = true;
                    parsed.identity_seed = Some(decode_hex32(&value()?)?);
                }
                "--identity-file" => {
                    identity_file_given = true;
                    let path = value()?;
                    let contents = std::fs::read_to_string(&path)
                        .map_err(|e| format!("reading --identity-file {path:?}: {e}"))?;
                    parsed.identity_seed = Some(decode_hex32(contents.trim())?);
                }
                "--json" => parsed.json = true,
                "--last" => parsed.last = true,
                other => return Err(format!("unknown flag {other}")),
            }
        }
        if identity_arg_given && identity_file_given {
            return Err("--identity and --identity-file are mutually exclusive".into());
        }
        if !parsed.last {
            if parsed.gate.is_none() {
                return Err("--gate <host:port> is required".into());
            }
            if parsed.community.is_none() {
                return Err("--community <64 hex chars> is required".into());
            }
        }
        Ok(parsed)
    }
}

/// Resolves `--friend` to the fingerprint the log names that peer by:
/// either 64 hex characters (a public key, hashed with this install's
/// salt) or the 8 hex characters of the fingerprint itself.
///
/// Section 7 has `doctor` take `--friend <name>`; there is no contact store
/// to resolve a name against before Phase 2 (D6), so a key or a fingerprint
/// is what a name would have resolved to.
fn friend_fingerprint(
    friend: &str,
    salt: &mosschat_net::diag::InstallSalt,
) -> Result<mosschat_net::diag::PeerFingerprint, String> {
    match friend.len() {
        64 => Ok(mosschat_net::diag::PeerFingerprint::from_key(
            salt,
            &decode_hex32(friend)?,
        )),
        8 => mosschat_net::diag::PeerFingerprint::from_hex(friend)
            .map_err(|e| format!("bad --friend fingerprint: {e}")),
        _ => Err(
            "--friend takes 64 hex characters (a public key) or 8 (the fingerprint the log uses)"
                .to_string(),
        ),
    }
}

fn run_doctor(args: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = DoctorArgs::parse(args)?;
    let dir = mosschat_net::diag::host_diagnostics_dir()?;
    let salt = mosschat_net::diag::InstallSalt::load_or_create(&dir)?;

    if parsed.last {
        let peer = match parsed.friend.as_deref() {
            Some(friend) => Some(friend_fingerprint(friend, &salt)?),
            None => None,
        };
        let Some(record) = mosschat_net::diag::last_record(&dir, peer)? else {
            // The directory is a path under the user's home, so it is not
            // repeated back into output meant to be pasted (Yseult's Low).
            eprintln!("mosschat doctor: no diagnostics record for that peer yet");
            std::process::exit(1);
        };
        print_record(&record, parsed.json);
        // `--last` reports what the log says, so a record of a failed
        // attempt exits non-zero exactly as running that attempt would.
        exit_for(&record);
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let record = runtime.block_on(run_doctor_steps(&parsed, dir, salt))?;
    print_record(&record, parsed.json);
    exit_for(&record);
}

/// Prints `record` in the form `--json` asked for.
fn print_record(record: &mosschat_net::diag::DiagRecord, json: bool) {
    if json {
        // The JSON form is the one most likely pasted verbatim into an
        // issue, so the notice goes out beside it rather than not at all
        // (Yseult's Low on PR #49). On stderr, so `--json`'s stdout stays
        // exactly one JSON object.
        eprintln!("{}", mosschat_net::diag::PRIVACY_NOTICE);
        println!("{}", record.to_json_line());
    } else {
        print!("{}", record.to_human_report());
    }
}

/// Exits 0 when the attempt got as far as it was asked to get, and 1
/// naming the first failed step otherwise.
///
/// Section 7 says "exit 0 only if it reached `live`", which is the rule for
/// a `--friend` run. A `--gate` run has no peer and so can never reach
/// `live`; for it the rule is the same one read as far as it goes, every
/// step it ran having succeeded.
fn exit_for(record: &mosschat_net::diag::DiagRecord) -> ! {
    match record.failed_step {
        Some(step) => {
            eprintln!("mosschat doctor: failed at step {}", step.as_str());
            std::process::exit(1);
        }
        None => std::process::exit(0),
    }
}

/// Runs the steps of section 7 for real and returns the record they
/// produced, written to the diagnostics log by the recorder itself.
async fn run_doctor_steps(
    args: &DoctorArgs,
    dir: std::path::PathBuf,
    salt: mosschat_net::diag::InstallSalt,
) -> Result<mosschat_net::diag::DiagRecord, Box<dyn std::error::Error>> {
    use mosschat_net::diag::{PeerFingerprint, Reason, Recorder, Step, StepOutcome};
    use rand::RngExt;

    let friend_key = match args.friend.as_deref() {
        Some(friend) => Some(decode_hex32(friend)?),
        None => None,
    };
    // A gate-only run names no peer, so its record's peer field is the
    // all-zero fingerprint: a value no key hashes to in practice, and the
    // record's `steps` say plainly that no peer was attempted.
    let peer = friend_key.map_or_else(PeerFingerprint::default, |key| {
        PeerFingerprint::from_key(&salt, &key)
    });
    let sink = mosschat_net::diag::DiagSink::new(dir)?;
    let recorder = Recorder::new(peer, Some(sink));

    let gate_arg = args.gate.clone().unwrap_or_default();
    let gate_addr = match resolve_one(&gate_arg) {
        Ok(addr) => addr,
        Err(e) => {
            // Section 7: "which cannot be told from 'the gate is down'
            // without a second gate or a TCP probe, so the `detail` says so
            // rather than pretending otherwise". A name that does not
            // resolve at all is not that case, and says so too.
            mosschat_net::diag::record(
                Some(&recorder),
                Step::GateDial,
                StepOutcome::Fail,
                format!("{gate_arg} did not resolve: {e}"),
            );
            let (record, _) = recorder.finish(Reason::GateUnreachable);
            return Ok(record);
        }
    };

    let identity_seed = args.identity_seed.unwrap_or_else(|| rand::rng().random());
    let community = args.community.unwrap_or_default();
    let friends = std::sync::Arc::new(mosschat_net::gate::client::InMemoryFriendStore::new());
    if let Some(key) = friend_key {
        friends.add(key);
    }
    let invites = std::sync::Arc::new(mosschat_net::gate::client::InMemoryInviteStore::new());

    // A deadline of `doctor`'s own, because the dial itself has none:
    // section 5 puts a deadline on every stream read, and the gate client
    // has one everywhere it reads a frame, but a QUIC handshake to a host
    // that never answers ends only at the idle timeout. A doctor that does
    // not return is not a doctor, so an unreachable gate is reported here
    // after `DIAL_DEADLINE` rather than waited out.
    let dialled = tokio::time::timeout(
        DIAL_DEADLINE,
        mosschat_net::gate::client::GateClient::connect_with_recorder(
            gate_addr,
            identity_seed,
            community,
            args.gate_key,
            friends,
            invites,
            Some(recorder.clone()),
        ),
    )
    .await;
    let dialled = match dialled {
        Ok(dialled) => dialled,
        Err(_) => {
            mosschat_net::diag::record(
                Some(&recorder),
                Step::GateDial,
                StepOutcome::Fail,
                format!(
                    "no answer from {gate_addr} in {} s; a gate that answers on neither port \
                     cannot be told from UDP being blocked without a second gate or a TCP probe",
                    DIAL_DEADLINE.as_secs()
                ),
            );
            let (record, written) = recorder.finish(Reason::GateUnreachable);
            report_write(written);
            return Ok(record);
        }
    };
    let client = match dialled {
        Ok(client) => client,
        Err(err) => {
            // Where `connect` recorded the step that failed, nothing is
            // recorded a second time (Konrad's should 4: a refusal printed
            // two failure lines, the second carrying UDP-blocked wording
            // that did not apply), and this only chooses the record's
            // reason: the one the gate itself named through frame 12's
            // code where there is one, and otherwise what the failed step
            // says.
            //
            // Where it recorded nothing, the step that was in flight is
            // recorded here with the error's own text. A connect that
            // returns an error must never leave `failed_step` null: that
            // is what made `exit_for` exit **0** on nine rows of the
            // 2026-09-08 fault matrix, every one of them a doctor that
            // dialled its gate and then failed to register.
            let reason = if let Some(hint) = recorder.reason_hint() {
                hint
            } else if let Some(step) = recorder.failed_step() {
                match step {
                    Step::GateDial => Reason::GateUnreachable,
                    _ => Reason::Internal,
                }
            } else {
                // No step recorded at all means the dial never got off the
                // ground (the endpoint, its socket or the certificate); a
                // recorded step means the dial succeeded and this
                // connection was in the middle of registering. Section 7
                // names no reason for "the gate closed the connection
                // without saying why", so it stays `internal`, section 7's
                // own stated catch-all, with the step and the error's text
                // carrying what actually happened.
                let in_flight = match recorder.last_step() {
                    None => Step::GateDial,
                    Some(_) => Step::GateRegister,
                };
                mosschat_net::diag::record(
                    Some(&recorder),
                    in_flight,
                    StepOutcome::Fail,
                    err.to_string(),
                );
                Reason::Internal
            };
            let (record, written) = recorder.finish(reason);
            report_write(written);
            return Ok(record);
        }
    };

    // Section 7's second observation, off the gate's secondary port: the
    // pair of reflections is what the mapping is inferred from.
    let secondary = std::net::SocketAddr::new(gate_addr.ip(), client.registered_secondary_port());
    let reflected_ok = client.reflect(secondary).await.is_ok();

    let Some(friend_key) = friend_key else {
        // A gate-only run stops here: there is no peer to introduce, and
        // the mapping is the answer it came for.
        let reason = gate_only_reason(reflected_ok, recorder.reason_hint());
        deregister(&client).await;
        let (record, written) = recorder.finish(reason);
        report_write(written);
        return Ok(record);
    };

    // Held behind an `Arc` from here so the doorbell task can own a handle
    // and this function keeps one to say goodbye with: every exit from a
    // `doctor` run deregisters, on the friend path as much as the gate-only
    // one.
    let client = std::sync::Arc::new(client);

    let introduced = client.introduce(friend_key, 30, None).await;
    if introduced.is_err() {
        deregister(&client).await;
        let (record, written) = recorder.finish(Reason::IntroduceTimeout);
        report_write(written);
        return Ok(record);
    }
    let peer_connection = match client.dial_peer(&friend_key).await {
        Ok(connection) => connection,
        Err(_) => {
            deregister(&client).await;
            let (record, written) = recorder.finish(Reason::PeerHandshakeFailed);
            report_write(written);
            return Ok(record);
        }
    };

    let session = introduced
        .map(|outcome| outcome.session)
        .unwrap_or_default();
    let control = mosschat_net::punch::DoorbellControl::new();
    // Section 2 step 1: every non-loopback local address plus the gate's
    // reflection of this house, de-duplicated and capped at 16.
    let local_port = client.local_port().unwrap_or_default();
    let local = mosschat_net::punch::local_addresses(local_port);
    let reflections = [client.registered_observed()];
    let candidates: Vec<std::net::SocketAddr> =
        mosschat_net::punch::gather(&local, &reflections, &[])
            .into_iter()
            .map(|(addr, _source)| addr)
            .collect();
    let params = mosschat_net::punch::DoorbellParams {
        session,
        role: 1,
        peer_key: friend_key,
        candidates,
        peer_observed: client.peer_observed_for(session),
        peer_discovered: Vec::new(),
        recorder: Some(recorder.clone()),
    };
    let porch = client.porch();
    // The doorbell owns the attempt from here: it records every step from
    // the candidate exchange to the upgrade, and settles the record
    // whichever way the attempt ends.
    let doorbell = {
        let porch_for_task = porch.clone();
        let client_for_task = std::sync::Arc::clone(&client);
        let peer_connection = peer_connection.clone();
        tokio::spawn(async move {
            mosschat_net::punch::run_doorbell(
                &porch_for_task,
                &client_for_task,
                &peer_connection,
                params,
                &control,
            )
            .await
        })
    };

    // Section 2 step 5's own deadline: 3 s fast plus 7 s slow, after which
    // every candidate is given up. Waiting past it would report the wrong
    // failure; waiting less would report a failure that had not happened.
    let upgraded = tokio::time::timeout(
        mosschat_net::punch::PROBE_GIVE_UP + std::time::Duration::from_secs(2),
        async {
            loop {
                if porch
                    .path_for(&friend_key)
                    .and_then(|path| path.direct_addr())
                    .is_some()
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        },
    )
    .await
    .is_ok();

    // Closing the peer connection is what ends the attempt: `run_doorbell`
    // records `closed`, reads the shaper counters and writes the record.
    peer_connection.close(0u32.into(), b"doctor done");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), doorbell).await;

    let reason = if upgraded {
        Reason::Ok
    } else {
        recorder.probe_failure_reason()
    };
    deregister(&client).await;
    let (record, written) = recorder.finish(reason);
    report_write(written);
    Ok(record)
}

/// The `Goodbye.reason` a finished `doctor` run sends. The frame carries a
/// `u8` and section 1 defines no enum of values for it, so 0 is the plain
/// clean exit, the value every caller in the workspace already uses.
const GOODBYE_DOCTOR_DONE: u8 = 0;

/// Deregisters at the gate, which is what ends a `doctor` run cleanly.
///
/// Section 1 has `Goodbye` "deregistering at once" and section 4 makes it
/// the clean exit's own frame. Without it a run leaves its registration
/// seated at the gate: [`exit_for`] ends the process through
/// `std::process::exit`, which runs no destructor, so nothing closes the
/// QUIC connection and the gate holds the slot until quinn's 30 s idle
/// timeout expires it. Section 1's per-key sub-cap is two live connections,
/// so a third run inside that window was refused `gate_at_capacity` before
/// it could register: rows 3 to 10 of the 2026-09-08 fault matrix, one
/// after another, none of them caused by the fault its row was applying.
///
/// The error is deliberately ignored. The run's result is already decided
/// by the time this is called, and a gate that has gone away cannot be said
/// goodbye to; section 4 calls a goodbye a courtesy whose absence the peer
/// is entitled to handle.
async fn deregister(client: &mosschat_net::gate::client::GateClient) {
    let _ = client.goodbye(GOODBYE_DOCTOR_DONE).await;
}

/// The reason a `--gate` run ends with, given whether the secondary port
/// answered and any reason the gate named while refusing it.
///
/// A secondary port that did not answer is **not** `udp_blocked` (Konrad's
/// must 2 on PR #49): section 7 defines that reason as neither gate port
/// being reachable, and a run that reaches this point registered on the
/// primary.
///
/// `named_by_gate` is the gate's own answer where it gave one, which is the
/// difference between a report saying `gate_rate_limited` and one saying
/// nothing useful: the secondary port refuses an over-rate `Reflect` by
/// closing, and the close carries section 7's code. Section 7 names no
/// reason for one port of two failing on its own, so without one it stays
/// `internal`, its own stated catch-all, with the `reflect_secondary` step
/// saying what failed and the mapping staying `unknown`, which is all one
/// reflection can prove.
fn gate_only_reason(
    reflected_ok: bool,
    named_by_gate: Option<mosschat_net::diag::Reason>,
) -> mosschat_net::diag::Reason {
    if reflected_ok {
        mosschat_net::diag::Reason::Ok
    } else {
        named_by_gate.unwrap_or(mosschat_net::diag::Reason::Internal)
    }
}

/// Says so on stderr when the record could not be written, rather than
/// letting a `doctor` run look like it filed a report it did not file.
fn report_write(written: Result<(), mosschat_net::diag::DiagError>) {
    if let Err(e) = written {
        eprintln!("mosschat doctor: the diagnostics record could not be written: {e}");
    }
}

/// Resolves `host:port` to one socket address, accepting a literal address
/// unchanged.
fn resolve_one(target: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    target
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("{target} resolved to no address"))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    /// Konrad's must 2: one port of two failing is not section 7's
    /// `udp_blocked`, which means neither port was reachable.
    ///
    /// Deliberate break to fail this test: return
    /// `mosschat_net::diag::Reason::UdpBlocked` from `gate_only_reason`'s
    /// else arm, which is what this code did.
    #[test]
    fn a_failed_secondary_reflection_is_not_udp_blocked() {
        assert_eq!(gate_only_reason(true, None), mosschat_net::diag::Reason::Ok);
        assert_eq!(
            gate_only_reason(false, None),
            mosschat_net::diag::Reason::Internal
        );
        assert_ne!(
            gate_only_reason(false, None),
            mosschat_net::diag::Reason::UdpBlocked
        );
    }

    /// A gate that named its refusal is reported by that name, not as
    /// `internal`: the secondary port refuses an over-rate `Reflect` by
    /// closing with section 7's `gate_rate_limited` code, and a record
    /// saying `internal` for a refusal the gate spelled out is the
    /// untruthful half of the 2026-09-08 fault matrix's exit-0 bug.
    ///
    /// Deliberate break to fail this test: drop the `named_by_gate`
    /// parameter and return `Reason::Internal` for every failed
    /// reflection, which is what this code did.
    #[test]
    fn a_reason_the_gate_named_survives_into_the_record() {
        assert_eq!(
            gate_only_reason(false, Some(mosschat_net::diag::Reason::GateRateLimited)),
            mosschat_net::diag::Reason::GateRateLimited
        );
        // A successful reflection is `ok` whatever else was hinted.
        assert_eq!(
            gate_only_reason(true, Some(mosschat_net::diag::Reason::GateRateLimited)),
            mosschat_net::diag::Reason::Ok
        );
    }
}
