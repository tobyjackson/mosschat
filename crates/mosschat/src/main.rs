//! The mosschat binary: one artefact, three roles (D1). Plain `mosschat` starts the
//! house if needed and attaches the terminal client; `mosschat --headless` runs the
//! house alone so a machine can stay home with no window open; the same binary can also
//! run the gatehouse role for a community. The house and client roles land in later work
//! orders; `gatehouse` (WO-1.3a) is the first role wired here.

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
        _ => {
            println!(
                "mosschat: workspace scaffold; only the `gatehouse` role is wired up (WO-1.3a)"
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
                "--identity" => identity_seed = Some(decode_hex32(&value()?)?),
                other => return Err(format!("unknown flag {other}")),
            }
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

    println!(
        "mosschat gatehouse: community={} identity={}",
        hex(&args.community),
        hex(&mosschat_core::identity::AuthorKey::from_bytes(&identity_seed).public_bytes())
    );
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
