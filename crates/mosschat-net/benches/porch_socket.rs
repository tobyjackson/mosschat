//! The reversing-condition benchmark of `docs/dev/gatehouse-design.md`
//! section 3, half (b), measured in WO-1.3a as the design requires: does the
//! porch socket add more than 20 microseconds at the median per received
//! datagram against a plain tokio socket? Custom harness (`harness = false`)
//! rather than a criterion dependency, since criterion is not a crate the
//! design names and this needs nothing beyond "time N receives, take the
//! median" (`Instant`, sorting, no statistics library).
//!
//! Run: `cargo bench -p mosschat-net --bench porch_socket`. The committed
//! run's output lives at `docs/measurements/2026-09-07-porch-socket-bench.txt`.

#![forbid(unsafe_code)]

use std::error::Error;
use std::io::IoSliceMut;
use std::net::UdpSocket as StdUdpSocket;
use std::time::{Duration, Instant};

use mosschat_net::sock::PorchSocket;
use quinn::AsyncUdpSocket;
use quinn::udp::RecvMeta;

const ITERATIONS: usize = 2000;
const PAYLOAD: &[u8] = b"mosschat porch socket benchmark payload, sixty-four bytes long!";

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    #[allow(clippy::indexing_slicing)]
    let mid = samples.len() / 2;
    samples.get(mid).copied().unwrap_or(Duration::ZERO)
}

async fn bench_plain_tokio_socket() -> Result<Duration, Box<dyn Error>> {
    let sender = StdUdpSocket::bind("127.0.0.1:0")?;
    let receiver_std = StdUdpSocket::bind("127.0.0.1:0")?;
    receiver_std.set_nonblocking(true)?;
    let receiver_addr = receiver_std.local_addr()?;
    let receiver = tokio::net::UdpSocket::from_std(receiver_std)?;

    let mut samples = Vec::with_capacity(ITERATIONS);
    let mut buf = [0u8; 1500];
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        sender.send_to(PAYLOAD, receiver_addr)?;
        let _ = receiver.recv_from(&mut buf).await?;
        samples.push(start.elapsed());
    }
    Ok(median(samples))
}

async fn bench_porch_socket() -> Result<Duration, Box<dyn Error>> {
    let sender = StdUdpSocket::bind("127.0.0.1:0")?;
    let receiver_std = StdUdpSocket::bind("127.0.0.1:0")?;
    let receiver_addr = receiver_std.local_addr()?;
    let porch = PorchSocket::new(receiver_std)?;

    let mut samples = Vec::with_capacity(ITERATIONS);
    let mut buf = [0u8; 1500];
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        sender.send_to(PAYLOAD, receiver_addr)?;
        std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            let mut meta = [RecvMeta::default()];
            porch.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await?;
        samples.push(start.elapsed());
    }
    Ok(median(samples))
}

fn main() -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    let plain_median = rt.block_on(bench_plain_tokio_socket())?;
    let porch_median = rt.block_on(bench_porch_socket())?;
    let delta =
        i128::try_from(porch_median.as_micros())? - i128::try_from(plain_median.as_micros())?;

    println!("plain tokio socket recv median: {plain_median:?} ({ITERATIONS} iterations)");
    println!("porch socket recv median:       {porch_median:?} ({ITERATIONS} iterations)");
    println!("delta (porch - plain):           {delta} microseconds");
    println!(
        "reversing condition (b) [{}]: porch socket adds {} 20 microseconds at the median",
        if delta > 20 { "TRIPPED" } else { "held" },
        if delta > 20 {
            "more than"
        } else {
            "no more than"
        }
    );
    Ok(())
}
