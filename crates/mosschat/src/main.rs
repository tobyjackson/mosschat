//! The mosschat binary: one artefact, three roles (D1). Plain `mosschat` starts the
//! house if needed and attaches the terminal client; `mosschat --headless` runs the
//! house alone so a machine can stay home with no window open; the same binary can also
//! run the gatehouse role for a community. Nothing here yet: this crate depends on the
//! four library crates and will wire the CLI, the house lifecycle and the client
//! attachment in later work orders.

#![forbid(unsafe_code)]

fn main() {
    println!("mosschat: workspace scaffold, no roles wired up yet");
}
