use std::mem::MaybeUninit;
use std::time::Duration;

use anyhow::bail;
use clap::Parser;

mod tap {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/interface_tap.skel.rs"));
}
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{AsRawLibbpf, MapCore, PerfBufferBuilder, RingBufferBuilder};
use tap::*;

#[derive(Parser)]
struct Commands {
    #[arg(short = 'i')]
    iface: String,
}

// TODO: WHYYYY
fn bump_memlock_rlimit() -> anyhow::Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    //let args = Commands::parse();
    bump_memlock_rlimit()?;   

    let mut open_object = MaybeUninit::uninit();
    let mut skel = InterfaceTapSkelBuilder::default().open(&mut open_object)?.load()?;

    skel.attach()?;

    let perf_map = skel.maps.perf_map;

    let perf_buffer = PerfBufferBuilder::new(&perf_map)
        .sample_cb(|_cpu: i32, data: &[u8]| {
            dbg!(data);
        })
        .build()?;

    loop {
        perf_buffer.poll(Duration::from_millis(100))?;
    }
}
