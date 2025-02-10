use std::mem::MaybeUninit;
use std::time::Duration;

use anyhow::bail;
use clap::Parser;

mod tap {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/interface_tap.skel.rs"));
}
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use tap::*;

#[derive(Parser)]
struct Commands {
    #[arg(short = 'i')]
    iface: i32,
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
    let args = Commands::parse();
    bump_memlock_rlimit()?;   

    let mut open_object = MaybeUninit::uninit();
    let mut skel = InterfaceTapSkelBuilder::default().open(&mut open_object)?.load()?;
    let link = skel.progs.read_from_interface.attach_xdp(args.iface)?;
    skel.links = InterfaceTapLinks {
        read_from_interface: Some(link),
    };

    skel.attach()?;

    let ring_buf = skel.maps.ringbuf;

    let mut ring_buf_builder = RingBufferBuilder::new();

    ring_buf_builder.add(&ring_buf, |bytes: &[u8]| -> i32 {
        dbg!(bytes);
        0
    })?;

    let ring_buffer = ring_buf_builder.build()?;

    loop {
        ring_buffer.poll(Duration::from_millis(100))?;
    }
}
