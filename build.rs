use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const BPF_PROGRAM_SRC_PATH: &'static str = "src/bpf/interface_tap.bpf.c";
const GENERATED_SKEL_OUTPUT_PATH: &'static str = "src/bpf/interface_tap.skel.rs";

fn main() {
    let cargo_manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set in build script");

    let generated_skel_output_path =
        PathBuf::from(cargo_manifest_dir).join(GENERATED_SKEL_OUTPUT_PATH);

    let cargo_config_target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(BPF_PROGRAM_SRC_PATH)
        .clang_args([
            OsStr::new("-g"),
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&cargo_config_target_arch).as_os_str(),
        ])
        .build_and_generate(&generated_skel_output_path)
        .unwrap();

    println!("cargo:rerun-if-changed={BPF_PROGRAM_SRC_PATH}");
}
