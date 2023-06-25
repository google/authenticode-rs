// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use clap::{Parser, Subcommand};
use command_run::Command;
use fs_err as fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    GenerateTestData,
}

#[derive(Clone, Copy)]
enum Bitness {
    B32,
    B64,
}

impl Bitness {
    fn as_num(self) -> u8 {
        match self {
            Bitness::B32 => 32,
            Bitness::B64 => 64,
        }
    }

    fn target(self) -> &'static str {
        match self {
            Bitness::B32 => "i686-unknown-uefi",
            Bitness::B64 => "x86_64-unknown-uefi",
        }
    }
}

struct Paths {
    test_data: PathBuf,
}

impl Paths {
    fn new() -> Self {
        Self {
            test_data: PathBuf::from("authenticode/tests/testdata"),
        }
    }

    fn unsigned_exe(&self, bitness: Bitness) -> PathBuf {
        self.test_data.join(format!("tiny{}.efi", bitness.as_num()))
    }

    fn signed_exe(&self, bitness: Bitness) -> PathBuf {
        self.test_data
            .join(format!("tiny{}.signed.efi", bitness.as_num()))
    }

    fn private_pem(&self) -> PathBuf {
        self.test_data.join("test_key_private.pem")
    }

    fn public_pem(&self) -> PathBuf {
        self.test_data.join("test_key_public.pem")
    }
}

fn generate_keys(paths: &Paths) {
    if paths.private_pem().exists() && paths.public_pem().exists() {
        println!("skipping key generation");
        return;
    }

    #[rustfmt::skip]
    Command::with_args("openssl", [
        "req", "-x509",
        "-newkey", "rsa:2048",
        "-subj", "/CN=TestKey/",
        // Turn off encryption so no password is needed.
        "-nodes",
    ])
    .add_arg_pair("-keyout", paths.private_pem())
    .add_arg_pair("-out", paths.public_pem())
    .run()
    .unwrap();
}

fn build_exe(root_path: &Path, bitness: Bitness) {
    Command::with_args(
        "cargo",
        [
            "build",
            "--release",
            "--target",
            bitness.target(),
            "--manifest-path",
        ],
    )
    .add_arg(root_path.join("Cargo.toml"))
    .run()
    .unwrap();
}

fn generate_tiny_pe_exe(paths: &Paths, bitness: Bitness) {
    if paths.unsigned_exe(bitness).exists()
        && paths.signed_exe(bitness).exists()
    {
        println!("skipping exe-{} generation", bitness.as_num());
        return;
    }

    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();

    // Generate a small UEFI project.
    Command::with_args("cargo", ["init", "--bin", "--name", "tiny"])
        .add_arg(tmp_path)
        .run()
        .unwrap();
    fs::write(
        tmp_path.join("src/main.rs"),
        include_str!("tiny_uefi_main.rs"),
    )
    .unwrap();

    // Build it.
    build_exe(tmp_path, bitness);

    // Copy to the test data directory.
    fs::copy(
        tmp_path
            .join("target")
            .join(bitness.target())
            .join("release/tiny.efi"),
        paths.unsigned_exe(bitness),
    )
    .unwrap();

    // Create a signed copy.
    Command::new("sbsign")
        .add_arg_pair("--cert", paths.public_pem())
        .add_arg_pair("--key", paths.private_pem())
        .add_arg_pair("--output", paths.signed_exe(bitness))
        .add_arg(paths.unsigned_exe(bitness))
        .run()
        .unwrap();
}

fn generate_test_data() {
    let paths = Paths::new();
    generate_keys(&paths);
    generate_tiny_pe_exe(&paths, Bitness::B32);
    generate_tiny_pe_exe(&paths, Bitness::B64);
}

fn main() {
    let cli = Cli::parse();

    match &cli.action {
        Action::GenerateTestData => generate_test_data(),
    }
}
