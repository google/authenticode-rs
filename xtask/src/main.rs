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
use std::path::PathBuf;
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

struct Paths {
    test_data: PathBuf,
}

impl Paths {
    fn new() -> Self {
        Self {
            test_data: PathBuf::from("authenticode/tests/data"),
        }
    }

    fn unsigned_exe(&self) -> PathBuf {
        self.test_data.join("tiny.efi")
    }

    fn signed_exe(&self) -> PathBuf {
        self.test_data.join("tiny.signed.efi")
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

fn generate_tiny_pe_exe(paths: &Paths) {
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
    Command::with_args(
        "cargo",
        [
            "build",
            "--release",
            "--target",
            "x86_64-unknown-uefi",
            "--manifest-path",
        ],
    )
    .add_arg(tmp_path.join("Cargo.toml"))
    .run()
    .unwrap();

    // Copy it to the test data directory.
    fs::copy(
        tmp_path.join("target/x86_64-unknown-uefi/release/tiny.efi"),
        paths.unsigned_exe(),
    )
    .unwrap();

    // Create a signed copy.
    Command::new("sbsign")
        .add_arg_pair("--cert", paths.public_pem())
        .add_arg_pair("--key", paths.private_pem())
        .add_arg_pair("--output", paths.signed_exe())
        .add_arg(paths.unsigned_exe())
        .run()
        .unwrap();
}

fn generate_test_data() {
    let paths = Paths::new();
    generate_keys(&paths);
    generate_tiny_pe_exe(&paths);
}

fn main() {
    let cli = Cli::parse();

    match &cli.action {
        Action::GenerateTestData => generate_test_data(),
    }
}
