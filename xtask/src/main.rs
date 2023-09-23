// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use clap::{Parser, Subcommand};
use fs_err as fs;
use std::path::{Path, PathBuf};
use std::process::Command;
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

fn run_command(command: &mut Command) {
    println!("{}", format!("{command:?}").replace('"', ""));
    let status = command.status().unwrap();
    assert!(status.success());
}

fn generate_keys(paths: &Paths) {
    if paths.private_pem().exists() && paths.public_pem().exists() {
        println!("skipping key generation");
        return;
    }

    run_command(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-subj",
                "/CN=TestKey/",
                // Turn off encryption so no password is needed.
                "-nodes",
                "-keyout",
            ])
            .arg(paths.private_pem())
            .arg("-out")
            .arg(paths.public_pem()),
    );
}

fn build_exe(root_path: &Path, bitness: Bitness) {
    run_command(
        Command::new("cargo")
            .args([
                "build",
                "--release",
                "--target",
                bitness.target(),
                "--manifest-path",
            ])
            .arg(root_path.join("Cargo.toml")),
    );
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
    run_command(
        Command::new("cargo")
            .args(["init", "--bin", "--name", "tiny"])
            .arg(tmp_path),
    );
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
    run_command(
        Command::new("sbsign")
            .arg("--cert")
            .arg(paths.public_pem())
            .arg("--key")
            .arg(paths.private_pem())
            .arg("--output")
            .arg(paths.signed_exe(bitness))
            .arg(paths.unsigned_exe(bitness)),
    );
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
