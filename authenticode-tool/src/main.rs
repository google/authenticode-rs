// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use anyhow::{anyhow, bail, Result};
use authenticode::{AttributeCertificateIterator, PeTrait};
use clap::{Parser, Subcommand};
use cms::signed_data::SignerIdentifier;
use der::Encode;
use digest::{Digest, Update};
use object::read::pe::{PeFile32, PeFile64};
use sha1::Sha1;
use sha2::Sha256;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}

#[derive(Parser)]
struct GetCertAction {
    pe_path: PathBuf,
    sig_index: usize,
    cert_index: usize,
}

#[derive(Subcommand)]
enum Action {
    Info { pe_path: PathBuf },
    GetCert(GetCertAction),
}

#[derive(Default)]
struct AuthenticodeHasher {
    sha1: Sha1,
    sha256: Sha256,
}

impl Update for AuthenticodeHasher {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.sha1, data);
        Update::update(&mut self.sha256, data);
    }
}

fn action_info(pe_path: &Path) -> Result<()> {
    let data = fs::read(pe_path)?;
    let pe = parse_pe(&data)?;

    let mut hasher = AuthenticodeHasher::default();
    authenticode::authenticode_digest(&*pe, &mut hasher)?;

    println!("SHA-1:   {:x}", hasher.sha1.finalize());
    println!("SHA-256: {:x}", hasher.sha256.finalize());

    let signatures =
        if let Some(iter) = AttributeCertificateIterator::new(&*pe)? {
            iter.map(|attr_cert| attr_cert.get_authenticode_signature())
                .collect::<Result<Vec<_>, _>>()?
        } else {
            println!("No signatures");
            return Ok(());
        };

    for (signature_index, s) in signatures.iter().enumerate() {
        println!("Signature {signature_index}:");

        print!("  Digest: ");
        for byte in s.digest() {
            print!("{byte:02x}");
        }
        println!();

        println!("  Signer:");
        if let SignerIdentifier::IssuerAndSerialNumber(sid) =
            &s.signer_info().sid
        {
            println!("    Issuer:        {}", sid.issuer);
            println!("    Serial number: {}", sid.serial_number);
        }

        for (i, cert) in s.certificates().enumerate() {
            println!("  Certificate {i}:");

            println!("    Issuer:        {}", cert.tbs_certificate.issuer);
            println!("    Subject:       {}", cert.tbs_certificate.subject);
            println!(
                "    Serial number: {}",
                cert.tbs_certificate.serial_number
            );
        }
    }

    Ok(())
}

fn action_get_cert(action: &GetCertAction) -> Result<()> {
    let data = fs::read(&action.pe_path)?;
    let pe = parse_pe(&data)?;
    let signatures =
        if let Some(iter) = AttributeCertificateIterator::new(&*pe)? {
            iter.map(|attr_cert| attr_cert.get_authenticode_signature())
                .collect::<Result<Vec<_>, _>>()?
        } else {
            bail!("input file has no signatures");
        };

    let s = &signatures
        .get(action.sig_index)
        .ok_or(anyhow!("invalid signature index"))?;

    let cert = s
        .certificates()
        .nth(action.cert_index)
        .ok_or(anyhow!("invalid certificate index"))?;
    let der = cert.to_der()?;
    io::stdout().write_all(&der)?;
    Ok(())
}

fn run_action(action: &Action) -> Result<()> {
    match action {
        Action::GetCert(action) => action_get_cert(action),
        Action::Info { pe_path } => action_info(pe_path),
    }
}

fn parse_pe(
    bytes: &[u8],
) -> Result<Box<dyn PeTrait + '_>, object::read::Error> {
    if let Ok(pe) = PeFile64::parse(bytes) {
        Ok(Box::new(pe))
    } else {
        let pe = PeFile32::parse(bytes)?;
        Ok(Box::new(pe))
    }
}

fn main() -> Result<()> {
    run_action(&Cli::parse().action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_info() {
        // Error: bad path.
        assert!(run_action(&Action::Info {
            pe_path: "../authenticode/tests/data/bad.efi".into(),
        })
        .is_err());

        // Success, no signatures.
        run_action(&Action::Info {
            pe_path: "../authenticode/tests/data/tiny64.efi".into(),
        })
        .unwrap();

        // Success, 32-bit.
        run_action(&Action::Info {
            pe_path: "../authenticode/tests/data/tiny32.signed.efi".into(),
        })
        .unwrap();

        // Success, 64-bit.
        run_action(&Action::Info {
            pe_path: "../authenticode/tests/data/tiny64.signed.efi".into(),
        })
        .unwrap();
    }

    #[test]
    fn test_action_get_cert() {
        // Error: bad path.
        assert!(run_action(&Action::GetCert(GetCertAction {
            pe_path: "../authenticode/tests/data/bad.efi".into(),
            sig_index: 0,
            cert_index: 0,
        }))
        .is_err());

        // Error: no signatures.
        assert!(run_action(&Action::GetCert(GetCertAction {
            pe_path: "../authenticode/tests/data/tiny64.efi".into(),
            sig_index: 0,
            cert_index: 0,
        }))
        .is_err());

        // Error: invalid signature index.
        assert!(run_action(&Action::GetCert(GetCertAction {
            pe_path: "../authenticode/tests/data/tiny64.signed.efi".into(),
            sig_index: 1,
            cert_index: 0,
        }))
        .is_err());

        // Error: invalid certificate index.
        assert!(run_action(&Action::GetCert(GetCertAction {
            pe_path: "../authenticode/tests/data/tiny64.signed.efi".into(),
            sig_index: 0,
            cert_index: 1,
        }))
        .is_err());

        // Success, 32-bit.
        run_action(&Action::GetCert(GetCertAction {
            pe_path: "../authenticode/tests/data/tiny32.signed.efi".into(),
            sig_index: 0,
            cert_index: 0,
        }))
        .unwrap();

        // Success, 64-bit.
        run_action(&Action::GetCert(GetCertAction {
            pe_path: "../authenticode/tests/data/tiny64.signed.efi".into(),
            sig_index: 0,
            cert_index: 0,
        }))
        .unwrap();
    }
}
