// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use authenticode::AttributeCertificateIterator;
use cms::signed_data::SignerIdentifier;
use digest::{Digest, Update};
use object::read::pe::PeFile64;
use sha1::Sha1;
use sha2::Sha256;

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

#[test]
fn test_authenticode() {
    let pe = include_bytes!("data/tiny64.signed.efi");
    let pe = PeFile64::parse(pe.as_slice()).unwrap();
    let mut hasher = AuthenticodeHasher::default();
    authenticode::authenticode_digest(&pe, &mut hasher).unwrap();
    let sha1 = format!("{:x}", hasher.sha1.finalize());
    let sha256 = format!("{:x}", hasher.sha256.finalize());
    assert_eq!(sha1, "e9bdfb63bdf687b8d3bf144033fcb09d7a393563");
    assert_eq!(
        sha256,
        "a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae"
    );

    // Get the signature.
    let signatures = AttributeCertificateIterator::new(&pe)
        .unwrap()
        .unwrap()
        .map(|attr_cert| attr_cert.get_authenticode_signature())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(signatures.len(), 1);
    let signature = &signatures[0];

    // Check digest.
    assert_eq!(
        format!("{:02x?}", signature.digest())
            .replace(", ", "")
            .replace('[', "")
            .replace(']', ""),
        sha256
    );

    // Check signer.
    let SignerIdentifier::IssuerAndSerialNumber(sid) = &signature.signer_info().sid else {
        panic!();
    };
    assert_eq!(sid.issuer.to_string(), "CN=TestKey");
    assert_eq!(
        sid.serial_number.to_string(),
        "2A:5B:9F:85:57:D6:D5:E8:60:E3:40:9D:42:FC:1C:B2:1F:3F:1B:6F"
    );

    // Check cert list.
    let certificates: Vec<_> = signature.certificates().collect();
    assert_eq!(certificates.len(), 1);
    let cert = &certificates[0];
    assert_eq!(cert.tbs_certificate.issuer, sid.issuer);
    assert_eq!(cert.tbs_certificate.subject, sid.issuer);
    assert_eq!(cert.tbs_certificate.serial_number, sid.serial_number);
}
