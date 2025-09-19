// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(feature = "object")]

use authenticode::{
    AttributeCertificate, AttributeCertificateAuthenticodeError,
    AttributeCertificateError, AttributeCertificateIterator, PeTrait,
    WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA,
};
use cms::signed_data::SignerIdentifier;
use core::mem::size_of;
use core::slice;
use digest::{Digest, Update};
use object::endian::LittleEndian as LE;
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_SECURITY, ImageDataDirectory, ImageFileHeader,
    ImageOptionalHeader64,
};
use object::read::pe::{PeFile32, PeFile64};
use sha1::Sha1;
use sha2::Sha256;

#[test]
fn test_get_authenticode_signature() {
    // Test an invalid revision.
    assert_eq!(
        AttributeCertificate {
            revision: 123,
            certificate_type: WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            data: &[],
        }
        .get_authenticode_signature()
        .unwrap_err(),
        AttributeCertificateAuthenticodeError::InvalidCertificateRevision(123)
    );

    // Test an invalid cert type.
    assert_eq!(
        AttributeCertificate {
            revision: WIN_CERT_REVISION_2_0,
            certificate_type: 123,
            data: &[],
        }
        .get_authenticode_signature()
        .unwrap_err(),
        AttributeCertificateAuthenticodeError::InvalidCertificateType(123)
    );
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

struct Expected {
    sha1: &'static str,
    sha256: &'static str,
}

fn check_exe(pe: &dyn PeTrait, expected: Expected) {
    let mut hasher = AuthenticodeHasher::default();
    authenticode::authenticode_digest(pe, &mut hasher).unwrap();
    let sha1 = format!("{:x}", hasher.sha1.finalize());
    let sha256 = format!("{:x}", hasher.sha256.finalize());
    assert_eq!(sha1, expected.sha1);
    assert_eq!(sha256, expected.sha256);

    // Get the signature.
    let signatures = AttributeCertificateIterator::new(pe)
        .unwrap()
        .unwrap()
        .map(|attr_cert| {
            attr_cert
                .expect("Invalid/Malformed signature")
                .get_authenticode_signature()
        })
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
    let SignerIdentifier::IssuerAndSerialNumber(sid) =
        &signature.signer_info().sid
    else {
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

#[test]
fn test_authenticode32() {
    let pe = include_bytes!("testdata/tiny32.signed.efi");
    let pe64 = PeFile32::parse(pe.as_slice()).unwrap();
    check_exe(
        &pe64,
        Expected {
            sha1: "49f239f1cd5083912880e03982bb54528f2c358d",
            sha256: "4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8",
        },
    );
}

#[test]
fn test_authenticode64() {
    let pe = include_bytes!("testdata/tiny64.signed.efi");
    let pe64 = PeFile64::parse(pe.as_slice()).unwrap();
    check_exe(
        &pe64,
        Expected {
            sha1: "e9bdfb63bdf687b8d3bf144033fcb09d7a393563",
            sha256: "a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae",
        },
    );
}

fn modify_image_security_data_dir<F>(f: F) -> Vec<u8>
where
    F: FnOnce(&mut ImageDataDirectory),
{
    let mut data = include_bytes!("testdata/tiny64.signed.efi").to_vec();

    // Get the offset of the PE header from a fixed offset within the
    // DOS header.
    let pe_header_offset = usize::try_from(u32::from_le_bytes(
        data[0x3c..][..4].try_into().unwrap(),
    ))
    .unwrap();

    let start_of_optional_header = pe_header_offset
        // Skip 4 bytes for the "PE\0\0" signature.
        + 4
        // Skip past the rest of the COFF header.
        + size_of::<ImageFileHeader>();

    let num_data_dirs = usize::try_from(u32::from_le_bytes(
        data[start_of_optional_header
             // The field containing the number of data dirs is the last
             // 4 bytes of the optional header.
            + size_of::<ImageOptionalHeader64>()
            - 4..][..4]
            .try_into()
            .unwrap(),
    ))
    .unwrap();

    let start_of_data_dirs = start_of_optional_header
        // Skip past the fixed fields of the optional header. The data
        // directories start immediately after.
        + size_of::<ImageOptionalHeader64>();

    let data_dirs: &mut [ImageDataDirectory] = unsafe {
        slice::from_raw_parts_mut(
            data[start_of_data_dirs..].as_mut_ptr().cast(),
            num_data_dirs,
        )
    };

    f(&mut data_dirs[IMAGE_DIRECTORY_ENTRY_SECURITY]);

    data
}

/// Test an image with an out-of-bounds size in the security data
/// directory.
#[test]
fn test_cert_table_out_of_bounds() {
    let data = modify_image_security_data_dir(|data_dir| {
        // Set a bigger size in the data dir so that it extends past the end
        // of the image.
        data_dir.size.set(LE, data_dir.size.get(LE) + 100)
    });

    let pe = PeFile64::parse(data.as_slice()).unwrap();
    assert_eq!(
        AttributeCertificateIterator::new(&pe).unwrap_err(),
        AttributeCertificateError::OutOfBounds
    );
}

/// Test an image with a mismatch between the size of the security data
/// directory and the actual entries in the table.
#[test]
fn test_cert_table_invalid_size() {
    let data = modify_image_security_data_dir(|data_dir| {
        // Decrease the size of the table by one, to make its contents
        // unaligned.
        data_dir.size.set(LE, data_dir.size.get(LE) - 1)
    });

    let pe = PeFile64::parse(data.as_slice()).unwrap();
    assert_eq!(
        AttributeCertificateIterator::new(&pe).unwrap_err(),
        AttributeCertificateError::InvalidSize
    );
}

/// Test an image containing a certificate with a too-small size.
#[test]
fn test_cert_size_too_small() {
    let mut data = include_bytes!("testdata/tiny64.signed.efi").to_vec();
    let cert_table_range = {
        let pe = PeFile64::parse(data.as_slice()).unwrap();
        pe.certificate_table_range().unwrap().unwrap()
    };
    let cert_table = &mut data[cert_table_range];
    let cert_size: *mut u32 = cert_table.as_mut_ptr().cast();
    // The cert size must be at least as big as the cert header (8 bytes).
    unsafe {
        cert_size.write(7);
    }

    let pe = PeFile64::parse(data.as_slice()).unwrap();
    let mut iter = AttributeCertificateIterator::new(&pe).unwrap().unwrap();
    assert_eq!(
        iter.next().unwrap().unwrap_err(),
        AttributeCertificateError::InvalidCertificateSize { size: 7 }
    );
    assert!(iter.next().is_none());
}

/// Test an image containing a certificate with a too-big size.
#[test]
fn test_cert_size_too_big() {
    let mut data = include_bytes!("testdata/tiny64.signed.efi").to_vec();
    let cert_table_range = {
        let pe = PeFile64::parse(data.as_slice()).unwrap();
        pe.certificate_table_range().unwrap().unwrap()
    };
    let cert_table = &mut data[cert_table_range];
    let cert_size: *mut u32 = cert_table.as_mut_ptr().cast();
    // TODO
    unsafe {
        cert_size.write(100_000);
    }

    let pe = PeFile64::parse(data.as_slice()).unwrap();
    let mut iter = AttributeCertificateIterator::new(&pe).unwrap().unwrap();
    assert_eq!(
        iter.next().unwrap().unwrap_err(),
        AttributeCertificateError::InvalidCertificateSize { size: 100_000 }
    );
    assert!(iter.next().is_none());
}
