// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use authenticode::{
    AttributeCertificateAuthenticodeError, AttributeCertificateError,
    AuthenticodeSignatureParseError, PeOffsetError,
};
use cms::content_info::CmsVersion;
use der::asn1::ObjectIdentifier;

// Don't check the actual messages, just validate that formatting without
// panic or error.

#[test]
fn test_attribute_certificate_authenticode_error() {
    format!(
        "{}",
        AttributeCertificateAuthenticodeError::InvalidCertificateRevision(0)
    );
    format!(
        "{}",
        AttributeCertificateAuthenticodeError::InvalidCertificateType(0)
    );
    format!(
        "{}",
        AttributeCertificateAuthenticodeError::InvalidSignature(
            AuthenticodeSignatureParseError::Empty
        )
    );
}

#[test]
fn test_attribute_certificate_error() {
    format!("{}", AttributeCertificateError::InvalidSize);
    format!("{}", AttributeCertificateError::OutOfBounds);
    format!(
        "{}",
        AttributeCertificateError::InvalidCertificateSize { size: 123 }
    );
}

#[test]
fn test_authenticode_signature_parse_error() {
    let cms_ver = CmsVersion::V1;
    let der_err = der::Error::new(der::ErrorKind::Failed, der::Length::ZERO);
    let oid = ObjectIdentifier::new_unwrap("1.2.3");

    format!("{}", AuthenticodeSignatureParseError::Empty);
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidContentInfo(der_err)
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidContentType(oid)
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidSignedData(der_err)
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidSignedDataVersion(cms_ver)
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidNumDigestAlgorithms(0)
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidEncapsulatedContentType(oid)
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::EmptyEncapsulatedContent
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidSpcIndirectDataContent(der_err)
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidNumSignerInfo(0)
    );
    format!(
        "{}",
        AuthenticodeSignatureParseError::InvalidSignerInfoVersion(cms_ver)
    );
    format!("{}", AuthenticodeSignatureParseError::AlgorithmMismatch);
    format!(
        "{}",
        AuthenticodeSignatureParseError::EmptyAuthenticatedAttributes
    );
    format!("{}", AuthenticodeSignatureParseError::MissingContentTypeAuthenticatedAttribute);
    format!("{}", AuthenticodeSignatureParseError::MissingMessageDigestAuthenticatedAttribute);
}

#[test]
fn test_pe_offset_error() {
    format!("{}", PeOffsetError);
}
