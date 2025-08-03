// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use cms::content_info::CmsVersion;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use core::fmt::{self, Display, Formatter};
use der::asn1::{ObjectIdentifier, OctetString};
use der::Decode;
use der::{Sequence, SliceReader};
use x509_cert::Certificate;

/// OID for [`SpcIndirectDataContent`].
pub const SPC_INDIRECT_DATA_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

/// Authenticode ASN.1 image and digest data.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcIndirectDataContent {
    /// Image data.
    pub data: SpcAttributeTypeAndOptionalValue,

    /// Authenticode digest.
    pub message_digest: DigestInfo,
}

/// Authenticode ASN.1 image data.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcAttributeTypeAndOptionalValue {
    /// Type of data stored in the `value` field.
    pub value_type: ObjectIdentifier,

    /// Image data.
    //TODO(nicholasbishop): implement SpcPeImageData.
    pub value: der::Any,
}

/// Authenticode ASN.1 digest data.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DigestInfo {
    /// Authenticode digest algorithm.
    pub digest_algorithm: spki::AlgorithmIdentifierOwned,

    /// Authenticode digest.
    pub digest: OctetString,
}

/// Error returned by [`AuthenticodeSignature::from_bytes`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticodeSignatureParseError {
    /// The signature data is empty.
    Empty,

    /// The signature data is not valid [`ContentInfo`].
    InvalidContentInfo(der::Error),

    /// The content type does not match [`const_oid::db::rfc6268::ID_SIGNED_DATA`].
    InvalidContentType(ObjectIdentifier),

    /// The content info is not valid [`SignedData`].
    InvalidSignedData(der::Error),

    /// The version of [`SignedData`] is not 1.
    InvalidSignedDataVersion(CmsVersion),

    /// The number of digest algorithms is not 1.
    InvalidNumDigestAlgorithms(usize),

    /// The encapsulated content type does not match [`SPC_INDIRECT_DATA_OBJID`].
    InvalidEncapsulatedContentType(ObjectIdentifier),

    /// The encapsulated content is empty.
    EmptyEncapsulatedContent,

    /// The encapsulated content is not valid [`SpcIndirectDataContent`].
    InvalidSpcIndirectDataContent(der::Error),

    /// The number of signer infos is not 1.
    InvalidNumSignerInfo(usize),

    /// The version of [`SignerInfo`] is not 1.
    InvalidSignerInfoVersion(CmsVersion),

    /// The digest algorithm is not internally consistent.
    AlgorithmMismatch,

    /// No authenticated attributes are present.
    EmptyAuthenticatedAttributes,

    /// The `contentType` authenticated attribute is missing.
    MissingContentTypeAuthenticatedAttribute,

    /// The `messageDigest` authenticated attribute is missing.
    MissingMessageDigestAuthenticatedAttribute,
}

impl Display for AuthenticodeSignatureParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // TODO(nicholasbishop): better error message.
        write!(f, "authenticode signature parse error: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuthenticodeSignatureParseError {}

/// Parsed authenticode signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticodeSignature {
    signed_data: SignedData,
    indirect_data: SpcIndirectDataContent,
}

impl AuthenticodeSignature {
    /// Parse an `AuthenticodeSignature` from DER-encoded bytes.
    ///
    /// Note that while many aspects of the data are validated, this
    /// does not constitute actual signature verification.
    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, AuthenticodeSignatureParseError> {
        // Construct a reader manually here rather than using
        // `Decode::from_der`, because there may be unused trailing data
        // in `bytes`, which causes a `TrailingData` error.
        let mut reader = SliceReader::new(bytes)
            .map_err(|_| AuthenticodeSignatureParseError::Empty)?;
        let content_info = ContentInfo::decode(&mut reader)
            .map_err(AuthenticodeSignatureParseError::InvalidContentInfo)?;

        if content_info.content_type != const_oid::db::rfc6268::ID_SIGNED_DATA {
            return Err(AuthenticodeSignatureParseError::InvalidContentType(
                content_info.content_type,
            ));
        }
        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(AuthenticodeSignatureParseError::InvalidSignedData)?;

        if signed_data.version != CmsVersion::V1 {
            return Err(
                AuthenticodeSignatureParseError::InvalidSignedDataVersion(
                    signed_data.version,
                ),
            );
        }

        // Exactly one is required per the spec.
        if signed_data.digest_algorithms.len() != 1 {
            return Err(
                AuthenticodeSignatureParseError::InvalidNumDigestAlgorithms(
                    signed_data.digest_algorithms.len(),
                ),
            );
        }

        if signed_data.encap_content_info.econtent_type
            != SPC_INDIRECT_DATA_OBJID
        {
            return Err(
                AuthenticodeSignatureParseError::InvalidEncapsulatedContentType(
                    signed_data.encap_content_info.econtent_type,
                ),
            );
        }
        let indirect_data = signed_data
            .clone()
            .encap_content_info
            .econtent
            .ok_or(AuthenticodeSignatureParseError::EmptyEncapsulatedContent)?
            .decode_as::<SpcIndirectDataContent>()
            .map_err(
                AuthenticodeSignatureParseError::InvalidSpcIndirectDataContent,
            )?;

        // Exactly one is required per the spec.
        if signed_data.signer_infos.0.len() != 1 {
            return Err(AuthenticodeSignatureParseError::InvalidNumSignerInfo(
                signed_data.signer_infos.0.len(),
            ));
        }
        let signer_info = &signed_data.signer_infos.0.as_slice()[0];

        if signer_info.version != CmsVersion::V1 {
            return Err(
                AuthenticodeSignatureParseError::InvalidSignerInfoVersion(
                    signer_info.version,
                ),
            );
        }

        if signer_info.digest_alg != signed_data.digest_algorithms.as_slice()[0]
        {
            return Err(AuthenticodeSignatureParseError::AlgorithmMismatch);
        }

        let signed_attrs = if let Some(signed_attrs) = &signer_info.signed_attrs
        {
            signed_attrs
        } else {
            return Err(
                AuthenticodeSignatureParseError::EmptyAuthenticatedAttributes,
            );
        };

        if !signed_attrs
            .iter()
            .any(|a| a.oid == const_oid::db::rfc6268::ID_CONTENT_TYPE)
        {
            return Err(AuthenticodeSignatureParseError::MissingContentTypeAuthenticatedAttribute);
        }

        if !signed_attrs
            .iter()
            .any(|a| a.oid == const_oid::db::rfc6268::ID_MESSAGE_DIGEST)
        {
            return Err(AuthenticodeSignatureParseError::MissingMessageDigestAuthenticatedAttribute);
        }

        Ok(Self {
            signed_data: signed_data.clone(),
            indirect_data,
        })
    }

    /// Get [`SignerInfo`].
    pub fn signer_info(&self) -> &SignerInfo {
        // The constructor validates that exactly one signer info is
        // present, so this won't panic.
        &self.signed_data.signer_infos.0.as_slice()[0]
    }

    /// Get the authenticode digest.
    ///
    /// This is the digest value embedded in the signature; it is not
    /// guaranteed to be correct.
    pub fn digest(&self) -> &[u8] {
        self.indirect_data.message_digest.digest.as_bytes()
    }

    /// Get the authenticode signature.
    ///
    /// This is the `encryptedDigest` value embedded in the signature;
    /// it is not guaranteed to be correct.
    pub fn signature(&self) -> &[u8] {
        self.signer_info().signature.as_bytes()
    }

    /// Get the encapsulated content.
    pub fn encapsulated_content(&self) -> Option<&[u8]> {
        self.signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .map(|c| c.value())
    }

    /// Get the certificate chain.
    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.signed_data
            .certificates
            .as_ref()
            .unwrap()
            .0
            .iter()
            .map(|cert| {
                if let cms::cert::CertificateChoices::Certificate(cert) = cert {
                    cert
                } else {
                    panic!()
                }
            })
    }
}
