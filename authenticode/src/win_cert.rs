// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::usize_from_u32;
use crate::PeTrait;
use crate::{AuthenticodeSignature, AuthenticodeSignatureParseError};
use core::fmt::{self, Display, Formatter};

/// Current version of `Win_Certificate` structure.
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;

/// Certificate contains a PKCS#7 `SignedData` structure.
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

fn align_up(size: usize, align: usize) -> Option<usize> {
    Some((size.checked_add(align)?.checked_sub(1)?) & !(align.checked_sub(1)?))
}

fn check_total_size_valid(remaining_data: &[u8]) -> bool {
    let mut iter = AttributeCertificateIterator { remaining_data };
    while iter.next().is_some() {}
    iter.remaining_data.is_empty()
}

/// Error returned by [`AttributeCertificateIterator::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeCertificateError {
    /// The certificate table's range is out of bounds.
    OutOfBounds,

    /// The certiticate table's size does not match the sum of the
    /// certificate entry's aligned sizes.
    InvalidSize,
}

impl Display for AttributeCertificateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds => {
                write!(f, "certificate table range is out of bounds")
            }
            Self::InvalidSize => {
                write!(f, "certificate table size does not match the sum of the certificate entry's aligned sizes")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AttributeCertificateError {}

/// Error returned by [`AttributeCertificate::get_authenticode_signature`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeCertificateAuthenticodeError {
    /// Attribute certificate revision does not match [`WIN_CERT_REVISION_2_0`].
    InvalidCertificateRevision(u16),

    /// Attribute certificate type does not match [`WIN_CERT_TYPE_PKCS_SIGNED_DATA`].
    InvalidCertificateType(u16),

    /// Attribute certificate data is not a valid [`AuthenticodeSignature`].
    InvalidSignature(AuthenticodeSignatureParseError),
}

impl Display for AttributeCertificateAuthenticodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCertificateRevision(rev) => {
                write!(f, "invalid attribute certificate revision: {rev:02x}")
            }
            Self::InvalidCertificateType(ctype) => {
                write!(f, "invalid attribute certificate type: {ctype:02x}")
            }
            Self::InvalidSignature(err) => {
                write!(f, "invalid signature: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AttributeCertificateAuthenticodeError {}

/// Raw data for a PE attribute certificate.
///
/// Note that PE attribute certificates are not related to X.509
/// attribute certificates.
pub struct AttributeCertificate<'a> {
    /// `WIN_CERTIFICATE` version number.
    pub revision: u16,

    /// Certificate type.
    pub certificate_type: u16,

    /// Raw certificate data (not including the header).
    pub data: &'a [u8],
}

impl<'a> AttributeCertificate<'a> {
    /// Get the certificate data as an authenticode signature.
    pub fn get_authenticode_signature(
        &self,
    ) -> Result<AuthenticodeSignature, AttributeCertificateAuthenticodeError>
    {
        if self.revision != WIN_CERT_REVISION_2_0 {
            return Err(AttributeCertificateAuthenticodeError::InvalidCertificateRevision(self.revision));
        }
        if self.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            return Err(
                AttributeCertificateAuthenticodeError::InvalidCertificateType(
                    self.certificate_type,
                ),
            );
        }

        AuthenticodeSignature::from_bytes(self.data)
            .map_err(AttributeCertificateAuthenticodeError::InvalidSignature)
    }
}

/// Iterator over PE attribute certificates.
pub struct AttributeCertificateIterator<'a> {
    remaining_data: &'a [u8],
}

impl<'a> AttributeCertificateIterator<'a> {
    /// Create a new `AttributeCertificateIterator`.
    ///
    /// If there is no attribute certificate table, this returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`AttributeCertificateError::OutOfBounds`] if the table
    /// is not within the PE image bounds.
    ///
    /// Returns [`AttributeCertificateError::InvalidSize`] if the table
    /// size does not match the sum of the certificate entry's aligned
    /// sizes.
    pub fn new(
        pe: &'a dyn PeTrait,
    ) -> Result<Option<Self>, AttributeCertificateError> {
        match pe.certificate_table_range() {
            Ok(Some(certificate_table_range)) => {
                let remaining_data = pe
                    .data()
                    .get(certificate_table_range)
                    .ok_or(AttributeCertificateError::OutOfBounds)?;

                // TODO(nicholasbishop): add unit test for this.
                if !check_total_size_valid(remaining_data) {
                    return Err(AttributeCertificateError::InvalidSize);
                }
                Ok(Some(Self { remaining_data }))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(AttributeCertificateError::OutOfBounds),
        }
    }
}

impl<'a> Iterator for AttributeCertificateIterator<'a> {
    type Item = AttributeCertificate<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header_size = 8;
        if self.remaining_data.len() < header_size {
            return None;
        }

        // TODO(nicholasbishop): replace unwraps with errors.

        let cert_bytes = self.remaining_data;
        let cert_size = usize_from_u32(u32::from_le_bytes(
            cert_bytes[0..4].try_into().unwrap(),
        ));
        let revision = u16::from_le_bytes(cert_bytes[4..6].try_into().unwrap());
        let certificate_type =
            u16::from_le_bytes(cert_bytes[6..8].try_into().unwrap());

        // Get the cert data (excludes the header).
        let cert_data_size = cert_size.checked_sub(header_size).unwrap();
        let cert_data = &cert_bytes
            [header_size..header_size.checked_add(cert_data_size).unwrap()];

        // Advance to next certificate. Data is 8-byte aligned, so round up.
        let size_rounded_up = align_up(cert_size, 8).unwrap();
        self.remaining_data = &cert_bytes[size_rounded_up..];

        Some(AttributeCertificate {
            revision,
            certificate_type,
            data: cert_data,
        })
    }
}
