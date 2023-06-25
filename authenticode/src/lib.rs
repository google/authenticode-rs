// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Authenticode utilities.
//!
//! Reference:
//! <https://docs.microsoft.com/en-us/windows/win32/debug/pe-format>

#![forbid(unsafe_code)]
// Allow using `std` if the `std` feature is enabled, or when running
// tests. Otherwise enable `no_std`.
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![warn(clippy::integer_arithmetic)]
#![warn(missing_docs)]

extern crate alloc;

mod authenticode_digest;
mod pe;
mod pe_object;
mod signature;
mod win_cert;

use core::convert::TryInto;

pub use authenticode_digest::authenticode_digest;
pub use pe::{PeOffsetError, PeOffsets, PeTrait};
pub use signature::{
    AuthenticodeSignature, AuthenticodeSignatureParseError, DigestInfo,
    SpcAttributeTypeAndOptionalValue, SpcIndirectDataContent,
    SPC_INDIRECT_DATA_OBJID,
};
pub use win_cert::{
    AttributeCertificate, AttributeCertificateAuthenticodeError,
    AttributeCertificateError, AttributeCertificateIterator,
    WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA,
};

/// Convert a `u32` to a `usize`, panicking if the value does not fit.
///
/// This can only panic on targets where `usize` is smaller than 32
/// bits, which is not considered a supported use case by this library.
fn usize_from_u32(val: u32) -> usize {
    val.try_into().unwrap()
}
