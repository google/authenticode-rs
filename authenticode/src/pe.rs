// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::fmt::{self, Display, Formatter};
use core::ops::Range;

/// An offset within the PE is invalid.
///
/// This can occur if an offset is larger than the PE itself, or if
/// arithmetic overflow occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeOffsetError;

impl Display for PeOffsetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "an offset within the PE is invalid")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PeOffsetError {}

/// Various offsets within the PE file needed for authenticode hashing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeOffsets {
    /// Offset of the `checksum` field in the optional header.
    pub check_sum: usize,
    /// Offset of the next byte after the `checksum` field.
    pub after_check_sum: usize,

    /// Offset of the security data directory itself (not the data
    /// pointed to by the directory).
    pub security_data_dir: usize,
    /// Offset of the next byte after the security data directory.
    pub after_security_data_dir: usize,

    /// Offset of the next byte after the header.
    pub after_header: usize,
}

/// Trait for reading a PE file.
///
/// Note that this trait (and this crate as a whole) does not validate
/// the PE file. It's up to the user to do that, if necessary. `PeTrait`
/// is used only to get data directly relevant to authenticode. For
/// example, this crate doesn't check for the magic bytes that indicate
/// whether a file is a PE. However, bounds checking is always used, so
/// an invalid PE file can only cause an error to be returned, never
/// memory unsafety or a panic.
///
/// If the `object` feature is enabled then `PeTrait` will be
/// implemented for [`PeFile`] from the [`object`] crate.
///
/// [`PeFile`]: https://docs.rs/object/latest/object/read/pe/struct.PeFile.html
/// [`object`]: https://docs.rs/object/latest/object/
pub trait PeTrait {
    /// Get the raw bytes of the PE file.
    fn data(&self) -> &[u8];

    /// Get the number of sections.
    fn num_sections(&self) -> usize;

    /// Get a section's data range.
    ///
    /// The section `index` starts at 1.
    ///
    /// The start of the range is `PointerToRawData`, and the size of
    /// the range is `SizeOfRawData`.
    ///
    /// # Panics
    ///
    /// Panics if the index is zero or greater than `num_sections()`.
    fn section_data_range(
        &self,
        index: usize,
    ) -> Result<Range<usize>, PeOffsetError>;

    /// Get the certificate table's data range, if present.
    fn certificate_table_range(
        &self,
    ) -> Result<Option<Range<usize>>, PeOffsetError>;

    /// Get various offsets within the PE file needed for authenticode hashing.
    fn offsets(&self) -> Result<PeOffsets, PeOffsetError>;
}
