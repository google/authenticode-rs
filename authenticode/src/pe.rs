// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::usize_from_u32;
use core::convert::TryInto;
use core::fmt::{self, Display, Formatter};
use core::mem;
use core::ops::Range;
use memoffset::offset_of;
use object::pe::{
    ImageDataDirectory, ImageOptionalHeader32, ImageOptionalHeader64,
    IMAGE_DIRECTORY_ENTRY_SECURITY,
};
use object::read::pe::ImageOptionalHeader;
use object::read::pe::{ImageNtHeaders, PeFile};
use object::{pod, LittleEndian};

/// An offset within the PE is invalid.
///
/// This can occur if an offset is larger than the PE itself, or if
/// arithmetic overflow occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeOffsetError;

impl Display for PeOffsetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "an offset with the PE is invalid")
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

impl<'data, I> PeTrait for PeFile<'data, I>
where
    I: ImageNtHeaders,
{
    fn data(&self) -> &'data [u8] {
        self.data()
    }

    fn num_sections(&self) -> usize {
        self.section_table().len()
    }

    fn section_data_range(
        &self,
        index: usize,
    ) -> Result<Range<usize>, PeOffsetError> {
        let section =
            self.section_table().section(index).expect("invalid index");
        let start =
            usize_from_u32(section.pointer_to_raw_data.get(LittleEndian));
        let size = usize_from_u32(section.size_of_raw_data.get(LittleEndian));
        let end = start.checked_add(size).ok_or(PeOffsetError)?;
        Ok(start..end)
    }

    fn certificate_table_range(
        &self,
    ) -> Result<Option<Range<usize>>, PeOffsetError> {
        if let Some(dir) = self.data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY) {
            let start = usize_from_u32(dir.virtual_address.get(LittleEndian));
            let size = usize_from_u32(dir.size.get(LittleEndian));
            let end = start.checked_add(size).ok_or(PeOffsetError)?;
            Ok(Some(start..end))
        } else {
            Ok(None)
        }
    }

    fn offsets(&self) -> Result<PeOffsets, PeOffsetError> {
        object_offsets_impl(self).ok_or(PeOffsetError)
    }
}

fn object_offsets_impl<I>(pe: &PeFile<I>) -> Option<PeOffsets>
where
    I: ImageNtHeaders,
{
    // Calculate the offset from the start of the pe data to the
    // beginning of `bytes`.
    let get_offset = |bytes: &[u8]| -> Option<usize> {
        let offset = unsafe { bytes.as_ptr().offset_from(pe.data().as_ptr()) };
        offset.try_into().ok()
    };

    // Get checksum offset.
    let optional_header = pe.nt_headers().optional_header();
    let optional_header_bytes = pod::bytes_of(optional_header);
    let optional_header_offset = get_offset(optional_header_bytes)?;
    let check_sum_offset = optional_header_offset.checked_add(
        if pe.nt_headers().is_type_64() {
            offset_of!(ImageOptionalHeader64, check_sum)
        } else {
            offset_of!(ImageOptionalHeader32, check_sum)
        },
    )?;

    // Hash from checksum to the security data directory.
    let data_dirs_offset =
        optional_header_offset.checked_add(optional_header_bytes.len())?;
    let sec_dir_offset = data_dirs_offset.checked_add(
        mem::size_of::<ImageDataDirectory>()
            .checked_mul(IMAGE_DIRECTORY_ENTRY_SECURITY)?,
    )?;

    // Hash from the security data directory to the end of the header.
    let sec_dir_size = mem::size_of::<ImageDataDirectory>();
    let size_of_headers =
        usize_from_u32(pe.nt_headers().optional_header().size_of_headers());

    Some(PeOffsets {
        check_sum: check_sum_offset,
        after_check_sum: check_sum_offset.checked_add(mem::size_of::<u32>())?,

        security_data_dir: sec_dir_offset,
        after_security_data_dir: sec_dir_offset.checked_add(sec_dir_size)?,

        after_header: size_of_headers,
    })
}
