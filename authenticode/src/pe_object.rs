// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::pe::{PeOffsetError, PeOffsets, PeTrait};
use crate::usize_from_u32;
use core::mem;
use core::ops::Range;
use object::pe::{ImageDataDirectory, IMAGE_DIRECTORY_ENTRY_SECURITY};
use object::read::pe::ImageOptionalHeader;
use object::read::pe::{ImageNtHeaders, PeFile};
use object::{pod, LittleEndian, SectionIndex};

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
        let section = self
            .section_table()
            .section(SectionIndex(index))
            .expect("invalid index");
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
        let base = pe.data().as_ptr() as usize;
        let bytes_start = bytes.as_ptr() as usize;
        bytes_start.checked_sub(base)
    };

    // Get checksum offset.
    let optional_header = pe.nt_headers().optional_header();
    let optional_header_bytes = pod::bytes_of(optional_header);
    let optional_header_offset = get_offset(optional_header_bytes)?;
    let check_sum_offset = optional_header_offset.checked_add(
        // The offset of the `check_sum` field is the same within both
        // the 32-bit and 64-bit headers.
        64,
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
