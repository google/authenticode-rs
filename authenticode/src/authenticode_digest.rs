// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::usize_from_u32;
use crate::{PeOffsetError, PeTrait};
use alloc::vec::Vec;
use digest::Update;

fn authenticode_digest_impl(
    pe: &dyn PeTrait,
    digest: &mut dyn Update,
) -> Option<()> {
    let offsets = pe.offsets().ok()?;

    // Hash from beginning to checksum.
    let bytes = &pe.data().get(..offsets.check_sum)?;
    digest.update(bytes);

    // Hash from checksum to the security data directory.
    let bytes = &pe
        .data()
        .get(offsets.after_check_sum..offsets.security_data_dir)?;
    digest.update(bytes);

    // Hash from the security data directory to the end of the header.
    let bytes = &pe
        .data()
        .get(offsets.after_security_data_dir..offsets.after_header)?;
    digest.update(bytes);

    // Track offset as sections are hashed. This is used to hash data
    // after the sections.
    let mut sum_of_bytes_hashed = usize_from_u32(offsets.after_header as u32);

    // First sort the sections.
    let mut sections = (1..=pe.num_sections())
        .map(|i| pe.section_data_range(i))
        .collect::<Result<Vec<_>, PeOffsetError>>()
        .ok()?;
    sections.sort_unstable_by_key(|r| r.start);

    // Then hash each section's data.
    for section_range in sections {
        let bytes = &pe.data().get(section_range)?;

        digest.update(bytes);
        sum_of_bytes_hashed = sum_of_bytes_hashed.checked_add(bytes.len())?;
    }

    let mut extra_hash_len =
        pe.data().len().checked_sub(sum_of_bytes_hashed)?;

    // The certificate table is not included in the hash.
    if let Some(security_data_dir) = pe.certificate_table_range().ok()? {
        let size =
            security_data_dir.end.checked_sub(security_data_dir.start)?;
        extra_hash_len = extra_hash_len.checked_sub(size)?;
    }

    digest.update(pe.data().get(
        sum_of_bytes_hashed..sum_of_bytes_hashed.checked_add(extra_hash_len)?,
    )?);

    Some(())
}

/// Calculate an authenticode digest.
pub fn authenticode_digest(
    pe: &dyn PeTrait,
    digest: &mut dyn Update,
) -> Result<(), PeOffsetError> {
    authenticode_digest_impl(pe, digest).ok_or(PeOffsetError)
}
