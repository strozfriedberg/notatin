use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32}
};
use std::io::Cursor;
use winstructs::security::SecurityDescriptor;
use serde::Serialize;
use crate::hive_bin_cell;
use crate::err::Error;
use crate::warn::Warnings;
use crate::util;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellKeySecurityDetail {
    pub size: u32,
    pub unknown1: u16,
    /* Offsets in bytes, relative from the start of the hive bin's data.
       When a key security item acts as a list header, flink points to the first entry of this list.
       If a list is empty, flink points to a list header (i.e. to a current cell).
       When a key security item acts as a list entry, flink points to the next entry of this list.
       If there is no next entry in a list, flink points to a list header. */
    pub flink: u32,
    /* Offsets in bytes, relative from the start of the hive bin's data.
       When a key security item acts as a list header, blink points to the last entry of this list.
       If a list is empty, blink points to a list header (i.e. to a current cell).
       When a key security item acts as a list entry, blink points to the previous entry of this list.
       If there is no previous entry in a list, blink points to a list header. */
    pub blink: u32,
    pub reference_count: u32,
    pub security_descriptor_size: u32,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellKeySecurity {
    pub detail: CellKeySecurityDetail,
    pub security_descriptor: Vec<u8>,
    pub parse_warnings: Warnings
}

impl CellKeySecurity {
    /// Uses nom to parse a key security (sk) hive bin cell.
    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let start_pos = input.as_ptr() as usize;
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("sk")(input)?;
        let (input, unknown1) = le_u16(input)?;
        let (input, flink) = le_u32(input)?;
        let (input, blink) = le_u32(input)?;
        let (input, reference_count) = le_u32(input)?;
        let (input, security_descriptor_size) = le_u32(input)?;
        let (input, security_descriptor) = take!(input, security_descriptor_size)?;

        let size_abs = size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            CellKeySecurity {
                detail: CellKeySecurityDetail {
                    size: size_abs,
                    unknown1,
                    flink,
                    blink,
                    reference_count,
                    security_descriptor_size,
                },
                security_descriptor: security_descriptor.to_vec(),
                parse_warnings: Warnings::default()
            },
        ))
    }
}

impl hive_bin_cell::Cell for CellKeySecurity {
    fn size(&self) -> u32 {
        self.detail.size
    }

    fn lowercase(&self) -> Option<String> {
        None
    }

    fn is_key(&self) -> bool {
        false
    }
}

pub fn read_cell_key_security(
    file_buffer: &[u8],
    security_key_offset: u32,
    hbin_offset_absolute: u32
) -> Result<Vec<SecurityDescriptor>, Error> {
    let mut security_descriptors = Vec::new();
    let mut offset: usize = security_key_offset as usize;
    loop {
        let (_, cell_key_security) = CellKeySecurity::from_bytes(&file_buffer[offset + hbin_offset_absolute as usize..])?;
        security_descriptors.push(
            SecurityDescriptor::from_stream(&mut Cursor::new(cell_key_security.security_descriptor))?
        );

        if cell_key_security.detail.flink == security_key_offset {
            break;
        }
        offset = cell_key_security.detail.flink as usize;
    }
    Ok(security_descriptors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_cell_key_security() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[5472..5736];
        let ret = CellKeySecurity::from_bytes(slice);

        let expected_output = CellKeySecurity {
            detail: CellKeySecurityDetail {
                size: 264,
                unknown1: 0,
                flink: 232704,
                blink: 234848,
                reference_count: 1,
                security_descriptor_size: 156,
            },
            security_descriptor: vec![1, 0, 4, 144, 128, 0, 0, 0, 144, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 108, 0, 4, 0, 0, 0, 0, 3, 36, 0, 63, 0, 15, 0, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 151, 42, 103, 121, 160, 84, 74, 182, 25, 135, 40, 126, 81, 4, 0, 0, 0, 3, 20, 0, 63, 0, 15, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 3, 24, 0, 63, 0, 15, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 0, 3, 20, 0, 25, 0, 2, 0, 1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 ],
            parse_warnings: Warnings::default()
        };

        let remaining: [u8; 0] = [];

        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(
            expected,
            ret
        );
    }
}