/*
 * Copyright 2021 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::err::Error;
use crate::log::Logs;
use nom::{
    bytes::complete::tag,
    number::complete::{le_i32, le_u16, le_u32},
    take, IResult,
};
use serde::Serialize;
use std::io::Cursor;
use winstructs::security::SecurityDescriptor;

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
    pub logs: Logs,
}

impl CellKeySecurity {
    /// Uses nom to parse a key security (sk) hive bin cell.
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("sk")(input)?;
        let (input, unknown1) = le_u16(input)?;
        let (input, flink) = le_u32(input)?;
        let (input, blink) = le_u32(input)?;
        let (input, reference_count) = le_u32(input)?;
        let (input, security_descriptor_size) = le_u32(input)?;
        let (input, security_descriptor) = take!(input, security_descriptor_size)?;

        Ok((
            input,
            CellKeySecurity {
                detail: CellKeySecurityDetail {
                    size: size.unsigned_abs(),
                    unknown1,
                    flink,
                    blink,
                    reference_count,
                    security_descriptor_size,
                },
                security_descriptor: security_descriptor.to_vec(),
                logs: Logs::default(),
            },
        ))
    }
}

pub(crate) fn read_cell_key_security(
    buffer: &[u8],
    security_key_offset: u32,
    hbin_offset_absolute: usize,
) -> Result<Vec<SecurityDescriptor>, Error> {
    let mut security_descriptors = Vec::new();
    let mut offset: usize = security_key_offset as usize;
    loop {
        let slice = buffer
            .get(offset + hbin_offset_absolute..)
            .ok_or_else(|| Error::buffer("read_cell_key_security"))?;
        let (_, cell_key_security) = CellKeySecurity::from_bytes(slice)?;
        security_descriptors.push(SecurityDescriptor::from_stream(&mut Cursor::new(
            cell_key_security.security_descriptor,
        ))?);

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
    fn test_parse_cell_key_security() {
        let slice = [
            0xF8, 0xFE, 0xFF, 0xFF, 0x73, 0x6B, 0x00, 0x00, 0x00, 0x8D, 0x03, 0x00, 0x60, 0x95,
            0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x9C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x90,
            0x80, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x6C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x24, 0x00,
            0x3F, 0x00, 0x0F, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00,
            0x00, 0x00, 0x97, 0x2A, 0x67, 0x79, 0xA0, 0x54, 0x4A, 0xB6, 0x19, 0x87, 0x28, 0x7E,
            0x51, 0x04, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00, 0x3F, 0x00, 0x0F, 0x00, 0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x03, 0x18, 0x00,
            0x3F, 0x00, 0x0F, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00,
            0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00, 0x19, 0x00, 0x02, 0x00,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0C, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x3F, 0x00, 0x0F, 0x00,
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
            0x00, 0x00, 0x00, 0x0A, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
        ];

        let (_, sec) = CellKeySecurity::from_bytes(&slice).unwrap();

        let expected_output = CellKeySecurity {
            detail: CellKeySecurityDetail {
                size: 264,
                unknown1: 0,
                flink: 232704,
                blink: 234848,
                reference_count: 1,
                security_descriptor_size: 156,
            },
            security_descriptor: vec![
                1, 0, 4, 144, 128, 0, 0, 0, 144, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 108, 0, 4,
                0, 0, 0, 0, 3, 36, 0, 63, 0, 15, 0, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 151, 42,
                103, 121, 160, 84, 74, 182, 25, 135, 40, 126, 81, 4, 0, 0, 0, 3, 20, 0, 63, 0, 15,
                0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 3, 24, 0, 63, 0, 15, 0, 1, 2, 0, 0, 0,
                0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 0, 3, 20, 0, 25, 0, 2, 0, 1, 1, 0, 0, 0, 0, 0,
                5, 12, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 1, 1, 0, 0, 0, 0,
                0, 5, 18, 0, 0, 0,
            ],
            logs: Logs::default(),
        };

        assert_eq!(expected_output, sec);
    }
}
