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

use crate::cell_key_value::{CellKeyValue, CellKeyValueDataTypes};
use crate::err::Error;
use crate::file_info::FileInfo;
use crate::log::Logs;
use nom::{
    bytes::complete::tag,
    multi::count,
    number::complete::{le_i32, le_u16, le_u32},
    IResult,
};
use serde::Serialize;

/* List of data segments. Big data is used to reference data larger than 16344 bytes
When the Minor version field of the base block is greater than 3, it has the following structure: */
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellBigData {
    pub size: u32,
    pub count: u16,
    pub segment_list_offset_relative: u32, // relative to the start of the hive bin
    pub logs: Logs,
}

impl CellBigData {
    pub(crate) fn is_big_data_block(input: &[u8]) -> bool {
        match input.get(4..) {
            Some(slice) => {
                tag::<&str, &[u8], nom::error::Error<&[u8]>>("db")(slice).map_or(false, |_| true)
            }
            None => false,
        }
    }

    /// Uses nom to parse a big data (db) hive bin cell. Returns a tuple of Self and the starting ptr offset
    fn from_bytes(input: &[u8]) -> IResult<&[u8], (Self, usize)> {
        let offset = input.as_ptr() as usize;
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("db")(input)?;
        let (input, count) = le_u16(input)?;
        let (input, segment_list_offset_relative) = le_u32(input)?;

        Ok((
            input,
            (
                CellBigData {
                    size: size.unsigned_abs(),
                    count,
                    segment_list_offset_relative,
                    logs: Logs::default(),
                },
                offset,
            ),
        ))
    }

    /// Returns a tuple of the full content buffer and the absolute data offsets
    pub(crate) fn get_big_data_bytes(
        file_info: &FileInfo,
        offset: usize,
        data_type: &CellKeyValueDataTypes,
        data_size: u32,
    ) -> Result<(Vec<u8>, Vec<usize>), Error> {
        let slice = file_info
            .buffer
            .get(offset..)
            .ok_or_else(|| Error::buffer("get_big_data_bytes"))?;
        let (_, (hive_bin_cell_big_data, _)) = CellBigData::from_bytes(slice)?;
        let (_, data_offsets_absolute) =
            hive_bin_cell_big_data.parse_big_data_offsets(file_info)?;

        let mut big_data_buffer: Vec<u8> = Vec::new();
        let mut data_size_remaining = data_size;
        for offset in data_offsets_absolute.iter() {
            if data_size_remaining > 0 {
                let (input, size) = CellBigData::parse_big_data_size(file_info, *offset)?;
                let size_to_read = std::cmp::min(
                    size.unsigned_abs(),
                    std::cmp::min(data_size_remaining, CellKeyValue::BIG_DATA_SIZE_THRESHOLD),
                );
                let slice = input
                    .get(..size_to_read as usize)
                    .ok_or_else(|| Error::buffer("get_big_data_bytes"))?;
                big_data_buffer.extend_from_slice(slice);
                data_size_remaining -= size_to_read;
            }
        }
        Ok((
            data_type.get_value_bytes(&big_data_buffer[..]),
            data_offsets_absolute.iter().map(|x| *x as usize).collect(),
        ))
    }

    fn parse_big_data_size(file_info: &FileInfo, offset: u32) -> IResult<&[u8], i32> {
        let slice = file_info
            .buffer
            .get(file_info.hbin_offset_absolute + offset as usize..)
            .ok_or(nom::Err::Error(nom::error::Error {
                input: &file_info.buffer[..],
                code: nom::error::ErrorKind::Eof,
            }))?;
        le_i32(slice)
    }

    fn parse_big_data_offsets<'a>(&self, file_info: &'a FileInfo) -> IResult<&'a [u8], Vec<u32>> {
        let slice = file_info
            .buffer
            .get(
                file_info.hbin_offset_absolute
                    + self.segment_list_offset_relative as usize..,
            )
            .ok_or(nom::Err::Error(nom::error::Error {
                input: &file_info.buffer[..],
                code: nom::error::ErrorKind::Eof,
            }))?;
        let (input, _size) = le_u32(slice)?;
        let (_, list) = count(le_u32, self.count as usize)(input)?;
        Ok((input, list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_big_data_block() {
        assert!(CellBigData::is_big_data_block(&[0, 0, 0, 0, 0x64, 0x62]));
        assert!(!CellBigData::is_big_data_block(&[0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_parse_big_data_size() {
        let file_info = FileInfo {
            hbin_offset_absolute: 0,
            buffer: [0, 1, 2, 3].to_vec(),
        };
        let (input, size) = CellBigData::parse_big_data_size(&file_info, 0).unwrap();
        assert_eq!(size, 0x03020100);
        assert_eq!(input, &[0; 0]);
    }

    #[test]
    fn test_parse_big_data_offsets() {
        let file_info = FileInfo {
            hbin_offset_absolute: 0,
            buffer: [
                0xF0, 0xFF, 0xFF, 0xFF, 0x20, 0x30, 0x00, 0x00, 0x20, 0x70, 0x00, 0x00,
            ]
            .to_vec(),
        };

        let cell_big_data = CellBigData {
            size: 0,
            count: 2,
            segment_list_offset_relative: 0,
            logs: Logs::default(),
        };
        let (_, offsets) = cell_big_data.parse_big_data_offsets(&file_info).unwrap();
        assert_eq!(vec![0x00003020, 0x00007020], offsets);
    }

    #[test]
    fn test_parse_sub_key_list_db() {
        let slice = [
            0xF0, 0xFF, 0xFF, 0xFF, 0x64, 0x62, 0x02, 0x00, 0xD8, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let (_, (big_data, _)) = CellBigData::from_bytes(&slice).unwrap();
        let expected_output = CellBigData {
            size: 16,
            count: 2,
            segment_list_offset_relative: 472,
            logs: Logs::default(),
        };

        assert_eq!(expected_output, big_data);
    }

    #[test]
    fn test_get_big_data_bytes() {
        let file_info = FileInfo {
            hbin_offset_absolute: 0,
            buffer: [
                0xF0, 0xFF, 0xFF, 0xFF, 0x20, 0x30, 0x00, 0x00, 0x20, 0x70, 0x00, 0x00,
            ]
            .to_vec(),
        };
        let res =
            CellBigData::get_big_data_bytes(&file_info, 20, &CellKeyValueDataTypes::REG_DWORD, 4);
        assert_eq!(Err(Error::buffer("get_big_data_bytes")), res);
    }
}
