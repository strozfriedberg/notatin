use nom::{
    IResult,
    Finish,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32},
    multi::count
};
use serde::Serialize;
use crate::hive_bin_cell;
use crate::cell_key_value::{CellKeyValueDataTypes, CellKeyValue};
use crate::cell_value::CellValue;
use crate::util;

/* List of data segments. Big data is used to reference data larger than 16344 bytes
   When the Minor version field of the base block is greater than 3, it has the following structure: */
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellBigData {
    pub size: u32,
    pub count: u16,
    pub segment_list_offset: u32, // relative to the start of the hive bin
}

impl CellBigData {
    /// Uses nom to parse a big data (db) hive bin cell.
    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let start_pos = input.as_ptr() as usize;
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("db")(input)?;
        let (input, count) = le_u16(input)?;
        let (input, segment_list_offset) = le_u32(input)?;

        let size_abs = size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs as usize, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            CellBigData {
                size: size_abs,
                count,
                segment_list_offset
            },
        ))
    }

    pub fn get_big_data_content(file_buffer: &[u8], offset: usize, hbin_offset: u32, data_type: CellKeyValueDataTypes, data_size: u32) -> (CellValue, Option<Vec<String>>) {
        match CellBigData::from_bytes(&file_buffer[offset..]).finish() {
            Ok((_, hive_bin_cell_big_data)) => {
                match CellBigData::parse_big_data_offsets(file_buffer, hive_bin_cell_big_data.count, hive_bin_cell_big_data.segment_list_offset as usize, hbin_offset).finish() {
                    Ok((_, data_offsets)) => {
                        let mut big_data_buffer: Vec<u8> = Vec::new();
                        let mut data_size_remaining = data_size;
                        for offset in data_offsets.iter() {
                            if data_size_remaining > 0 {
                                match CellBigData::parse_big_data_size(file_buffer, (offset + hbin_offset) as usize).finish() {
                                    Ok((input, size)) => {
                                        let mut size_to_read = std::cmp::min(size.abs() as u32, data_size_remaining);
                                        size_to_read = std::cmp::min(CellKeyValue::BIG_DATA_SIZE_THRESHOLD, size_to_read);
                                        big_data_buffer.extend_from_slice(&input[..(size_to_read-1) as usize]);
                                        data_size_remaining -= size_to_read;
                                    },
                                    Err(e) => {} //todo: add warning about missing data (error codes?)
                                }
                            }
                        }
                        return data_type.get_value_content(&big_data_buffer[..]);
                    },
                    Err(e) => {}
                }
            },
            Err(e) => {}
        }
        (CellValue::ValueNone,None)
    }

    fn parse_big_data_size(
        file_buffer: &[u8],
        offset: usize,
    ) -> IResult<&[u8], i32> {
        let (input, size) = le_i32(&file_buffer[offset..])?;
        Ok((input, size))
    }

    fn parse_big_data_offsets(
        file_buffer: &[u8],
        segments_count: u16,
        list_offset: usize,
        hbin_offset: u32
    ) -> IResult<&[u8], Vec<u32>> {
        let slice: &[u8] = &file_buffer[list_offset + (hbin_offset as usize)..];
        let (slice, _size) = le_u32(slice)?;
        let (_, list) = count(le_u32, segments_count as usize)(slice)?;

        Ok((
            slice,
            list
        ))
    }
}

impl hive_bin_cell::Cell for CellBigData {
    fn size(&self) -> u32 {
        self.size
    }

    fn name_lowercase(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sub_key_list_db() {
        let f = std::fs::read("test_data/FuseHive").unwrap();
        let slice = &f[4552..4568];
        let ret = CellBigData::from_bytes(slice);
        let expected_output = CellBigData {
            size: 16,
            count: 2,
            segment_list_offset: 472
        };
        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(
            expected,
            ret
        );
    }
}