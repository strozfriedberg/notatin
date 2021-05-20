use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32},
    multi::count
};
use serde::Serialize;
use crate::err::Error;
use crate::state::State;
use crate::hive_bin_cell;
use crate::cell_key_value::{CellKeyValueDataTypes, CellKeyValue};
use crate::util;
use crate::warn::Warnings;

/* List of data segments. Big data is used to reference data larger than 16344 bytes
   When the Minor version field of the base block is greater than 3, it has the following structure: */
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellBigData {
    pub size: u32,
    pub count: u16,
    pub segment_list_offset_relative: u32, // relative to the start of the hive bin
    pub parse_warnings: Warnings
}

impl CellBigData {
    pub(crate) fn is_big_data_block(input: &[u8]) -> bool {
        tag::<&str, &[u8], nom::error::Error<&[u8]>>("db")(&input[4..]).map_or(false, |_| true)
    }

    /// Uses nom to parse a big data (db) hive bin cell.
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let start_pos = input.as_ptr() as usize;
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("db")(input)?;
        let (input, count) = le_u16(input)?;
        let (input, segment_list_offset_relative) = le_u32(input)?;

        let size_abs = size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            CellBigData {
                size: size_abs,
                count,
                segment_list_offset_relative,
                parse_warnings: Warnings::default()
            },
        ))
    }

    pub(crate) fn get_big_data_bytes(state: &State, offset: usize, data_type: CellKeyValueDataTypes, data_size: u32) -> Result<Vec<u8>, Error> {
        let (_, hive_bin_cell_big_data) = CellBigData::from_bytes(&state.file_buffer[offset..])?;
        let (_, data_offsets_absolute)  = hive_bin_cell_big_data.parse_big_data_offsets(state)?;
        let mut big_data_buffer: Vec<u8> = Vec::new();
        let mut data_size_remaining = data_size;
        for offset in data_offsets_absolute.iter() {
            if data_size_remaining > 0 {
                let (input, size) = CellBigData::parse_big_data_size(state, *offset)?;
                let size_to_read = std::cmp::min(size.abs() as u32,
                                                 std::cmp::min(data_size_remaining, CellKeyValue::BIG_DATA_SIZE_THRESHOLD));
                big_data_buffer.extend_from_slice(&input[..(size_to_read-1) as usize]);
                data_size_remaining -= size_to_read;
            }
        }
        Ok(data_type.get_value_bytes(&big_data_buffer[..]))
    }

    fn parse_big_data_size(
        state: &State,
        offset: u32,
    ) -> IResult<&[u8], i32> {
        le_i32(&state.file_buffer[state.hbin_offset_absolute + offset as usize..])
    }

    fn parse_big_data_offsets<'a>(
        &self,
        state: &'a State
    ) -> IResult<&'a [u8], Vec<u32>> {
        let (input, _size) = le_u32(&state.file_buffer[state.hbin_offset_absolute + self.segment_list_offset_relative as usize..])?;
        let (_, list) = count(le_u32, self.count as usize)(input)?;
        Ok((
            input,
            list
        ))
    }
}

impl hive_bin_cell::Cell for CellBigData {
    fn size(&self) -> u32 {
        self.size
    }

    fn lowercase(&self) -> Option<String> {
        None
    }

    fn is_key(&self) -> bool {
        false
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
            segment_list_offset_relative: 472,
            parse_warnings: Warnings::default()
        };
        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(
            expected,
            ret
        );
    }
}