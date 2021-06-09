use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32},
    multi::count
};
use serde::Serialize;
use crate::err::Error;
use crate::file_info::FileInfo;
use crate::state::State;
use crate::hive_bin_cell;
use crate::cell_key_value::{CellKeyValueDataTypes, CellKeyValue};
use crate::log::Logs;

/* List of data segments. Big data is used to reference data larger than 16344 bytes
   When the Minor version field of the base block is greater than 3, it has the following structure: */
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellBigData {
    pub size: u32,
    pub count: u16,
    pub segment_list_offset_relative: u32, // relative to the start of the hive bin
    pub logs: Logs
}

impl CellBigData {
    pub(crate) fn is_big_data_block(input: &[u8]) -> bool {
        tag::<&str, &[u8], nom::error::Error<&[u8]>>("db")(&input[4..]).map_or(false, |_| true)
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
                    size: size.abs() as u32,
                    count,
                    segment_list_offset_relative,
                    logs: Logs::default()
                },
                offset
            )
        ))
    }

    /// Returns a tuple of the full content buffer and the absolute data offsets
    pub(crate) fn get_big_data_bytes(
        file_info: &FileInfo,
        state: &mut State,
        offset: usize,
        data_type: &CellKeyValueDataTypes,
        data_size: u32
    ) -> Result<(Vec<u8>, Vec<usize>), Error> {
        let (_, (hive_bin_cell_big_data, offset_ptr)) = CellBigData::from_bytes(&file_info.buffer[offset..])?;
        let (_, data_offsets_absolute) = hive_bin_cell_big_data.parse_big_data_offsets(file_info)?;

        state.update_track_cells(file_info.get_file_offset_from_ptr(offset_ptr));
        let mut big_data_buffer: Vec<u8> = Vec::new();
        let mut data_size_remaining = data_size;
        for offset in data_offsets_absolute.iter() {
            if data_size_remaining > 0 {
                let (input, size) = CellBigData::parse_big_data_size(file_info, *offset)?;
                let size_to_read =
                    std::cmp::min(
                        size.abs() as u32,
                        std::cmp::min(
                            data_size_remaining,
                            CellKeyValue::BIG_DATA_SIZE_THRESHOLD
                        )
                    );
                state.update_track_cells(*offset as usize);
                big_data_buffer.extend_from_slice(&input[..size_to_read as usize]);
                data_size_remaining -= size_to_read;
            }
        }
        Ok((data_type.get_value_bytes(&big_data_buffer[..]), data_offsets_absolute.iter().map(|x| *x as usize).collect()))
    }

    fn parse_big_data_size(
        file_info: &FileInfo,
        offset: u32,
    ) -> IResult<&[u8], i32> {
        le_i32(&file_info.buffer[file_info.hbin_offset_absolute + offset as usize..])
    }

    fn parse_big_data_offsets<'a>(
        &self,
        file_info: &'a FileInfo
    ) -> IResult<&'a [u8], Vec<u32>> {
        let (input, _size) = le_u32(&file_info.buffer[file_info.hbin_offset_absolute + self.segment_list_offset_relative as usize..])?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sub_key_list_db() {
        let f = std::fs::read("test_data/FuseHive").unwrap();
        let slice = &f[4552..4568];
        let (_, (big_data, _)) = CellBigData::from_bytes(slice).unwrap();
        let expected_output =
            CellBigData {
                size: 16,
                count: 2,
                segment_list_offset_relative: 472,
                logs: Logs::default()
            };

        assert_eq!(
            expected_output,
            big_data
        );
    }
}