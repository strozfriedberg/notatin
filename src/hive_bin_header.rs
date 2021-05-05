use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u32, le_u64}
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use crate::registry::State;
use crate::util;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct HiveBinHeader {
    pub absolute_file_offset: usize,
    pub offset_from_first_hbin: u32, // The offset of the hive bin, Value in bytes and relative from the start of the hive bin data
    pub size: u32, // Size of the hive bin
    pub unknown1: u32, // 0 most of the time, can contain remnant data
    pub unknown2: u32, // 0 most of the time, can contain remnant data
    pub timestamp: DateTime<Utc>, // Only the root (first) hive bin seems to contain a valid FILETIME
    pub unknown4: u32, // Contains number of bytes
}

impl HiveBinHeader {
    pub fn from_bytes<'a>(state: &State, input: &'a[u8]) -> IResult<&'a[u8], Self> {
        let absolute_file_offset = state.get_file_offset(input);
        let (input, _signature) = tag("hbin")(input)?;
        let (input, offset_from_first_hbin) = le_u32(input)?;
        let (input, size) = le_u32(input)?;
        let (input, unknown1) = le_u32(input)?;
        let (input, unknown2) = le_u32(input)?;
        let (input, timestamp) = le_u64(input)?;
        let (input, unknown4) = le_u32(input)?;

        let hbh = HiveBinHeader {
            absolute_file_offset,
            offset_from_first_hbin,
            size,
            unknown1,
            unknown2,
            timestamp: util::get_date_time_from_filetime(timestamp),
            unknown4
        };

        Ok((
            input,
            hbh
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hive_bin_header() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let state = State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset: 4096,
            file_buffer: &f[..]
        };
        let ret = HiveBinHeader::from_bytes(&state, &f[4096..4128]);

        let expected_output = HiveBinHeader {
            absolute_file_offset: 4096,
            offset_from_first_hbin: 0,
            size: 4096,
            unknown1: 0,
            unknown2: 0,
            timestamp: util::get_date_time_from_filetime(129782121007374460),
            unknown4: 0
        };

        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(
            expected,
            ret
        );
    }
}
