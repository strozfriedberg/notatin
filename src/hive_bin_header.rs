use crate::file_info::FileInfo;
use crate::util;
use chrono::{DateTime, Utc};
use nom::{
    bytes::complete::tag,
    number::complete::{le_u32, le_u64},
    IResult,
};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HiveBinHeader {
    /// The absolute offset of the hive bin, calculated at parse time
    pub file_offset_absolute: usize,
    /// The offset of the hive bin, Value in bytes and relative from the start of the hive bin data
    pub offset_from_first_hbin: u32,
    /// Size of the hive bin
    pub size: u32,
    /// 0 most of the time, can contain remnant data
    pub unknown1: u32,
    /// 0 most of the time, can contain remnant data
    pub unknown2: u32,
    /// Only the first hive bin contains a valid FILETIME. The timestamp in the header of the first hive bin acts as a backup copy of a Last written timestamp in the base block.
    pub timestamp: DateTime<Utc>,
    /// The Spare field is used when shifting hive bins and cells in memory. In Windows 2000, the same field is called MemAlloc, it is used to track memory allocations for hive bins.
    pub spare: u32,
}

impl HiveBinHeader {
    pub(crate) fn from_bytes<'a>(file_info: &FileInfo, input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let file_offset_absolute = file_info.get_file_offset(input);
        let (input, _signature) = tag("hbin")(input)?;
        let (input, offset_from_first_hbin) = le_u32(input)?;
        let (input, size) = le_u32(input)?;
        let (input, unknown1) = le_u32(input)?;
        let (input, unknown2) = le_u32(input)?;
        let (input, timestamp) = le_u64(input)?;
        let (input, spare) = le_u32(input)?;

        let hbh = HiveBinHeader {
            file_offset_absolute,
            offset_from_first_hbin,
            size,
            unknown1,
            unknown2,
            timestamp: util::get_date_time_from_filetime(timestamp),
            spare,
        };

        Ok((input, hbh))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hive_bin_header() {
        let buffer = [
            0x68, 0x62, 0x69, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x60, 0xD7, 0xC4, 0x26, 0x14, 0xCD, 0x01,
            0x00, 0x00, 0x00, 0x00,
        ];

        let file_info = FileInfo {
            hbin_offset_absolute: 4096,
            buffer: buffer.to_vec(),
        };

        let ret = HiveBinHeader::from_bytes(&file_info, &file_info.buffer[..]);

        let expected_output = HiveBinHeader {
            file_offset_absolute: 0,
            offset_from_first_hbin: 0,
            size: 4096,
            unknown1: 0,
            unknown2: 0,
            timestamp: util::get_date_time_from_filetime(129782121007374460),
            spare: 0,
        };

        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(expected, ret);
    }
}
