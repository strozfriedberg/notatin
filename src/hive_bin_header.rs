use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u32, le_u64}
};
use serde::Serialize;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct HiveBinHeader {
    pub offset_from_first_hbin: u32, // The offset of the hive bin, Value in bytes and relative from the start of the hive bin data
    pub size: u32, // Size of the hive bin
    pub unknown1: u32, // 0 most of the time, can contain remnant data
    pub unknown2: u32, // 0 most of the time, can contain remnant data
    pub timestamp: u64, // Only the root (first) hive bin seems to contain a valid FILETIME
    pub unknown4: u32, // Contains number of bytes
}

pub fn parse_hive_bin_header(input: &[u8]) -> IResult<&[u8], HiveBinHeader> {
    let (input, _signature) = tag("hbin")(input)?;
    let (input, offset_from_first_hbin) = le_u32(input)?;
    let (input, size) = le_u32(input)?;
    let (input, unknown1) = le_u32(input)?;
    let (input, unknown2) = le_u32(input)?;
    let (input, timestamp) = le_u64(input)?;
    let (input, unknown4) = le_u32(input)?;

    let hbh = HiveBinHeader {
        offset_from_first_hbin,
        size,
        unknown1,
        unknown2,
        timestamp,
        unknown4
    };

    Ok((
        input,
        hbh
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hive_bin_header() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let ret = parse_hive_bin_header(&f[4096..4128]);

        let expected_output = HiveBinHeader {
            offset_from_first_hbin: 0,
            size: 4096,
            unknown1: 0,
            unknown2: 0,
            timestamp: 129782121007374460,
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
