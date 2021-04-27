use nom::{
    IResult,
    Finish,
    bytes::complete::tag,
    number::complete::{le_u32, le_u64}
};
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use crate::hive_bin_cell;
use crate::hive_bin_cell_key_security;
use crate::hive_bin_cell_key_node;
use crate::hive_bin_cell_key_value;
use crate::hive_bin_cell_big_data;
use crate::sub_key_list_lf;
use crate::sub_key_list_lh;
use crate::sub_key_list_li;
use crate::sub_key_list_ri;
use crate::filter;
use crate::err::Error;

#[derive(Debug, Eq, PartialEq)]
pub struct HiveBinHeader {
    pub signature: [u8; 4], // "hbin"
    pub offset_from_first_hbin: u32, // The offset of the hive bin, Value in bytes and relative from the start of the hive bin data
    pub size: u32, // Size of the hive bin
    pub unknown1: u32, // 0 most of the time, can contain remnant data
    pub unknown2: u32, // 0 most of the time, can contain remnant data
    pub timestamp: u64, // Only the root (first) hive bin seems to contain a valid FILETIME
    pub unknown4: u32, // Contains number of bytes
}

pub fn parse_hive_bin_header<'a>(input: &'a [u8]) -> IResult<&'a [u8], HiveBinHeader> {
    let (input, signature) = tag("hbin")(input)?;
    let (input, offset_from_first_hbin) = le_u32(input)?;
    let (input, size) = le_u32(input)?;
    let (input, unknown1) = le_u32(input)?;
    let (input, unknown2) = le_u32(input)?;
    let (input, timestamp) = le_u64(input)?;
    let (input, unknown4) = le_u32(input)?;

    let hbh = HiveBinHeader {
        signature: <[u8; 4]>::try_from(signature).unwrap(),
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
            signature: [104, 98, 105, 110],
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
