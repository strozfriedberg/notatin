use nom::{
    IResult,
    Finish,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32}
};
use std::convert::TryFrom;
use std::io::{Cursor, Read};
use winstructs::security::SecurityDescriptor;
use crate::hive_bin_cell;
use crate::util;
use crate::err::Error;

// Security descriptor
#[derive(Debug, Eq, PartialEq)]
pub struct HiveBinCellKeySecurity {
    pub size: u32,
    pub signature: [u8; 2], // "sk"
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
    pub security_descriptor: Vec<u8>
}

impl hive_bin_cell::HiveBinCell for HiveBinCellKeySecurity {    
    fn size(&self) -> u32 {
        self.size
    }

    fn signature(&self) -> [u8;2] {
        self.signature
    }

    fn name_lowercase(&self) -> Option<String> {
        None
    }
}

pub fn read_hive_bin_cell_key_security(file_buffer: &[u8], security_key_offset: u32, hbin_offset: u32) -> Result<Vec<SecurityDescriptor>, Error> {
    let mut security_descriptors = Vec::new();
    let mut offset: usize = security_key_offset as usize;
    loop {    
        let input = &file_buffer[offset + hbin_offset as usize..];
        match parse_hive_bin_cell_key_security(input).finish() {
            Ok((_, hive_bin_cell_key_security)) => {
                let res_security_descriptor = SecurityDescriptor::from_stream(&mut Cursor::new(hive_bin_cell_key_security.security_descriptor));
                match res_security_descriptor {
                    Ok(security_descriptor) => {
                        security_descriptors.push(security_descriptor);
                    },
                    Err(e) => {
                        // log error as warning and keep going
                    }
                }       
                if hive_bin_cell_key_security.flink == security_key_offset {
                    break;
                }                
                offset = hive_bin_cell_key_security.flink as usize;
            },
            Err(e) => return Err(Error::Nom { detail: format!("read_hive_bin: hive_bin_header::parse_hive_bin_header {:#?}", e) })
        }
    }
    Ok(security_descriptors)
}

/// Uses nom to parse a key security (sk) hive bin cell.
pub fn parse_hive_bin_cell_key_security(input: &[u8]) -> IResult<&[u8], HiveBinCellKeySecurity> {
    let start_pos = input.as_ptr() as usize;
    let (input, size) = le_i32(input)?;
    let (input, signature) = tag("sk")(input)?;
    let (input, unknown1) = le_u16(input)?;
    let (input, flink) = le_u32(input)?;
    let (input, blink) = le_u32(input)?;
    let (input, reference_count) = le_u32(input)?;
    let (input, security_descriptor_size) = le_u32(input)?;
    let (input, security_descriptor) = take!(input, security_descriptor_size)?;

    let size_abs = size.abs() as u32;
    let (input, _) = util::eat_remaining(input, size_abs as usize, input.as_ptr() as usize - start_pos)?;

    Ok((
        input,
        HiveBinCellKeySecurity {
            size: size_abs,
            signature: <[u8; 2]>::try_from(signature).unwrap(),
            unknown1,
            flink,
            blink,
            reference_count,
            security_descriptor_size,
            security_descriptor: security_descriptor.to_vec()
        },
    ))
}


#[cfg(test)]
mod tests {
    use super::*;
        
    #[test]
    pub fn test_parse_hive_bin_cell_key_security() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[5472..5736];
        let ret = parse_hive_bin_cell_key_security(slice);

        let expected_output = HiveBinCellKeySecurity {
            size: 264,
            signature: [115, 107],
            unknown1: 0,
            flink: 232704,
            blink: 234848,
            reference_count: 1,
            security_descriptor_size: 156,
            security_descriptor: vec![1, 0, 4, 144, 128, 0, 0, 0, 144, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 108, 0, 4, 0, 0, 0, 0, 3, 36, 0, 63, 0, 15, 0, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 151, 42, 103, 121, 160, 84, 74, 182, 25, 135, 40, 126, 81, 4, 0, 0, 0, 3, 20, 0, 63, 0, 15, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 3, 24, 0, 63, 0, 15, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 0, 3, 20, 0, 25, 0, 2, 0, 1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 ]
        };

        let remaining: [u8; 0] = [];

        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(
            expected,
            ret
        );
    }
}