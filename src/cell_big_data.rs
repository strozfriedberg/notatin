use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32}
};
use serde::Serialize;
use crate::hive_bin_cell;
use crate::util;

/* List of data segments. Big data is used to reference data larger than 16344 bytes  
   When the Minor version field of the base block is greater than 3, it has the following structure: */
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellBigData {
    #[serde(skip_serializing)]
    pub size: u32,
    #[serde(skip_serializing)]
    pub count: u16,
    #[serde(skip_serializing)]
    pub segment_list_offset: u32, // relative to the start of the hive bin
    pub items: Vec<CellBigDataItem> // Vec size = count
}

impl hive_bin_cell::Cell for CellBigData {    
    fn size(&self) -> u32 {
        self.size
    }

    fn name_lowercase(&self) -> Option<String> {
        None
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellBigDataItem {
    pub data_segment_offset: u32, // The offset value is in bytes and relative from the start of the hive bin data
 }
 
/// Uses nom to parse a big data (db) hive bin cell.
fn parse_cell_big_data_internal(input: &[u8]) -> IResult<&[u8], CellBigData> {
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
            segment_list_offset,
            items: Vec::new()
        },
    ))
}


#[cfg(test)]
mod tests {
    use super::*;
        
    #[test]
    fn test_parse_sub_key_list_db() {
        let f = std::fs::read("test_data/FuseHive").unwrap();
        let slice = &f[4552..4568];
        let ret = parse_cell_big_data_internal(slice);
        let expected_output = CellBigData {
            size: 16,
            count: 2,
            segment_list_offset: 472,
            items: Vec::new()
        };
        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(
            expected,
            ret
        );
    }
}