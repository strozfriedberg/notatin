use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32}
};
use std::convert::TryFrom;
use crate::hive_bin_cell;
use crate::util;

/* List of data segments. Big data is used to reference data larger than 16344 bytes  
   When the Minor version field of the base block is greater than 3, it has the following structure: */
#[derive(Debug, Eq, PartialEq)]
pub struct HiveBinCellBigData {
    pub size: u32,
    pub signature: [u8; 2], // "db"
    pub count: u16,
    pub segment_list_offset: u32, // relative to the start of the hive bin
    pub items: Vec<HiveBinCellBigDataItem> // Vec size = count
}

impl hive_bin_cell::HiveBinCell for HiveBinCellBigData {    
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

#[derive(Debug, Eq, PartialEq)]
pub struct HiveBinCellBigDataItem {
    pub data_segment_offset: u32, // The offset value is in bytes and relative from the start of the hive bin data
 }

 fn parse_hive_bin_cell_big_data_item() -> impl Fn(&[u8]) -> IResult<&[u8], HiveBinCellBigDataItem> {
    |input: &[u8]| {
        let (input, data_segment_offset) = le_u32(input)?;        
        Ok((
            input,
            HiveBinCellBigDataItem {
                data_segment_offset
            },
        ))
    }
}

pub fn parse_hive_bin_cell_big_data() -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn hive_bin_cell::HiveBinCell>> {
   move |input: &[u8]| {
       let (input, ret) = parse_hive_bin_cell_big_data_internal(input)?;     
       Ok((
           input,
           Box::new(ret)
       ))
   }
}
 
/// Uses nom to parse a big data (db) hive bin cell.
fn parse_hive_bin_cell_big_data_internal(input: &[u8]) -> IResult<&[u8], HiveBinCellBigData> {
    let start_pos = input.as_ptr() as usize;
    let (input, size) = le_i32(input)?;
    let (input, signature) = tag("db")(input)?;
    let (input, count) = le_u16(input)?;
    let (input, segment_list_offset) = le_u32(input)?;

    let size_abs = size.abs() as u32;
    let (input, _) = util::eat_remaining(input, size_abs as usize, input.as_ptr() as usize - start_pos)?;
   // let (input, items) = nom::multi::count(parse_hive_bin_cell_big_data(input), count.into())(input).unwrap();

    Ok((
        input,
        HiveBinCellBigData {
            size: size_abs,
            signature: <[u8; 2]>::try_from(signature).unwrap(),
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
        let ret = parse_hive_bin_cell_big_data_internal(slice);
        let expected_output = HiveBinCellBigData {
            size: 16,
            signature: [100, 98],
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