use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_i32, le_u32}
};
use std::convert::TryFrom;
use crate::hive_bin_cell;
use crate::util;

// Subkeys list with name hints
#[derive(Debug, Eq, PartialEq)]
pub struct SubKeyListLh {
    pub size: u32,
    pub signature: [u8; 2], // "lh"
    pub count: u16,
    pub items: Vec<SubKeyListLhItem> // Vec size = count
}

impl hive_bin_cell::HiveBinCellSubKeyList for SubKeyListLh {    
    fn size(&self) -> u32 {
        self.size
    }

    fn signature(&self) -> [u8;2] {
        self.signature
    }
    
    fn offsets(&self, hbin_offset: u32) -> Vec<u32> {
        self.items.iter().map(|x| x.named_key_offset + hbin_offset).collect()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SubKeyListLhItem {
    pub named_key_offset: u32, // The offset value is in bytes and relative from the start of the hive bin data
    pub name_hash: u32, // Hash of a key name string (used to speed up lookups). A different hash function is used for different sub key list types.
}

fn parse_sub_key_list_lh_item() -> impl Fn(&[u8]) -> IResult<&[u8], SubKeyListLhItem> {
    |input: &[u8]| {
        let (input, named_key_offset) = le_u32(input)?;
        let (input, name_hash) = le_u32(input)?;
        
        Ok((
            input,
            SubKeyListLhItem {
                named_key_offset,
                name_hash
            },
        ))
    }
}

pub fn parse_sub_key_list_lh() -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn hive_bin_cell::HiveBinCellSubKeyList>> {
    |input: &[u8]| {
        let (input, ret) = parse_sub_key_list_lh_internal(input)?;
        Ok((
            input,
            Box::new(ret)
        ))
    }
}

/// Uses nom to parse an lh sub key list (lh) hive bin cell.
fn parse_sub_key_list_lh_internal(input: &[u8]) -> IResult<&[u8], SubKeyListLh> {
    let start_pos = input.as_ptr() as usize;
    let (input, size)      = le_i32(input)?;
    let (input, signature) = tag("lh")(input)?;
    let (input, count)     = le_u16(input)?;
    let (input, items)     = nom::multi::count(parse_sub_key_list_lh_item(), count.into())(input)?;

    let size_abs = size.abs() as u32;
    let (input, _) = util::parser_eat_remaining(input, size_abs as usize, input.as_ptr() as usize - start_pos)?;

    Ok((
        input,
        SubKeyListLh {
            size: size_abs,
            signature: <[u8; 2]>::try_from(signature).unwrap(), // todo: handle unwrap
            count,
            items: items
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;   
    use crate::hive_bin_cell::HiveBinCellSubKeyList; 
    
    #[test]
    fn test_sub_key_list_lh_traits() {
        let lh = SubKeyListLh {
            size: 64,
            signature: [108, 105], // "lh"
            count: 2,
            items: vec![SubKeyListLhItem { named_key_offset: 12345, name_hash: 1111 },
                        SubKeyListLhItem { named_key_offset: 54321, name_hash: 2222 }]
        };        
        assert_eq!(lh.size, lh.size());
        assert_eq!(lh.signature, lh.signature());
        assert_eq!(vec![16441, 58417], lh.offsets(4096));             
    }

    #[test]
    fn test_parse_sub_key_list_lh() {
        let f = std::fs::read("test_data/lh_block").unwrap();
        let slice = &f[..];
        let ret = parse_sub_key_list_lh_internal(slice);

        let expected_output = SubKeyListLh {
            size: 96,
            signature: [108, 104],
            count: 8,
            items: vec![
                SubKeyListLhItem {named_key_offset:4600, name_hash:129374869},
                SubKeyListLhItem {named_key_offset:7008, name_hash:97615},
                SubKeyListLhItem {named_key_offset:7536, name_hash:397082278},
                SubKeyListLhItem {named_key_offset:7192, name_hash:2451360315},
                SubKeyListLhItem {named_key_offset:7440, name_hash:235888890},
                SubKeyListLhItem {named_key_offset:6376, name_hash:2289207844},
                SubKeyListLhItem {named_key_offset:7096, name_hash:2868760012},
                SubKeyListLhItem {named_key_offset:7352, name_hash:123397}
            ]
        };

        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_output));
        assert_eq!(
            expected,
            ret
        );
    }
}
