use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_i32, le_u32}
};
use std::convert::TryFrom;
use crate::hive_bin_cell;
use crate::hive_bin_cell_key_node;
use crate::util;
use crate::hive_bin_cell::HiveBinCellSubKeyList;
use crate::err::Error;

// List of subkeys lists (used to subdivide subkeys lists)
#[derive(Debug, Eq, PartialEq)]
pub struct SubKeyListRi {
    pub size: u32,
    pub signature: [u8; 2], // "ri"
    pub count: u16,
    pub items: Vec<SubKeyListRiItem> // Vec size = count
}

impl hive_bin_cell::HiveBinCellSubKeyList for SubKeyListRi {    
    fn size(&self) -> u32 {
        self.size
    }

    fn signature(&self) -> [u8;2] {
        self.signature
    }
    
    fn offsets(&self, hbin_offset: u32) -> Vec<u32> {
        self.items.iter().map(|x| x.sub_key_list_offset + hbin_offset).collect()
    }
}

impl SubKeyListRi {    
    pub fn parse_offsets<'a>(&self, file_buffer: &'a [u8], hbin_offset: u32) -> IResult<&'a [u8], Vec<u32>> {
        let mut list: Vec<u32> = Vec::new();
        for item in self.items.iter() {
            let nom_ret_sub_list = hive_bin_cell_key_node::parse_sub_key_list(file_buffer, 0, item.sub_key_list_offset, hbin_offset);
            match nom_ret_sub_list {
                Ok((_, mut sub_list)) => {
                    list.append(&mut sub_list);
                },
                Err(e) => { return Err(e) }
            }
        }
        Ok((file_buffer, list))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SubKeyListRiItem {
    pub sub_key_list_offset: u32, // The offset value is in bytes and relative from the start of the hive bin data
}

 fn parse_sub_key_list_ri_item() -> impl Fn(&[u8]) -> IResult<&[u8], SubKeyListRiItem> {
    |input: &[u8]| {
        let (input, sub_key_list_offset) = le_u32(input)?;
        
        Ok((
            input,
            SubKeyListRiItem {
                sub_key_list_offset
            },
        ))
    }
}

/*pub fn parse_sub_key_list_ri<'a>(file_buffer: &'a [u8]) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Box<dyn hive_bin_cell::HiveBinCellSubKeyList>> {
    |input: &[u8]| {
        let (input, ret) = parse_sub_key_list_ri_internal(input, file_buffer)?;
        
        Ok((
            input,
            Box::new(ret)
        ))
    }
}*/

/// Uses nom to parse an ri sub key list (ri) hive bin cell.
pub fn parse_sub_key_list_ri<'a>(input: &'a [u8]) -> IResult<&'a [u8], SubKeyListRi> {
    let start_pos = input.as_ptr() as usize;
    let (input, size)         = le_i32(input)?;
    let (input, signature)    = tag("ri")(input)?;
    let (input, count)        = le_u16(input)?;
    let (input, list_offsets) = nom::multi::count(parse_sub_key_list_ri_item(), count.into())(input).unwrap();

    let size_abs = size.abs() as u32;
    let (input, _) = util::eat_remaining(input, size_abs as usize, input.as_ptr() as usize - start_pos)?;

    Ok((
        input,
        SubKeyListRi {
            size: size_abs,
            signature: <[u8; 2]>::try_from(signature).unwrap(),
            count,
            items: list_offsets
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;    
    
    #[test]
    fn test_sub_key_list_ri_traits() {
        let ri = SubKeyListRi {
            size: 64,
            signature: [114, 105], // "ri"
            count: 2,
            items: vec![SubKeyListRiItem { sub_key_list_offset: 12345 },
                        SubKeyListRiItem { sub_key_list_offset: 54321 }]
        };        
        assert_eq!(ri.size, ri.size());
        assert_eq!(ri.signature, ri.signature());
        assert_eq!(vec![16441, 58417], ri.offsets(4096));             
    }

    #[test]
    fn test_parse_sub_key_list_ri() {
        let f = std::fs::read("test_data/ManySubkeysHive").unwrap();
        let slice = &f[5920..5968];
        let ret = parse_sub_key_list_ri(slice);
        let expected_output = SubKeyListRi {
            size: 48,
            signature: [114, 105],
            count: 9,
            items: vec![
                SubKeyListRiItem {
                    sub_key_list_offset: 49184,
                },
                SubKeyListRiItem {
                    sub_key_list_offset: 176160,
                },
                SubKeyListRiItem {
                    sub_key_list_offset: 225312,
                },
                SubKeyListRiItem {
                    sub_key_list_offset: 274464,
                },
                SubKeyListRiItem {
                    sub_key_list_offset: 323616,
                },
                SubKeyListRiItem {
                    sub_key_list_offset: 372768,
                },
                SubKeyListRiItem {
                    sub_key_list_offset: 421920,
                },
                SubKeyListRiItem {
                    sub_key_list_offset: 471072,
                },
                SubKeyListRiItem {
                    sub_key_list_offset: 98336,
                },
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
