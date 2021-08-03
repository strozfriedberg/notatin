use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_i32, le_u32}
};
use serde::Serialize;
use crate::state::State;
use crate::file_info::FileInfo;
use crate::hive_bin_cell;
use crate::cell_key_node::CellKeyNode;
use crate::util;
use crate::err::Error;

// List of subkeys lists (used to subdivide subkeys lists)
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListRi {
    pub size: u32,
    pub count: u16,
    pub items: Vec<SubKeyListRiItem> // Vec size = count
}

impl hive_bin_cell::CellSubKeyList for SubKeyListRi {
    fn size(&self) -> u32 {
        self.size
    }

    fn get_offset_list(&self, hbin_offset_absolute: u32) -> Vec<u32> {
        self.items.iter().map(|x| x.sub_key_list_offset_relative + hbin_offset_absolute).collect()
    }
}

impl SubKeyListRi {
    /// Uses nom to parse an ri sub key list (ri) hive bin cell.
    pub(crate) fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let start_pos = input.as_ptr() as usize;
        let (input, size)         = le_i32(input)?;
        let (input, _signature)   = tag("ri")(input)?;
        let (input, count)        = le_u16(input)?;
        let (input, list_offsets) = nom::multi::count(parse_sub_key_list_ri_item(), count.into())(input)?;

        let size_abs = size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            SubKeyListRi {
                size: size_abs,
                count,
                items: list_offsets
            },
        ))
    }

    pub(crate) fn parse_offsets(
        &self,
        file_info: &FileInfo,
        state: &mut State
    ) -> Result<Vec<u32>, Error> {
        let mut list: Vec<u32> = Vec::new();
        for item in self.items.iter() {
            let mut sub_list = CellKeyNode::parse_sub_key_list(file_info, state, item.sub_key_list_offset_relative)?;
            list.append(&mut sub_list);
        }
        Ok(list)
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListRiItem {
    pub sub_key_list_offset_relative: u32, // The offset value is in bytes and relative from the start of the hive bin data
}

 fn parse_sub_key_list_ri_item() -> impl Fn(&[u8]) -> IResult<&[u8], SubKeyListRiItem> {
    |input: &[u8]| {
        let (input, sub_key_list_offset_relative) = le_u32(input)?;

        Ok((
            input,
            SubKeyListRiItem {
                sub_key_list_offset_relative
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hive_bin_cell::CellSubKeyList;

    #[test]
    fn test_sub_key_list_ri_traits() {
        let ri = SubKeyListRi {
            size: 64,
            count: 2,
            items: vec![SubKeyListRiItem { sub_key_list_offset_relative: 12345 },
                        SubKeyListRiItem { sub_key_list_offset_relative: 54321 }]
        };
        assert_eq!(ri.size, ri.size());
        assert_eq!(vec![16441, 58417], ri.get_offset_list(4096));
    }

    #[test]
    fn test_parse_sub_key_list_ri() {
        let f = std::fs::read("test_data/ManySubkeysHive").unwrap();
        let slice = &f[5920..5968];
        let ret = SubKeyListRi::from_bytes(slice);
        let expected_output = SubKeyListRi {
            size: 48,
            count: 9,
            items: vec![
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 49184,
                },
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 176160,
                },
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 225312,
                },
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 274464,
                },
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 323616,
                },
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 372768,
                },
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 421920,
                },
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 471072,
                },
                SubKeyListRiItem {
                    sub_key_list_offset_relative: 98336,
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
