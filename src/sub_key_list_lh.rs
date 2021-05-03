use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_i32, le_u32}
};
use serde::Serialize;
use crate::hive_bin_cell;
use crate::util;
use crate::warn::Warnings;

// Subkeys list with name hints
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLh {
    pub size: u32,
    pub count: u16,
    pub items: Vec<SubKeyListLhItem> // Vec size = count
}

impl SubKeyListLh {
    /// Uses nom to parse an lf sub key list (lf) hive bin cell.
    fn from_bytes_direct(input: &[u8]) -> IResult<&[u8], Self> {
        let start_pos = input.as_ptr() as usize;
        let (input, size)       = le_i32(input)?;
        let (input, _signature) = tag("lh")(input)?;
        let (input, count)      = le_u16(input)?;
        let (input, items)      = nom::multi::count(SubKeyListLhItem::from_bytes(), count.into())(input)?;

        let size_abs = size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            SubKeyListLh {
                size: size_abs,
                count,
                items
            },
        ))
    }

    pub fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn hive_bin_cell::CellSubKeyList>> {
        |input: &[u8]| {
            let (input, ret) = SubKeyListLh::from_bytes_direct(input)?;
            Ok((
                input,
                Box::new(ret)
            ))
        }
    }
}

impl hive_bin_cell::CellSubKeyList for SubKeyListLh {
    fn size(&self) -> u32 {
        self.size
    }

    fn get_offset_list(&self, hbin_offset: u32, parse_warnings: &mut Warnings) -> Vec<u32> {
        self.items.iter().map(|x| x.named_key_offset + hbin_offset).collect()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLhItem {
    pub named_key_offset: u32, // The offset value is in bytes and relative from the start of the hive bin data
    pub name_hash: u32, // Hash of a key name string (used to speed up lookups). A different hash function is used for different sub key list types.
}

impl SubKeyListLhItem {
    fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hive_bin_cell::CellSubKeyList;

    #[test]
    fn test_sub_key_list_lh_traits() {
        let lh = SubKeyListLh {
            size: 64,
            count: 2,
            items: vec![SubKeyListLhItem { named_key_offset: 12345, name_hash: 1111 },
                        SubKeyListLhItem { named_key_offset: 54321, name_hash: 2222 }]
        };
        assert_eq!(lh.size, lh.size());
        assert_eq!(vec![16441, 58417], lh.get_offset_list(4096, &mut Warnings::new()));
    }

    #[test]
    fn test_parse_sub_key_list_lh() {
        let f = std::fs::read("test_data/lh_block").unwrap();
        let slice = &f[..];
        let ret = SubKeyListLh::from_bytes_direct(slice);

        let expected_output = SubKeyListLh {
            size: 96,
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
