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
pub struct SubKeyListLf {
    pub size: u32,
    pub count: u16,
    pub items: Vec<SubKeyListLfItem> // Vec size = count
}

impl hive_bin_cell::CellSubKeyList for SubKeyListLf {
    fn size(&self) -> u32 {
        self.size
    }

    fn get_offset_list(&self, hbin_offset: u32) -> Vec<u32> {
        self.items.iter().map(|x| x.named_key_offset + hbin_offset).collect()
    }
}

impl SubKeyListLf {
    /// Uses nom to parse an lf sub key list (lf) hive bin cell.
    fn from_bytes_direct(input: &[u8]) -> IResult<&[u8], Self> {
        let start_pos = input.as_ptr() as usize;
        let (input, size)       = le_i32(input)?;
        let (input, _signature) = tag("lf")(input)?;
        let (input, count)      = le_u16(input)?;
        let (input, items)      = nom::multi::count(SubKeyListLfItem::from_bytes(), count.into())(input)?;

        let size_abs = size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            SubKeyListLf {
                size: size_abs,
                count,
                items
            },
        ))
    }

    pub fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn hive_bin_cell::CellSubKeyList>> {
        |input: &[u8]| {
            let (input, ret) = SubKeyListLf::from_bytes_direct(input)?;
            Ok((
                input,
                Box::new(ret)
            ))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLfItem {
    pub named_key_offset: u32, // The offset value is in bytes and relative from the start of the hive bin data
    pub name_hint: String, // The first 4 ASCII characters of a key name string (used to speed up lookups)
    pub parse_warnings: Warnings
}

impl SubKeyListLfItem {
    fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        |input: &[u8]| {
            let (input, named_key_offset) = le_u32(input)?;
            let (input, name_hint) = take!(input, 4usize)?;
            let mut parse_warnings = Warnings::new();
            Ok((
                input,
                SubKeyListLfItem {
                    named_key_offset,
                    name_hint: util::from_utf8(&name_hint, &mut parse_warnings, "SubKeyListLfItem::key_name"),
                    parse_warnings
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
    fn test_sub_key_list_lf_traits() {
        let lf = SubKeyListLf {
            size: 64,
            count: 2,
            items: vec![SubKeyListLfItem { named_key_offset: 12345, name_hint: "aaaa".to_string(), parse_warnings: Warnings::new() },
                        SubKeyListLfItem { named_key_offset: 54321, name_hint: "zzzz".to_string(), parse_warnings: Warnings::new()  }]
        };
        assert_eq!(lf.size, lf.size());
        assert_eq!(vec![16441, 58417], lf.get_offset_list(4096));
    }

    #[test]
    fn test_parse_sub_key_list_lf() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4360..4384];
        let ret = SubKeyListLf::from_bytes_direct(slice);

        let expected_output = SubKeyListLf {
            size: 24,
            count: 2,
            items: vec![
                SubKeyListLfItem {
                    named_key_offset: 105464,
                    name_hint: "Scre".to_string(),
                    parse_warnings: Warnings::new()
                },
                SubKeyListLfItem {
                    named_key_offset: 105376,
                    name_hint: "Scre".to_string(),
                    parse_warnings: Warnings::new()
                }
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
