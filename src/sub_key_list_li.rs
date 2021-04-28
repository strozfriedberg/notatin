use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_i32, le_u32}
};
use serde::Serialize;
use crate::hive_bin_cell;
use crate::util;

// Subkeys list
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLi {
    pub size: u32,
    pub count: u16,
    pub items: Vec<SubKeyListLiItem> // Vec size = count
}

impl hive_bin_cell::CellSubKeyList for SubKeyListLi {
    fn size(&self) -> u32 {
        self.size
    }

    fn offsets(&self, hbin_offset: u32) -> Vec<u32> {
        self.items.iter().map(|x| x.named_key_offset + hbin_offset).collect()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLiItem {
    pub named_key_offset: u32, // The offset value is in bytes and relative from the start of the hive bin data
}

 fn parse_sub_key_list_li_item() -> impl Fn(&[u8]) -> IResult<&[u8], SubKeyListLiItem> {
    |input: &[u8]| {
        let (input, named_key_offset) = le_u32(input)?;
        Ok((
            input,
            SubKeyListLiItem {
                named_key_offset
            },
        ))
    }
}

pub fn parse_sub_key_list_li() -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn hive_bin_cell::CellSubKeyList>> {
    |input: &[u8]| {
        let (input, ret) = parse_sub_key_list_li_internal(input)?;
        Ok((
            input,
            Box::new(ret)
        ))
    }
}

/// Uses nom to parse an li sub key list (li) hive bin cell.
fn parse_sub_key_list_li_internal(input: &[u8]) -> IResult<&[u8], SubKeyListLi> {
    let start_pos = input.as_ptr() as usize;
    let (input, size)      = le_i32(input)?;
    let (input, _signature) = tag("li")(input)?;
    let (input, count)     = le_u16(input)?;
    let (input, items)     = nom::multi::count(parse_sub_key_list_li_item(), count.into())(input)?;

    let size_abs = size.abs() as u32;
    let (input, _) = util::parser_eat_remaining(input, size_abs as usize, input.as_ptr() as usize - start_pos)?;

    Ok((
        input,
        SubKeyListLi {
            size: size_abs,
            count,
            items
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hive_bin_cell::CellSubKeyList;

    #[test]
    fn test_sub_key_list_li_traits() {
        let li = SubKeyListLi {
            size: 64,
            count: 2,
            items: vec![SubKeyListLiItem { named_key_offset: 12345 },
                        SubKeyListLiItem { named_key_offset: 54321 }]
        };
        assert_eq!(li.size, li.size());
        assert_eq!(vec![16441, 58417], li.offsets(4096));
    }

    #[test]
    fn test_parse_sub_key_list_li() {
        let f = std::fs::read("test_data/ManySubkeysHive").unwrap();
        let slice = &f[53280..58960];
        let ret = parse_sub_key_list_li_internal(slice);
        assert_eq!(true, ret.is_ok());
        let unwrapped = ret.unwrap();
        let remaining = unwrapped.0;
        assert_eq!(0, remaining.len());
        let val = unwrapped.1;
        assert_eq!(5680, val.size);
        assert_eq!(506, val.count);
        assert_eq!(506, val.items.len());
    }
}
