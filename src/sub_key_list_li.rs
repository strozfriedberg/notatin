/*
 * Copyright 2023 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::hive_bin_cell;
use nom::{
    bytes::complete::tag,
    number::complete::{le_i32, le_u16, le_u32},
    IResult,
};
use serde::Serialize;

// Subkeys list
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLi {
    pub size: u32,
    pub count: u16,
    pub items: Vec<SubKeyListLiItem>, // Vec size = count
}

impl SubKeyListLi {
    /// Uses nom to parse an lf sub key list (lf) hive bin cell.
    fn from_bytes_internal(input: &[u8]) -> IResult<&[u8], SubKeyListLi> {
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("li")(input)?;
        let (input, count) = le_u16(input)?;
        let (input, items) =
            nom::multi::count(SubKeyListLiItem::from_bytes(), count.into())(input)?;
        Ok((
            input,
            SubKeyListLi {
                size: size.unsigned_abs(),
                count,
                items,
            },
        ))
    }

    pub(crate) fn from_bytes(
    ) -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn hive_bin_cell::CellSubKeyList>> {
        |input: &[u8]| {
            let (input, ret) = SubKeyListLi::from_bytes_internal(input)?;
            Ok((input, Box::new(ret)))
        }
    }
}

impl hive_bin_cell::CellSubKeyList for SubKeyListLi {
    fn size(&self) -> u32 {
        self.size
    }

    fn get_offset_list(&self, hbin_offset_absolute: u32) -> Vec<u32> {
        self.items
            .iter()
            .map(|x| x.named_key_offset_relative + hbin_offset_absolute)
            .collect()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLiItem {
    pub named_key_offset_relative: u32, // The offset value is in bytes and relative from the start of the hive bin data
}

impl SubKeyListLiItem {
    fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        |input: &[u8]| {
            let (input, named_key_offset_relative) = le_u32(input)?;
            Ok((
                input,
                SubKeyListLiItem {
                    named_key_offset_relative,
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
    fn test_sub_key_list_li_traits() {
        let li = SubKeyListLi {
            size: 64,
            count: 2,
            items: vec![
                SubKeyListLiItem {
                    named_key_offset_relative: 12345,
                },
                SubKeyListLiItem {
                    named_key_offset_relative: 54321,
                },
            ],
        };
        assert_eq!(li.size, li.size());
        assert_eq!(vec![16441, 58417], li.get_offset_list(4096));
    }
}
