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

use nom::Parser;
use crate::hive_bin_cell;
use nom::{
    bytes::complete::tag,
    number::complete::{le_i32, le_u16, le_u32},
    IResult,
};
use serde::Serialize;

// Subkeys list with name hints
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLh {
    pub size: u32,
    pub count: u16,
    pub items: Vec<SubKeyListLhItem>, // Vec size = count
}

impl SubKeyListLh {
    /// Uses nom to parse an lh sub key list (lh) hive bin cell.
    fn from_bytes_internal(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("lh")(input)?;
        let (input, count) = le_u16(input)?;
        let (input, items) =
            nom::multi::count(SubKeyListLhItem::from_bytes(), count.into()).parse(input)?;
        Ok((
            input,
            SubKeyListLh {
                size: size.unsigned_abs(),
                count,
                items,
            },
        ))
    }

    pub(crate) fn from_bytes(
    ) -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn hive_bin_cell::CellSubKeyList>> {
        |input: &[u8]| {
            let (input, ret) = SubKeyListLh::from_bytes_internal(input)?;
            Ok((input, Box::new(ret)))
        }
    }
}

impl hive_bin_cell::CellSubKeyList for SubKeyListLh {
    fn size(&self) -> u32 {
        self.size
    }

    fn get_offset_list(&self, hbin_offset_absolute: u32) -> Vec<u32> {
        self.items
            .iter()
            .filter_map(|x| {
                x.named_key_offset_relative
                    .checked_add(hbin_offset_absolute)
            })
            .collect()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLhItem {
    pub named_key_offset_relative: u32, // The offset value is in bytes and relative from the start of the hive bin data
    pub name_hash: u32, // Hash of a key name string (used to speed up lookups). A different hash function is used for different sub key list types.
}

impl SubKeyListLhItem {
    fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        |input: &[u8]| {
            let (input, named_key_offset_relative) = le_u32(input)?;
            let (input, name_hash) = le_u32(input)?;
            Ok((
                input,
                SubKeyListLhItem {
                    named_key_offset_relative,
                    name_hash,
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
            items: vec![
                SubKeyListLhItem {
                    named_key_offset_relative: 12345,
                    name_hash: 1111,
                },
                SubKeyListLhItem {
                    named_key_offset_relative: 54321,
                    name_hash: 2222,
                },
            ],
        };
        assert_eq!(lh.size, lh.size());
        assert_eq!(vec![16441, 58417], lh.get_offset_list(4096));
    }

    #[test]
    fn test_parse_sub_key_list_lh() {
        let f = std::fs::read("test_data/lh_block").unwrap();
        let slice = &f[..];
        let (_, key_list) = SubKeyListLh::from_bytes_internal(slice).unwrap();

        let expected_output = SubKeyListLh {
            size: 96,
            count: 8,
            items: vec![
                SubKeyListLhItem {
                    named_key_offset_relative: 4600,
                    name_hash: 129374869,
                },
                SubKeyListLhItem {
                    named_key_offset_relative: 7008,
                    name_hash: 97615,
                },
                SubKeyListLhItem {
                    named_key_offset_relative: 7536,
                    name_hash: 397082278,
                },
                SubKeyListLhItem {
                    named_key_offset_relative: 7192,
                    name_hash: 2451360315,
                },
                SubKeyListLhItem {
                    named_key_offset_relative: 7440,
                    name_hash: 235888890,
                },
                SubKeyListLhItem {
                    named_key_offset_relative: 6376,
                    name_hash: 2289207844,
                },
                SubKeyListLhItem {
                    named_key_offset_relative: 7096,
                    name_hash: 2868760012,
                },
                SubKeyListLhItem {
                    named_key_offset_relative: 7352,
                    name_hash: 123397,
                },
            ],
        };
        assert_eq!(expected_output, key_list);
    }
}
