/*
 * Copyright 2021 Aon Cyber Solutions
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
use crate::log::Logs;
use crate::util;
use nom::{
    bytes::complete::tag,
    number::complete::{le_i32, le_u16, le_u32},
    take, IResult,
};
use serde::Serialize;

// Subkeys list with name hints
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLf {
    pub size: u32,
    pub count: u16,
    pub items: Vec<SubKeyListLfItem>, // Vec size = count
}

impl hive_bin_cell::CellSubKeyList for SubKeyListLf {
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

impl SubKeyListLf {
    /// Uses nom to parse an lf sub key list (lf) hive bin cell.
    fn from_bytes_internal(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("lf")(input)?;
        let (input, count) = le_u16(input)?;
        let (input, items) =
            nom::multi::count(SubKeyListLfItem::from_bytes(), count.into())(input)?;
        Ok((
            input,
            SubKeyListLf {
                size: size.unsigned_abs(),
                count,
                items,
            },
        ))
    }

    pub(crate) fn from_bytes(
    ) -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn hive_bin_cell::CellSubKeyList>> {
        |input: &[u8]| {
            let (input, ret) = SubKeyListLf::from_bytes_internal(input)?;
            Ok((input, Box::new(ret)))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SubKeyListLfItem {
    pub named_key_offset_relative: u32, // The offset value is in bytes and relative from the start of the hive bin data
    pub name_hint: String, // The first 4 ASCII characters of a key name string (used to speed up lookups)
    pub logs: Logs,
}

impl SubKeyListLfItem {
    fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        |input: &[u8]| {
            let (input, named_key_offset_relative) = le_u32(input)?;
            let (input, name_hint) = take!(input, 4usize)?;
            let mut logs = Logs::default();
            Ok((
                input,
                SubKeyListLfItem {
                    named_key_offset_relative,
                    name_hint: util::from_ascii(name_hint, &mut logs, "SubKeyListLfItem::key_name"),
                    logs,
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
            items: vec![
                SubKeyListLfItem {
                    named_key_offset_relative: 12345,
                    name_hint: "aaaa".to_string(),
                    logs: Logs::default(),
                },
                SubKeyListLfItem {
                    named_key_offset_relative: 54321,
                    name_hint: "zzzz".to_string(),
                    logs: Logs::default(),
                },
            ],
        };
        assert_eq!(lf.size, lf.size());
        assert_eq!(vec![16441, 58417], lf.get_offset_list(4096));
    }

    #[test]
    fn test_parse_sub_key_list_lf() {
        let slice = [
            0xE8, 0xFF, 0xFF, 0xFF, 0x6C, 0x66, 0x02, 0x00, 0xF8, 0x9B, 0x01, 0x00, 0x53, 0x63,
            0x72, 0x65, 0xA0, 0x9B, 0x01, 0x00, 0x53, 0x63, 0x72, 0x65,
        ];

        let ret = SubKeyListLf::from_bytes_internal(&slice);

        let expected_output = SubKeyListLf {
            size: 24,
            count: 2,
            items: vec![
                SubKeyListLfItem {
                    named_key_offset_relative: 105464,
                    name_hint: "Scre".to_string(),
                    logs: Logs::default(),
                },
                SubKeyListLfItem {
                    named_key_offset_relative: 105376,
                    name_hint: "Scre".to_string(),
                    logs: Logs::default(),
                },
            ],
        };

        let remaining: [u8; 0] = [0; 0];

        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(expected, ret);
    }
}
