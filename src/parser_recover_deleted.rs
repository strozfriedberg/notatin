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

use crate::cell::{CellState, CellType};
use crate::cell_key_node::{CellKeyNode, CellKeyNodeReadOptions};
use crate::cell_key_value::CellKeyValue;
use crate::err::Error;
use crate::file_info::FileInfo;
use crate::hive_bin_header::HiveBinHeader;
use crate::log::LogCode;
use crate::state::State;
use nom::{branch::alt, bytes::complete::tag, combinator::map, number::complete::le_i32, IResult};

pub(crate) struct ParserRecoverDeleted<'a> {
    pub file_info: &'a FileInfo,
    pub state: &'a mut State,
}

impl<'a> ParserRecoverDeleted<'a> {
    pub(crate) fn find_free_keys_and_values(
        &mut self,
        mut file_offset_absolute: usize,
    ) -> Result<usize, Error> {
        let slice = read_checked(&self.file_info.buffer, file_offset_absolute)
            .ok_or_else(|| Error::buffer("find_free_keys_and_values"))?;
        let (input, hbin_header) = HiveBinHeader::from_bytes(self.file_info, slice)?;

        let hbin_size = hbin_header.size as usize;
        let hbin_start = file_offset_absolute;
        file_offset_absolute = self.file_info.get_file_offset(input);

        let file_offset_absolute =
            self.find_unused_cells_in_hbin(file_offset_absolute, hbin_start + hbin_size)?;

        Ok(file_offset_absolute)
    }

    fn find_unused_cells_in_hbin(
        &mut self,
        mut file_offset_absolute: usize,
        hbin_max: usize,
    ) -> Result<usize, Error> {
        let mut input = read_checked(&self.file_info.buffer, file_offset_absolute)
            .ok_or_else(|| Error::buffer("find_unused_cells_in_hbin: initial"))?;
        while file_offset_absolute < hbin_max {
            let (input_cell_type, size) = le_i32(input)?;
            let size_abs = size.unsigned_abs() as usize;
            if size == 0 {
                break;
            } else {
                match CellType::read_cell_type(input_cell_type) {
                    CellType::CellValue => {
                        if let Some(value_slack) =
                            read_checked(&self.file_info.buffer, file_offset_absolute)
                        {
                            self.read_cell_key_value(
                                value_slack,
                                file_offset_absolute,
                                CellState::DeletedPrimaryFile,
                                false,
                            );
                        }
                    }
                    CellType::CellKey => {
                        if let Some(key_slack) =
                            read_checked(&self.file_info.buffer, file_offset_absolute)
                        {
                            self.read_cell_key_node(
                                key_slack,
                                file_offset_absolute,
                                CellState::DeletedPrimaryFile,
                                false,
                            );
                        }
                    }
                    _ => {
                        if let Some(slack) = read_range_checked(
                            &self.file_info.buffer,
                            file_offset_absolute,
                            size_abs,
                        ) {
                            self.find_cells_in_slack(slack, file_offset_absolute);
                        }
                    }
                }
            }
            file_offset_absolute += size_abs;
            match read_range_checked(&self.file_info.buffer, file_offset_absolute, size_abs) {
                Some(data) => input = data,
                None => break,
            };
        }

        Ok(file_offset_absolute)
    }

    // this method will ignore errors that are encountered
    fn find_cells_in_slack(&mut self, input_orig: &[u8], file_offset_absolute_start: usize) {
        let _ = self.find_cells_in_slack_internal(input_orig, file_offset_absolute_start);
    }

    fn read_cell_key_value(
        &mut self,
        input_orig: &[u8],
        file_offset_absolute: usize,
        cell_state: CellState,
        force_add: bool,
    ) -> usize {
        let mut offset_ret = 1; // Return bytes to increment offset. If we encounter a parseable cell, we will increment by the size of the cell; if we don't, we inc by one.
        match CellKeyValue::from_bytes(input_orig, file_offset_absolute, None, false) {
            Ok((_, mut cell_key_value)) => {
                self.find_cells_in_slack(
                    &cell_key_value.detail.slack(),
                    cell_key_value.slack_offset_absolute(),
                );
                if force_add || cell_key_value.is_free() {
                    cell_key_value.read_value_bytes(self.file_info, self.state);
                    offset_ret = cell_key_value.get_cell_size();
                    cell_key_value.cell_state = cell_state;
                    self.state.deleted_values.add("", cell_key_value);
                }
            }
            Err(_) => {
                self.state.info.add(
                    LogCode::WarningRecovery,
                    &format!(
                        "\tUnable to parse deleted value at offset {}",
                        file_offset_absolute
                    ),
                );
            }
        }
        offset_ret
    }

    fn read_cell_key_node(
        &mut self,
        input_orig: &[u8],
        file_offset_absolute: usize,
        cell_state: CellState,
        force_add: bool,
    ) -> usize {
        let mut offset_ret = 1; // Return bytes to increment offset. If we encounter a parseable cell, we will increment by the size of the cell; if we don't, we inc by one.
        match CellKeyNode::read_from_slice(
            self.file_info,
            self.state,
            input_orig,
            CellKeyNodeReadOptions {
                offset: file_offset_absolute,
                cur_path: "",
                filter: None,
                self_is_filter_match_or_descendent: true,
                sequence_num: None,
                get_deleted_and_modified: false,
            },
        ) {
            Ok(full_key) => {
                if let Some(mut full_key) = full_key {
                    self.find_cells_in_slack(
                        &full_key.detail.slack(),
                        full_key.slack_offset_absolute(),
                    );
                    if force_add || full_key.is_free() {
                        offset_ret = full_key.get_cell_size();
                        full_key.cell_state = cell_state;
                        self.state.deleted_keys.add("", full_key);
                    }
                }
            }
            Err(e) => {
                self.state.info.add(
                    LogCode::WarningRecovery,
                    &format!(
                        "Unable to parse deleted key at offset {} ({})",
                        file_offset_absolute, e
                    ),
                );
            }
        }
        offset_ret
    }

    fn find_cells_in_slack_internal(
        &mut self,
        input_orig: &[u8],
        file_offset_absolute_start: usize,
    ) -> Result<(), Error> {
        let mut offset = 0;
        while offset < input_orig.len() {
            let input = &input_orig[offset..]; // direct access ok; loop checks for offset < input_orig.len()
            let file_offset_absolute = file_offset_absolute_start + offset;
            let (input, _size) = le_i32(input)?;

            fn cell_type(b: &[u8]) -> IResult<&[u8], CellType> {
                alt((
                    map(tag("nk"), |_| CellType::CellKey),
                    map(tag("vk"), |_| CellType::CellValue),
                ))(b)
            }

            match cell_type(input) {
                Ok((_, cell_type)) => match cell_type {
                    CellType::CellValue => {
                        offset += self.read_cell_key_value(
                            &input_orig[offset..], // direct access ok; loop checks for offset < input_orig.len()
                            file_offset_absolute,
                            CellState::DeletedPrimaryFileSlack,
                            true,
                        );
                    }
                    CellType::CellKey => {
                        offset += self.read_cell_key_node(
                            &input_orig[offset..], // direct access ok; loop checks for offset < input_orig.len()
                            file_offset_absolute,
                            CellState::DeletedPrimaryFileSlack,
                            true,
                        );
                    }
                    _ => offset += 1,
                },
                Err(_) => offset += 1,
            }
        }
        Ok(())
    }
}

fn read_range_checked(buffer: &[u8], file_offset_absolute: usize, size: usize) -> Option<&[u8]> {
    if file_offset_absolute < buffer.len() {
        Some(
            buffer
                .get(file_offset_absolute..std::cmp::min(file_offset_absolute + size, buffer.len()))
                .expect("read_range_checked failure - but, we just checked this..."),
        )
    } else {
        None
    }
}

fn read_checked(buffer: &[u8], file_offset_absolute: usize) -> Option<&[u8]> {
    if file_offset_absolute < buffer.len() {
        Some(
            buffer
                .get(file_offset_absolute..)
                .expect("read_checked failure - but, we just checked this..."),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_checked() {
        let buffer = vec![0, 1, 2, 3, 4];
        let ret0: &[u8] = &buffer[0..];
        let ret4: &[u8] = &buffer[4..];
        assert_eq!(None, read_checked(&buffer, 5));
        assert_eq!(Some(ret0), read_checked(&buffer, 0));
        assert_eq!(Some(ret4), read_checked(&buffer, 4));
    }

    #[test]
    fn test_read_range_checked() {
        let buffer = vec![0, 1, 2, 3, 4];
        let ret0: &[u8] = &buffer[0..2];
        let ret1: &[u8] = &buffer[1..4];
        let ret4: &[u8] = &buffer[4..5];
        assert_eq!(None, read_range_checked(&buffer, 5, 0));
        assert_eq!(None, read_range_checked(&buffer, 5, 1));
        assert_eq!(Some(ret0), read_range_checked(&buffer, 0, 2));
        assert_eq!(Some(ret1), read_range_checked(&buffer, 1, 3));
        assert_eq!(Some(ret4), read_range_checked(&buffer, 4, 1));
    }
}
