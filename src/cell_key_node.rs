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

use crate::cell::CellState;
use crate::cell_key_security;
use crate::cell_key_value::CellKeyValue;
use crate::err::Error;
use crate::file_info::FileInfo;
use crate::filter::{Filter, FilterFlags, RegQueryBuilder};
use crate::impl_flags_from_bits;
use crate::impl_serialize_for_bitflags;
use crate::log::{LogCode, Logs};
use crate::parser::Parser;
use crate::state::State;
use crate::sub_key_list_lf::SubKeyListLf;
use crate::sub_key_list_lh::SubKeyListLh;
use crate::sub_key_list_li::SubKeyListLi;
use crate::sub_key_list_ri::SubKeyListRi;
use crate::util;
use bitflags::bitflags;
use blake3::Hash;
use chrono::{DateTime, Utc};
use nom::{
    branch::alt,
    bytes::complete::tag,
    multi::count,
    number::complete::{le_i32, le_u16, le_u32, le_u64},
    take, IResult,
};
use serde::Serialize;
use std::time::SystemTime;
use winstructs::security::SecurityDescriptor;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CellKeyNodeDetail {
    pub file_offset_absolute: usize,
    pub size: i32,
    pub number_of_volatile_sub_keys: u32, // The offset value is in bytes and relative from the start of the hive bin data / Refers to a sub keys list or contains -1 (0xffffffff) if empty.
    pub sub_keys_list_offset_relative: u32, // In bytes, relative from the start of the hive bins data (also, this field may point to an Index root)
    pub volatile_sub_keys_list_offset_relative: i32, // This field has no meaning on a disk (volatile keys are not written to a file)
    pub key_values_list_offset_relative: i32,
    pub security_key_offset_relative: u32,
    pub class_name_offset_relative: i32,
    /*  Starting from Windows Vista, Windows Server 2003 SP2, and Windows XP SP3, the Largest subkey name length field has been split
    into 4 bit fields (the offsets below are relative from the beginning of the old Largest subkey name length field,
    i.e. the first bit field starts within the byte at the lowest address):
    Offset (bits)	Length (bits)	Field	                     Description
    0	            16	            Largest subkey name length
    16	            4	            Virtualization control flags Bit mask, see below
    20	            4	            User flags (Wow64 flags)     Bit mask, see below
    24              8	            Debug                        See below */
    pub largest_sub_key_name_size: u32, // In bytes, a subkey name is treated as a UTF-16LE string (see below)
    pub largest_sub_key_class_name_size: u32,
    pub largest_value_name_size: u32, // In bytes, a value name is treated as a UTF-16LE string
    pub largest_value_data_size: u32,
    pub work_var: u32, // Unused as of WinXP
    pub key_name_size: u16,
    pub class_name_size: u16,
    pub slack: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum FilterMatchState {
    None,
    Descendent,
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CellKeyNodeIteration {
    pub(crate) to_return: u32,
    pub(crate) track_returned: u32,
    pub(crate) filter_state: Option<FilterMatchState>,
    pub(crate) sub_keys_iter_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CellKeyNode {
    pub detail: CellKeyNodeDetail,
    pub key_node_flags: KeyNodeFlags,
    pub last_key_written_date_and_time: DateTime<Utc>,
    /// Bit mask (this field is used as of Windows 8 and Windows Server 2012; in previous versions of Windows, this field is reserved and called Spare)
    pub access_flags: AccessFlags,
    /// Offset of the parent key node in bytes, relative from the start of the hive bin's data (this field has no meaning on a disk for a root key node)
    pub parent_key_offset_relative: i32,
    pub number_of_sub_keys: u32,
    pub number_of_key_values: u32,
    pub key_name: String,

    pub path: String,
    pub cell_state: CellState,
    pub(crate) sub_values: Vec<CellKeyValue>, // sub_values includes deleted values, if present
    pub logs: Logs,
    pub sequence_num: Option<u32>,
    pub updated_by_sequence_num: Option<u32>,
    #[serde(skip_serializing)]
    pub hash: Option<Hash>,

    /// Absolute offsets of any sub key cells
    #[serde(skip_serializing)]
    pub cell_sub_key_offsets_absolute: Vec<u32>,

    #[serde(skip_serializing)]
    pub versions: Vec<Self>,
    #[serde(skip_serializing)]
    pub deleted_keys: Vec<Self>,

    #[serde(skip_serializing)]
    pub(crate) iteration_state: CellKeyNodeIteration,
}

impl Default for CellKeyNode {
    fn default() -> Self {
        Self {
            detail: CellKeyNodeDetail::default(),
            key_node_flags: KeyNodeFlags::default(),
            last_key_written_date_and_time: DateTime::from(SystemTime::UNIX_EPOCH),
            access_flags: AccessFlags::default(),
            parent_key_offset_relative: i32::default(),
            number_of_sub_keys: u32::default(),
            number_of_key_values: u32::default(),
            key_name: String::default(),
            path: String::default(),
            cell_state: CellState::Allocated,
            sub_values: Vec::new(),
            logs: Logs::default(),
            cell_sub_key_offsets_absolute: Vec::new(),
            iteration_state: CellKeyNodeIteration {
                to_return: 0,
                track_returned: 0,
                filter_state: None,
                sub_keys_iter_index: 0,
            },
            versions: Vec::new(),
            deleted_keys: Vec::new(),
            hash: None,
            sequence_num: None,
            updated_by_sequence_num: None,
        }
    }
}

pub(crate) struct CellKeyNodeReadOptions<'a> {
    pub offset: usize,
    pub cur_path: &'a str,
    pub filter: Option<&'a Filter>,
    pub self_is_filter_match_or_descendent: bool,
    pub sequence_num: Option<u32>,
    pub get_deleted_and_modified: bool,
}

impl CellKeyNode {
    const MIN_CELL_KEY_SIZE: usize = 72;

    fn check_size(size: i32, input_len: usize) -> bool {
        let size_abs = size.abs() as usize;
        Self::MIN_CELL_KEY_SIZE <= size_abs && size_abs <= input_len
    }

    /// Returns the byte length of the cell (regardless of if it's allocated or free)
    pub(crate) fn get_cell_size(&self) -> usize {
        self.detail.size.abs() as usize
    }

    pub(crate) fn is_free(&self) -> bool {
        self.detail.size > 0
    }

    pub(crate) fn slack_offset_absolute(&self) -> usize {
        self.detail.file_offset_absolute + self.get_cell_size() - self.detail.slack.len()
    }

    fn from_bytes<'a>(
        state: &mut State,
        input: &'a [u8],
        file_offset_absolute: usize,
        cur_path: &str,
        sequence_num: Option<u32>,
    ) -> IResult<&'a [u8], Self> {
        let start_pos_ptr = input.as_ptr() as usize;

        let (input, size) = le_i32(input)?;
        if !Self::check_size(size, input.len() + std::mem::size_of::<i32>()) {
            Err(nom::Err::Error(nom::error::Error {
                input,
                code: nom::error::ErrorKind::Eof,
            }))
        } else {
            let (input, _signature) = tag("nk")(input)?;
            let (input, flags) = le_u16(input)?;
            let (input, last_key_written_date_and_time) = le_u64(input)?;
            let (input, access_bits) = le_u32(input)?;
            let (input, parent_key_offset_relative) = le_i32(input)?;
            let (input, number_of_sub_keys) = le_u32(input)?;
            let (input, number_of_volatile_sub_keys) = le_u32(input)?;
            let (input, sub_keys_list_offset_relative) = le_u32(input)?;
            let (input, volatile_sub_keys_list_offset_relative) = le_i32(input)?;
            let (input, number_of_key_values) = le_u32(input)?;
            let (input, key_values_list_offset_relative) = le_i32(input)?;
            let (input, security_key_offset_relative) = le_u32(input)?;
            let (input, class_name_offset_relative) = le_i32(input)?;
            let (input, largest_sub_key_name_size) = le_u32(input)?;
            let (input, largest_sub_key_class_name_size) = le_u32(input)?;
            let (input, largest_value_name_size) = le_u32(input)?;
            let (input, largest_value_data_size) = le_u32(input)?;
            let (input, work_var) = le_u32(input)?;
            let (input, key_name_size) = le_u16(input)?;
            let (input, class_name_size) = le_u16(input)?;
            let (input, key_name_bytes) = take!(input, key_name_size)?;

            let mut logs = Logs::default();
            let key_node_flags = KeyNodeFlags::from_bits_checked(flags, &mut logs);

            let key_name = util::string_from_bytes(
                key_node_flags.contains(KeyNodeFlags::KEY_COMP_NAME),
                key_name_bytes,
                key_name_size,
                &mut logs,
                "key_name_bytes",
            );

            let mut path = cur_path.to_owned();
            path.push('\\');
            path += &key_name;

            let size_abs = size.unsigned_abs();
            let (input, slack) = util::parser_eat_remaining(
                input,
                size_abs,
                input.as_ptr() as usize - start_pos_ptr,
            )?;

            let cell_key_node = Self {
                detail: CellKeyNodeDetail {
                    file_offset_absolute,
                    size,
                    number_of_volatile_sub_keys,
                    sub_keys_list_offset_relative,
                    volatile_sub_keys_list_offset_relative,
                    key_values_list_offset_relative,
                    security_key_offset_relative,
                    class_name_offset_relative,
                    largest_sub_key_name_size,
                    largest_sub_key_class_name_size,
                    largest_value_name_size,
                    largest_value_data_size,
                    work_var,
                    key_name_size,
                    class_name_size,
                    slack: slack.to_vec(),
                },
                key_node_flags,
                last_key_written_date_and_time: util::get_date_time_from_filetime(
                    last_key_written_date_and_time,
                ),
                access_flags: AccessFlags::from_bits_checked(access_bits, &mut logs),
                parent_key_offset_relative,
                number_of_sub_keys,
                number_of_key_values,
                key_name,
                path,
                cell_state: CellState::Allocated,
                sub_values: Vec::new(),
                logs,
                cell_sub_key_offsets_absolute: Vec::new(),
                iteration_state: CellKeyNodeIteration {
                    to_return: 0,
                    track_returned: 0,
                    filter_state: None,
                    sub_keys_iter_index: 0,
                },
                versions: Vec::new(),
                deleted_keys: Vec::new(),
                hash: Some(Self::hash(
                    state,
                    flags,
                    last_key_written_date_and_time,
                    access_bits,
                )),
                sequence_num,
                updated_by_sequence_num: None,
            };

            Ok((input, cell_key_node))
        }
    }

    fn hash(
        state: &mut State,
        flags_raw: u16,
        last_key_written_raw: u64,
        access_bits_raw: u32,
    ) -> Hash {
        state.hasher.reset();
        state.hasher.update(&flags_raw.to_le_bytes());
        state.hasher.update(&last_key_written_raw.to_le_bytes());
        state.hasher.update(&access_bits_raw.to_le_bytes());
        state.hasher.finalize()
    }

    fn update_modified_lists(&mut self, state: &State) {
        let path;
        if self.is_key_root() {
            path = String::new();
        } else {
            path = self.path.clone();
        }
        if let Some(sequence_num) = state.sequence_numbers.get(&(path.clone(), None)) {
            self.sequence_num = Some(*sequence_num);
        }
        if let Some(deleted_keys) = state.deleted_keys.get(&path) {
            self.deleted_keys = deleted_keys.to_vec();
            for dk in self.deleted_keys.iter_mut() {
                dk.update_modified_lists(state);
            }
        }
        if let Some(updated_keys) = state.updated_keys.get(&path) {
            self.versions = updated_keys.to_vec();
        }

        for val in &mut self.sub_values {
            if let Some(sequence_num) = state
                .sequence_numbers
                .get(&(path.clone(), Some(val.value_name.clone())))
            {
                val.sequence_num = Some(*sequence_num);
            }
            if let Some(updated_values) = state.updated_values.get(&path, &val.value_name) {
                val.versions = updated_values.to_vec();
            }
        }

        if let Some(deleted_values) = state.deleted_values.get(&path) {
            self.sub_values.extend(deleted_values.to_vec());
        }
    }

    pub(crate) fn is_filter_match_or_descendent(&self) -> bool {
        matches!(
            self.iteration_state.filter_state,
            Some(FilterMatchState::Exact) | Some(FilterMatchState::Descendent)
        )
    }

    fn should_read_values(
        filter: Option<&Filter>,
        filter_flags: FilterFlags,
        self_is_filter_match_or_descendent: bool,
    ) -> bool {
        self_is_filter_match_or_descendent
            || filter.is_none()
            || !filter.unwrap().is_valid()
            || filter_flags.contains(FilterFlags::FILTER_KEY_MATCH)
    }

    /// Reads a key node from file_info.
    /// Returns a CellKeyNode
    pub(crate) fn read_from_slice(
        file_info: &FileInfo,
        state: &mut State,
        slice: &[u8],
        options: CellKeyNodeReadOptions,
    ) -> Result<Option<Self>, Error> {
        let (_, mut cell_key_node) = Self::from_bytes(
            state,
            slice,
            options.offset,
            options.cur_path,
            options.sequence_num,
        )?;

        let filter_flags = match options.filter {
            Some(filter) => filter.check_cell(state, &cell_key_node),
            _ => FilterFlags::FILTER_ITERATE_KEYS,
        };
        if filter_flags.contains(FilterFlags::FILTER_NO_MATCH) {
            return Ok(None);
        }

        if cell_key_node.number_of_key_values > 0
            && Self::should_read_values(
                options.filter,
                filter_flags,
                options.self_is_filter_match_or_descendent,
            )
        {
            if let Err(e) = cell_key_node.read_values(file_info, state, options.sequence_num) {
                cell_key_node.logs.add(
                    LogCode::WarningParse,
                    &format!("Unable to parse values {:?}", e),
                )
            }
        }

        if filter_flags.contains(FilterFlags::FILTER_KEY_MATCH) {
            cell_key_node.iteration_state.filter_state = Some(FilterMatchState::Exact);
        }

        if options.get_deleted_and_modified {
            cell_key_node.update_modified_lists(state);
        }

        Ok(Some(cell_key_node))
    }

    /// Reads a key node from file_info.
    /// Returns a CellKeyNode
    pub(crate) fn read(
        file_info: &FileInfo,
        state: &mut State,
        options: CellKeyNodeReadOptions,
    ) -> Result<Option<Self>, Error> {
        Self::read_from_slice(
            file_info,
            state,
            &file_info.buffer[options.offset..],
            options,
        )
    }

    pub fn read_sub_keys(&mut self, parser: &mut Parser) -> Vec<Self> {
        let (sub_keys, _) = self.read_sub_keys_internal(
            &parser.file_info,
            &mut parser.state,
            &Filter::new(),
            None,
            true,
        );
        sub_keys
    }

    pub(crate) fn read_sub_keys_internal(
        &mut self,
        file_info: &FileInfo,
        state: &mut State,
        filter: &Filter,
        sequence_num: Option<u32>,
        get_deleted_and_modified: bool,
    ) -> (Vec<Self>, bool) {
        if self.cell_state == CellState::Allocated {
            let mut children = Vec::with_capacity(self.number_of_sub_keys as usize);
            let mut found_key = false;
            if self.number_of_sub_keys > 0 {
                match Self::parse_sub_key_list(
                    file_info,
                    state,
                    self.detail.sub_keys_list_offset_relative,
                ) {
                    Ok(cell_sub_key_offsets_absolute) => {
                        let self_is_filter_match_or_descendent =
                            self.is_filter_match_or_descendent();
                        let sub_filter;
                        if self_is_filter_match_or_descendent && filter.return_sub_keys() {
                            sub_filter = None;
                        } else {
                            sub_filter = Some(filter);
                        }
                        for val in cell_sub_key_offsets_absolute.iter() {
                            let ret = Self::read(
                                file_info,
                                state,
                                CellKeyNodeReadOptions {
                                    offset: *val as usize,
                                    cur_path: &self.path,
                                    filter: sub_filter,
                                    self_is_filter_match_or_descendent,
                                    sequence_num,
                                    get_deleted_and_modified,
                                },
                            );
                            match ret {
                                Err(_) => self.logs.add(
                                    LogCode::WarningParse,
                                    &format!(
                                        "{}: Unable to parse sub_key at offset {}",
                                        self.path, val
                                    ),
                                ),
                                Ok(kn) => {
                                    if let Some(mut kn) = kn {
                                        if kn.iteration_state.filter_state == None {
                                            if self_is_filter_match_or_descendent {
                                                kn.iteration_state.filter_state =
                                                    Some(FilterMatchState::Descendent);
                                            } else if filter.is_valid() {
                                                kn.iteration_state.filter_state =
                                                    Some(FilterMatchState::None);
                                            }
                                        } else if kn.iteration_state.filter_state
                                            == Some(FilterMatchState::Exact)
                                        {
                                            found_key = true
                                        }
                                        children.push(kn);
                                    };
                                }
                            }
                        }
                        self.cell_sub_key_offsets_absolute = cell_sub_key_offsets_absolute;
                    }
                    Err(_) => self.logs.add(
                        LogCode::WarningParse,
                        &format!(
                            "{}: Unable to parse sub_key_list at offset {}",
                            self.path,
                            (self.detail.sub_keys_list_offset_relative as usize
                                + file_info.hbin_offset_absolute)
                        ),
                    ),
                }
            }
            (children, found_key)
        } else {
            (vec![], false)
        }
    }

    fn get_sub_key_internal(
        &mut self,
        file_info: &FileInfo,
        state: &mut State,
        filter: &Filter,
        sequence_num: Option<u32>,
    ) -> Option<Self> {
        let (children, found_key) =
            self.read_sub_keys_internal(file_info, state, filter, sequence_num, false);
        if found_key {
            match children.get(0) {
                Some(child) => return Some(child.clone()),
                None => return None,
            }
        }
        for mut child in children {
            if let Some(key) = child.get_sub_key_internal(file_info, state, filter, sequence_num) {
                return Some(key);
            }
        }
        None
    }

    pub fn get_sub_key_by_path(&mut self, parser: &mut Parser, sub_path: &str) -> Option<Self> {
        if sub_path.is_empty() {
            Some(self.clone())
        } else {
            let filter = Filter::from_path(
                RegQueryBuilder::from_key(&format!("{}\\{}", self.path, sub_path))
                    .key_path_has_root(true)
                    .build(),
            );
            self.get_sub_key_internal(&parser.file_info, &mut parser.state, &filter, None)
        }
    }

    pub fn get_sub_key_by_index(&mut self, parser: &mut Parser, index: usize) -> Option<Self> {
        if self.number_of_sub_keys > 0 {
            match Self::parse_sub_key_list(
                &parser.file_info,
                &mut parser.state,
                self.detail.sub_keys_list_offset_relative,
            ) {
                Ok(cell_sub_key_offsets_absolute) => {
                    if let Some(offset) = cell_sub_key_offsets_absolute.get(index) {
                        let ret = Self::read(
                            &parser.file_info,
                            &mut parser.state,
                            CellKeyNodeReadOptions {
                                offset: *offset as usize,
                                cur_path: &self.path,
                                filter: None,
                                self_is_filter_match_or_descendent: self
                                    .is_filter_match_or_descendent(),
                                sequence_num: None,
                                get_deleted_and_modified: true,
                            },
                        );
                        match ret {
                            Err(_) => self.logs.add(
                                LogCode::WarningParse,
                                &format!(
                                    "{}: Unable to parse sub_key at offset {}",
                                    self.path, offset
                                ),
                            ),
                            Ok(sub_key) => {
                                if let Some(sub_key) = sub_key {
                                    return Some(sub_key);
                                };
                            }
                        }
                    }
                }
                Err(_) => self.logs.add(
                    LogCode::WarningParse,
                    &format!(
                        "{}: Unable to parse sub_key_list at offset {}",
                        self.path,
                        (self.detail.sub_keys_list_offset_relative as usize
                            + parser.file_info.hbin_offset_absolute)
                    ),
                ),
            }
        }
        None
    }

    fn read_values(
        &mut self,
        file_info: &FileInfo,
        state: &mut State,
        sequence_num: Option<u32>,
    ) -> Result<(), Error> {
        if self.detail.key_values_list_offset_relative > 0
            && (self.detail.key_values_list_offset_relative as usize) < file_info.buffer.len()
        {
            self.sub_values = Vec::with_capacity(self.number_of_key_values as usize);
            let (_, key_values) = Self::parse_key_values(
                file_info,
                self.number_of_key_values,
                self.detail.key_values_list_offset_relative,
            )?;
            for val in key_values.iter() {
                let input = file_info
                    .buffer
                    .get(*val as usize + file_info.hbin_offset_absolute);
                if input.is_none() {
                    self.logs.add(
                        LogCode::WarningParse,
                        &format!(
                            "read_values error: offset {} out of range",
                            (*val as usize + file_info.hbin_offset_absolute)
                        ),
                    );
                    return Ok(());
                }
                let offset = *val as usize + file_info.hbin_offset_absolute;
                let (_, mut cell_key_value) =
                    CellKeyValue::from_bytes(&file_info.buffer[offset..], offset, sequence_num)?;

                cell_key_value.read_value_bytes(file_info, state);
                self.sub_values.push(cell_key_value);
            }
        }
        Ok(())
    }

    /// Returns a vector of Security Descriptors for the key
    pub fn get_security_descriptors(
        &mut self,
        parser: &mut Parser,
    ) -> Result<Vec<SecurityDescriptor>, Error> {
        let file_info = parser.get_file_info();
        cell_key_security::read_cell_key_security(
            &file_info.buffer[..],
            self.detail.security_key_offset_relative,
            file_info.hbin_offset_absolute,
        )
    }

    pub fn get_value(&self, find_value_name: &str) -> Option<CellKeyValue> {
        let find_value_name = find_value_name.to_ascii_lowercase();
        let val = self
            .sub_values
            .iter()
            .find(|v| v.value_name.to_ascii_lowercase() == find_value_name);
        val.cloned()
    }

    pub fn value_iter(&self) -> CellKeyNodeValueIterator<'_> {
        CellKeyNodeValueIterator {
            inner: self,
            sub_values_iter_index: 0,
        }
    }

    pub(crate) fn parse_key_values(
        file_info: &FileInfo,
        key_values_count: u32,
        list_offset_relative: i32,
    ) -> IResult<&[u8], Vec<u32>> {
        let slice: &[u8] =
            &file_info.buffer[list_offset_relative as usize + file_info.hbin_offset_absolute..];
        let (slice, _size) = le_u32(slice)?;
        let (_, list) = count(le_u32, key_values_count as usize)(slice)?;
        Ok((slice, list))
    }

    /// Returns a vector of the absolute sub key offsets
    pub(crate) fn parse_sub_key_list(
        file_info: &FileInfo,
        state: &mut State,
        list_offset_relative: u32,
    ) -> Result<Vec<u32>, Error> {
        let file_offset_absolute = list_offset_relative as usize + file_info.hbin_offset_absolute;
        let slice = &file_info.buffer[file_offset_absolute..];

        // We either have an lf/lh/li list here (offsets to subkey lists), or an ri list (offsets to offsets...)
        // Look for the ri list first and follow the pointers
        match SubKeyListRi::from_bytes(slice) {
            Ok((_, sub_key_list_ri)) => sub_key_list_ri.parse_offsets(file_info, state),
            Err(_) => {
                let (_, cell_sub_key_list) = alt((
                    SubKeyListLf::from_bytes(),
                    SubKeyListLh::from_bytes(),
                    SubKeyListLi::from_bytes(),
                ))(slice)?;
                Ok(cell_sub_key_list.get_offset_list(file_info.hbin_offset_absolute as u32))
            }
        }
    }

    pub fn init_sub_key_iter(&mut self) {
        self.iteration_state.sub_keys_iter_index = 0
    }

    pub fn next_value(&self, mut sub_values_iter_index: usize) -> Option<(CellKeyValue, usize)> {
        match self.sub_values.get(sub_values_iter_index) {
            Some(value) => {
                sub_values_iter_index += 1;
                Some((value.clone(), sub_values_iter_index))
            }
            _ => None,
        }
    }

    pub fn next_sub_key(&mut self, parser: &mut Parser) -> Option<CellKeyNode> {
        match self.get_sub_key_by_index(parser, self.iteration_state.sub_keys_iter_index) {
            Some(sub_key) => {
                self.iteration_state.sub_keys_iter_index += 1;
                Some(sub_key)
            }
            _ => None,
        }
    }

    pub(crate) fn lowercase(&self) -> String {
        self.path.to_ascii_lowercase()
    }

    pub(crate) fn is_key_root(&self) -> bool {
        self.key_node_flags.contains(KeyNodeFlags::KEY_HIVE_ENTRY)
    }

    pub fn get_pretty_path(&self) -> &str {
        &self.path[util::get_root_path_offset(&self.path)..]
    }
}

pub struct CellKeyNodeValueIterator<'a> {
    inner: &'a CellKeyNode,
    sub_values_iter_index: usize,
}

impl Iterator for CellKeyNodeValueIterator<'_> {
    type Item = CellKeyValue;

    // Why isn't this just implemented entirely here, rather than in 'CellKeyValue::next_value(...)'?
    // Because pyo3 doesn't allow exposure of objects with lifetimes, so we need to be able to call CellKeyValue::next_value directly in pynotatin
    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next_value(self.sub_values_iter_index) {
            Some((val, sub_values_iter_index)) => {
                self.sub_values_iter_index = sub_values_iter_index;
                Some(val)
            }
            _ => None,
        }
    }
}

bitflags! {
    #[allow(non_camel_case_types)]
    #[derive(Default)]
    pub struct AccessFlags: u32 {
        /// This key was accessed before a Windows registry was initialized with the NtInitializeRegistry() routine during the boot
        const ACCESSED_BEFORE_INIT = 0x00000001;
        /// This key was accessed after a Windows registry was initialized with the NtInitializeRegistry() routine during the boot
        const ACCESSED_AFTER_INIT  = 0x00000002;
    }
}
impl_serialize_for_bitflags! { AccessFlags }
impl_flags_from_bits! { AccessFlags, u32 }

bitflags! {
    #[allow(non_camel_case_types)]
    #[derive(Default)]
    pub struct KeyNodeFlags: u16 {
        /// Is volatile (not used, a key node on a disk isn't expected to have this flag set)
        const KEY_VOLATILE       = 0x0001;
        /// Is the mount point of another hive (a key node on a disk isn't expected to have this flag set)
        const KEY_HIVE_EXIT      = 0x0002;
        /// Is the root key for this hive
        const KEY_HIVE_ENTRY     = 0x0004;
        /// This key can't be deleted
        const KEY_NO_DELETE      = 0x0008;
        /// This key is a symlink (a target key is specified as a UTF-16LE string (REG_LINK) in a value named "SymbolicLinkValue", example: \REGISTRY\MACHINE\SOFTWARE\Classes\Wow6432Node)
        const KEY_SYM_LINK       = 0x0010;
        /// Key name is an ASCII string, possibly an extended ASCII string (otherwise it is a UTF-16LE string)
        const KEY_COMP_NAME      = 0x0020;
        /// Is a predefined handle (a handle is stored in the Number of key values field)
        const KEY_PREDEF_HANDLE  = 0x0040;
        /// This key was virtualized at least once
        const KEY_VIRTUAL_SOURCE = 0x0080;
        /// Is virtual
        const KEY_VIRTUAL_TARGET = 0x0100;
        /// Is a part of a virtual store path
        const KEY_VIRTUAL_STORE  = 0x0200;
        const KEY_UNKNOWN1       = 0x1000;
        const KEY_UNKNOWN2       = 0x4000;
    }
}
impl_serialize_for_bitflags! { KeyNodeFlags }
impl_flags_from_bits! { KeyNodeFlags, u16 }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_key_value::{CellKeyValueDataTypes, CellKeyValueDetail, CellKeyValueFlags};
    use crate::filter::RegQueryBuilder;
    use crate::parser_builder::ParserBuilder;
    use nom::error::ErrorKind;

    #[test]
    fn test_iterator() {
        let filter = Filter::from_path(
            RegQueryBuilder::from_key("Control Panel\\Accessibility\\Keyboard Response")
                .return_child_keys(true)
                .build(),
        );
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .with_filter(filter)
            .build()
            .unwrap();
        for key in parser.iter_include_ancestors() {
            for val in key.value_iter() {
                println!("{}", val.value_name);
            }
        }
    }

    #[test]
    fn test_get_sub_key_by_path() {
        let filter = Filter::from_path(RegQueryBuilder::from_key("Control Panel").build());
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .with_filter(filter)
            .build()
            .unwrap();
        let mut key = parser.next_key_postorder(true).unwrap();

        let sub_key = key
            .get_sub_key_by_path(&mut parser, "Accessibility")
            .unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\Control Panel\Accessibility",
            sub_key.path
        );

        let sub_key = key
            .get_sub_key_by_path(&mut parser, "Accessibility\\AudioDescription")
            .unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\Control Panel\Accessibility\AudioDescription",
            sub_key.path
        );

        let invalid_sub_key = key.get_sub_key_by_path(&mut parser, "Accessibility\\Nope");
        assert_eq!(None, invalid_sub_key);

        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .build()
            .unwrap();
        let mut key = parser.get_root_key().unwrap().unwrap();
        let sub_key = key.get_sub_key_by_path(&mut parser, "").unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}",
            sub_key.path
        );
    }

    #[test]
    fn test_get_sub_key_by_index() {
        let filter =
            Filter::from_path(RegQueryBuilder::from_key("Control Panel\\Accessibility").build());
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .with_filter(filter)
            .build()
            .unwrap();
        let mut key = parser.next_key_postorder(true).unwrap();
        let sub_key = key.get_sub_key_by_index(&mut parser, 0).unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\Control Panel\Accessibility\AudioDescription",
            sub_key.path
        );
        let sub_key = key.get_sub_key_by_index(&mut parser, 11).unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\Control Panel\Accessibility\TimeOut",
            sub_key.path
        );

        let invalid_sub_key = key.get_sub_key_by_index(&mut parser, 20);
        assert_eq!(None, invalid_sub_key);
    }

    #[test]
    fn test_next_sub_key() {
        let filter =
            Filter::from_path(RegQueryBuilder::from_key("Control Panel\\Accessibility").build());
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .with_filter(filter)
            .build()
            .unwrap();
        let mut key = parser.next_key_postorder(true).unwrap();
        let sub_key = key.next_sub_key(&mut parser).unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\Control Panel\Accessibility\AudioDescription",
            sub_key.path
        );
        let sub_key = key.next_sub_key(&mut parser).unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\Control Panel\Accessibility\Blind Access",
            sub_key.path
        );
    }

    #[test]
    fn test_get_value() {
        let filter = Filter::from_path(
            RegQueryBuilder::from_key("Control Panel\\Accessibility\\Keyboard Response").build(),
        );
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .with_filter(filter)
            .build()
            .unwrap();
        let key = parser.iter_postorder_include_ancestors().next().unwrap();
        let val = key.get_value("delayBeforeAcceptance");
        let hash_array: [u8; blake3::OUT_LEN] = [
            0x37, 0x5c, 0xce, 0x20, 0x66, 0xc3, 0x70, 0x09, 0x20, 0xc6, 0xe0, 0xe2, 0x4a, 0xe3,
            0x88, 0xaf, 0xa3, 0x15, 0x8d, 0x04, 0xb9, 0x1d, 0x86, 0xa9, 0xc6, 0xd7, 0xb9, 0xe0,
            0xb5, 0xa3, 0xb2, 0xef,
        ];

        let expected = CellKeyValue {
            detail: CellKeyValueDetail {
                file_offset_absolute: 117656,
                size: -48,
                value_name_size: 21,
                data_size_raw: 10,
                data_offset_relative: 113608,
                data_type_raw: 1,
                flags_raw: 1,
                padding: 0,
                value_bytes: Some(vec![49, 0, 48, 0, 48, 0, 48, 0, 0, 0]),
                slack: vec![0, 0, 0],
            },
            data_type: CellKeyValueDataTypes::REG_SZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            data_offsets_absolute: vec![117708],
            value_name: "DelayBeforeAcceptance".to_string(),
            logs: Logs::default(),
            versions: Vec::new(),
            cell_state: CellState::Allocated,
            hash: Some(hash_array.into()),
            sequence_num: None,
            updated_by_sequence_num: None,
        };
        assert_eq!(Some(expected), val);
    }

    #[test]
    fn test_parse_cell_key_node() {
        let buffer = [
            0x70, 0xFF, 0xFF, 0xFF, 0x6E, 0x6B, 0x2C, 0x00, 0x99, 0x66, 0xDF, 0x7A, 0x32, 0x4A,
            0xD0, 0x01, 0x02, 0x00, 0x00, 0x00, 0x20, 0x08, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00, 0x68, 0x02, 0x00, 0x80, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x50, 0x22, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x44, 0x00, 0x43, 0x00, 0x39, 0x00, 0x00, 0x00, 0x43, 0x73, 0x69, 0x54,
            0x6F, 0x6F, 0x6C, 0x2D, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x48, 0x69, 0x76, 0x65,
            0x2D, 0x7B, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2D, 0x30, 0x30, 0x30,
            0x30, 0x2D, 0x30, 0x30, 0x30, 0x30, 0x2D, 0x30, 0x30, 0x30, 0x30, 0x2D, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x7D, 0x00, 0x63, 0x00,
            0x6F, 0x00, 0x6D, 0x00,
        ];
        let file_info = FileInfo {
            hbin_offset_absolute: 4096,
            buffer: buffer.to_vec(),
        };
        let mut state = State::default();
        let (_, key_node) =
            CellKeyNode::from_bytes(&mut state, &file_info.buffer[0..], 0, &String::new(), None)
                .unwrap();
        let hash_array: [u8; blake3::OUT_LEN] = [
            0xfa, 0x8e, 0x6e, 0xc3, 0xf0, 0xa9, 0xbf, 0xf5, 0xbb, 0x82, 0x82, 0x0a, 0x44, 0xcb,
            0x07, 0x75, 0x01, 0x6f, 0x64, 0x8b, 0x07, 0x00, 0xe4, 0x62, 0xab, 0x3e, 0x0a, 0xcb,
            0x18, 0x12, 0x85, 0xf7,
        ];

        let expected_output = CellKeyNode {
            detail: CellKeyNodeDetail {
                file_offset_absolute: 0,
                size: -144,
                number_of_volatile_sub_keys: 1,
                sub_keys_list_offset_relative: 1920,
                volatile_sub_keys_list_offset_relative: -2147483032,
                key_values_list_offset_relative: -1,
                security_key_offset_relative: 139856,
                class_name_offset_relative: -1,
                largest_sub_key_name_size: 40,
                largest_sub_key_class_name_size: 0,
                largest_value_name_size: 0,
                largest_value_data_size: 0,
                work_var: 4390980,
                key_name_size: 57,
                class_name_size: 0,
                slack: vec![0, 99, 0, 111, 0, 109, 0],
            },
            key_node_flags: KeyNodeFlags::KEY_HIVE_ENTRY
                | KeyNodeFlags::KEY_NO_DELETE
                | KeyNodeFlags::KEY_COMP_NAME,
            last_key_written_date_and_time: util::get_date_time_from_filetime(130685969864025753),
            access_flags: AccessFlags::ACCESSED_AFTER_INIT,
            parent_key_offset_relative: 2080,
            number_of_sub_keys: 10,
            number_of_key_values: 0,
            key_name: "CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}".to_string(),
            path: String::from("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}"),
            cell_state: CellState::Allocated,
            sub_values: Vec::new(),
            logs: Logs::default(),
            cell_sub_key_offsets_absolute: Vec::new(),
            iteration_state: CellKeyNodeIteration {
                to_return: 0,
                track_returned: 0,
                filter_state: None,
                sub_keys_iter_index: 0,
            },
            versions: Vec::new(),
            deleted_keys: Vec::new(),
            hash: Some(hash_array.into()),
            sequence_num: None,
            updated_by_sequence_num: None,
        };
        assert_eq!(expected_output, key_node);

        let slice = &file_info.buffer[0..10];
        let ret = CellKeyNode::from_bytes(&mut state, slice, 0, &String::new(), None);
        let remaining = &file_info.buffer[4..10];
        let expected_error = Err(nom::Err::Error(nom::error::Error {
            input: remaining,
            code: ErrorKind::Eof,
        }));
        assert_eq!(expected_error, ret);
    }

    #[test]
    fn test_get_pretty_path() {
        let key_node = CellKeyNode {
            path: String::from("\\Root\\folder1\\folder2"),
            ..Default::default()
        };
        assert_eq!("folder1\\folder2", key_node.get_pretty_path());
    }
}
