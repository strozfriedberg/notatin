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
use crate::cell::{Cell, CellState};
use crate::cell_key_security;
use crate::cell_key_value::CellKeyValue;
use crate::err::Error;
use crate::field_offset_len::{FieldFull, FieldLight};
use crate::field_serializers;
use crate::file_info::FileInfo;
use crate::filter::{Filter, FilterBuilder, FilterFlags};
use crate::impl_enum;
use crate::impl_flags_from_bits;
use crate::impl_serialize_for_bitflags;
use crate::init_value_enum;
use crate::log::{LogCode, Logs};
use crate::make_field_struct;
use crate::make_file_offset_structs;
use crate::parser::Parser;
use crate::read_value_offset_length;
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
use winstructs::security::SecurityDescriptor;

make_file_offset_structs!(
    CellKeyNodeDetail {
        size: i32,
        signature: String,
        key_node_flag_bits: u16; serde(serialize_with = "field_serializers::field_key_node_flag_bits_interpreted"),
        last_key_written_date_and_time: u64; serde(serialize_with = "field_serializers::field_last_key_written_date_and_time_interpreted"),
        access_flag_bits: u32; serde(serialize_with = "field_serializers::field_acccess_flag_bits_interpreted"),
        parent_key_offset_relative: i32,
        number_of_sub_keys: u32,
        number_of_volatile_sub_keys: u32,
        sub_keys_list_offset_relative: u32,
        volatile_sub_keys_list_offset_relative: i32,
        number_of_key_values: u32,
        key_values_list_offset_relative: i32,
        security_key_offset_relative: u32,
        class_name_offset_relative: i32,
        largest_sub_key_name_size: u32,
        largest_sub_key_class_name_size: u32,
        largest_value_name_size: u32,
        largest_value_data_size: u32,
        work_var: u32,
        key_name_size: u16,
        class_name_size: u16,
        slack: Vec<u8>,
    }
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum FilterMatchState {
    None,
    Descendent,
    Exact,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CellKeyNodeIteration {
    pub(crate) to_return: u32,
    pub(crate) track_returned: u32,
    pub(crate) filter_state: Option<FilterMatchState>,
    pub(crate) sub_keys_iter_index: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CellKeyNode {
    pub file_offset_absolute: usize,
    pub detail: CellKeyNodeDetailEnum,
    pub key_name: String,
    pub path: String,
    pub cell_state: CellState,
    pub sequence_num: Option<u32>,
    pub updated_by_sequence_num: Option<u32>,
    pub(crate) sub_values: Vec<CellKeyValue>, // sub_values includes deleted values, if present
    pub logs: Logs,

    #[serde(skip)]
    pub cell_sub_key_offsets_absolute: Vec<u32>,

    #[serde(skip)]
    pub hash: Option<Hash>,
    #[serde(skip)]
    pub versions: Vec<Self>,
    #[serde(skip)]
    pub deleted_keys: Vec<Self>,
    #[serde(skip)]
    pub(crate) iteration_state: CellKeyNodeIteration,
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
    const SIGNATURE: &'static str = "nk";

    pub fn key_node_flags(&self, logs: &mut Logs) -> KeyNodeFlags {
        KeyNodeFlags::from_bits_checked(self.detail.key_node_flag_bits(), logs)
    }

    pub fn access_flags(&self, logs: &mut Logs) -> AccessFlags {
        AccessFlags::from_bits_checked(self.detail.access_flag_bits(), logs)
    }

    fn check_size(size: i32, input_len: usize) -> bool {
        let size_abs = size.unsigned_abs() as usize;
        Self::MIN_CELL_KEY_SIZE <= size_abs && size_abs <= input_len
    }

    /// Returns the byte length of the cell (regardless of if it's allocated or free)
    pub(crate) fn get_cell_size(&self) -> usize {
        self.detail.size().unsigned_abs() as usize
    }

    pub fn last_key_written_date_and_time(&self) -> DateTime<Utc> {
        util::get_date_time_from_filetime(self.detail.last_key_written_date_and_time())
    }

    pub(crate) fn is_free(&self) -> bool {
        self.detail.size() > 0
    }

    pub(crate) fn slack_offset_absolute(&self) -> usize {
        self.file_offset_absolute + self.get_cell_size() - self.detail.slack().len()
    }

    fn from_bytes<'a>(
        state: &mut State,
        input: &'a [u8],
        file_offset_absolute: usize,
        cur_path: &str,
        sequence_num: Option<u32>,
    ) -> IResult<&'a [u8], Self> {
        let get_full_field_info = state.get_full_field_info;
        let start_pos_ptr = input.as_ptr() as usize;

        init_value_enum! { CellKeyNodeDetail, detail_enum, get_full_field_info };

        read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, size, i32, le_i32 };
        if !Self::check_size(size, input.len() + std::mem::size_of::<i32>()) {
            Err(nom::Err::Error(nom::error::Error {
                input,
                code: nom::error::ErrorKind::Eof,
            }))
        } else {
            let signature_offset = input.as_ptr() as usize - start_pos_ptr;
            let (input, _signature) = tag(Self::SIGNATURE)(input)?;
            detail_enum.set_signature_full(
                &Self::SIGNATURE.to_owned(),
                signature_offset,
                Self::SIGNATURE.len() as u32,
            );

            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, key_node_flag_bits, u16, le_u16 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, last_key_written_date_and_time, u64, le_u64 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, access_flag_bits, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, parent_key_offset_relative, i32, le_i32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, number_of_sub_keys, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, number_of_volatile_sub_keys, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, sub_keys_list_offset_relative, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, volatile_sub_keys_list_offset_relative, i32, le_i32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, number_of_key_values, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, key_values_list_offset_relative, i32, le_i32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, security_key_offset_relative, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, class_name_offset_relative, i32, le_i32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, largest_sub_key_name_size, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, largest_sub_key_class_name_size, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, largest_value_name_size, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, largest_value_data_size, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, work_var, u32, le_u32 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, key_name_size, u16, le_u16 }
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, class_name_size, u16, le_u16 }

            let mut logs = Logs::default();

            let (input, key_name_bytes) = take!(input, key_name_size)?;
            let key_node_flags = KeyNodeFlags::from_bits_checked(key_node_flag_bits, &mut logs);
            //let access_flags = AccessFlags::from_bits_checked(access_flag_bits, &mut logs);

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

            let slack_offset = input.as_ptr() as usize - start_pos_ptr;
            let size_abs = size.unsigned_abs();
            let (input, slack_bytes) = util::parser_eat_remaining(input, size_abs, slack_offset)?;
            detail_enum.set_slack_full(
                &slack_bytes.to_vec(),
                slack_offset,
                slack_bytes.len() as u32,
            );

            let cell_key_node = Self {
                detail: detail_enum,
                file_offset_absolute,
                //key_node_flags,
                //access_flags,
                key_name,
                path,
                cell_state: CellState::Allocated,
                sub_values: Vec::new(),
                logs,
                cell_sub_key_offsets_absolute: Vec::new(),
                iteration_state: CellKeyNodeIteration::default(),
                versions: Vec::new(),
                deleted_keys: Vec::new(),
                hash: Some(Self::hash(
                    state,
                    key_node_flag_bits,
                    last_key_written_date_and_time,
                    access_flag_bits,
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
        let path = if self.is_key_root() { "" } else { &self.path };
        if !self.cell_state.is_deleted_primary_file() {
            if let Some(deleted_keys) = state.deleted_keys.get(path) {
                self.deleted_keys = deleted_keys.to_vec();
                for dk in self.deleted_keys.iter_mut() {
                    dk.update_modified_lists(state);
                }
            }
            if let Some(modified_keys) = state.modified_keys.get(path) {
                self.versions = modified_keys.to_vec();
                self.versions
                    .sort_by(|a, b| b.sequence_num.cmp(&a.sequence_num));
            }

            for val in &mut self.sub_values {
                if let Some(modified_values) =
                    state.modified_values.get(path, &val.detail.value_name())
                {
                    val.versions = modified_values.to_vec();
                    val.versions
                        .sort_by(|a, b| b.sequence_num.cmp(&a.sequence_num));
                }
            }

            if let Some(deleted_values) = state.deleted_values.get(path) {
                let mut deleted_values = deleted_values.to_vec();
                deleted_values.sort_by(|a, b| a.detail.value_name().cmp(&b.detail.value_name()));
                self.sub_values.extend(deleted_values.to_vec());
            }
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

    /// Reads a key node from a slice.
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

        if cell_key_node.detail.number_of_key_values() > 0
            && Self::should_read_values(
                options.filter,
                filter_flags,
                options.self_is_filter_match_or_descendent,
            )
            && cell_key_node
                .read_values(file_info, state, options.sequence_num)
                .is_err()
        {
            cell_key_node.logs.add(
                LogCode::WarningParse,
                &format!(
                    "Unable to parse values for cell key node {} (offset: {})",
                    cell_key_node.path, cell_key_node.file_offset_absolute
                ),
            )
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
            file_info
                .buffer
                .get(options.offset..)
                .ok_or_else(|| Error::buffer("cell_key_node::read"))?,
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
            let mut children = Vec::with_capacity(self.detail.number_of_sub_keys() as usize);
            let mut found_key = false;
            if self.detail.number_of_sub_keys() > 0 {
                match Self::parse_sub_key_list(
                    file_info,
                    state,
                    self.detail.sub_keys_list_offset_relative(),
                ) {
                    Ok(cell_sub_key_offsets_absolute) => {
                        let self_is_filter_match_or_descendent =
                            self.is_filter_match_or_descendent();
                        let sub_filter =
                            if self_is_filter_match_or_descendent && filter.return_sub_keys() {
                                None
                            } else {
                                Some(filter)
                            };
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
                            (self.detail.sub_keys_list_offset_relative() as usize
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
            let filter = FilterBuilder::new()
                .add_key_path(&format!("{}\\{}", self.path, sub_path))
                .key_path_has_root(true)
                .build()
                .unwrap_or_default();
            self.get_sub_key_internal(&parser.file_info, &mut parser.state, &filter, None)
        }
    }

    pub fn get_sub_key_by_index(&mut self, parser: &mut Parser, index: usize) -> Option<Self> {
        if self.detail.number_of_sub_keys() > 0 {
            match Self::parse_sub_key_list(
                &parser.file_info,
                &mut parser.state,
                self.detail.sub_keys_list_offset_relative(),
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
                        (self.detail.sub_keys_list_offset_relative() as usize
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
        if self.detail.key_values_list_offset_relative() > 0
            && (self.detail.key_values_list_offset_relative() as usize) < file_info.buffer.len()
        {
            self.sub_values = Vec::with_capacity(self.detail.number_of_key_values() as usize);
            let (_, key_values) = Self::parse_key_values(
                file_info,
                self.detail.number_of_key_values(),
                self.detail.key_values_list_offset_relative(),
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
                let (_, mut cell_key_value) = CellKeyValue::from_bytes(
                    file_info
                        .buffer
                        .get(offset..)
                        .ok_or_else(|| Error::buffer("read_values"))?,
                    offset,
                    sequence_num,
                    state.get_full_field_info,
                )?;

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
            self.detail.security_key_offset_relative(),
            file_info.hbin_offset_absolute,
        )
    }

    pub fn get_value(&self, find_value_name: &str) -> Option<CellKeyValue> {
        let find_value_name = find_value_name.to_ascii_lowercase();
        let val = self
            .sub_values
            .iter()
            .find(|v| v.detail.value_name().to_ascii_lowercase() == find_value_name);
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
        let slice = file_info
            .buffer
            .get(list_offset_relative as usize + file_info.hbin_offset_absolute..)
            .ok_or(nom::Err::Error(nom::error::Error {
                input: &file_info.buffer[..],
                code: nom::error::ErrorKind::Eof,
            }))?;
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
        let slice = file_info
            .buffer
            .get(file_offset_absolute..)
            .ok_or_else(|| Error::buffer("parse_sub_key_list"))?;
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
        let mut logs = Logs::default();
        self.key_node_flags(&mut logs)
            .contains(KeyNodeFlags::KEY_HIVE_ENTRY)
    }

    /// Returns path without root key
    pub fn get_pretty_path(&self) -> &str {
        &self.path[util::get_root_path_offset(&self.path)..]
    }
}

impl Cell for CellKeyNode {
    fn get_file_offset_absolute(&self) -> usize {
        self.file_offset_absolute
    }

    fn get_hash(&self) -> Option<blake3::Hash> {
        self.hash
    }

    fn get_logs(&self) -> &Logs {
        &self.logs
    }

    /// Returns true for an item that is deleted, modified, or is an allocated item that contains a modified version
    fn has_or_is_recovered(&self) -> bool {
        self.cell_state.is_deleted()
            || self.cell_state == CellState::ModifiedTransactionLog
            || !self.versions.is_empty()
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
    use crate::cell_key_value::{
        CellKeyValueDataTypes, CellKeyValueDetailEnum, CellKeyValueDetailFull,
        CellKeyValueDetailLight, CellKeyValueFlags,
    };
    use crate::filter::FilterBuilder;
    use crate::parser::{ParserIterator, ParserIteratorContext};
    use crate::parser_builder::ParserBuilder;
    use nom::error::ErrorKind;

    #[test]
    fn test_get_sub_key_by_path() -> Result<(), Error> {
        let filter = FilterBuilder::new().add_key_path("Control Panel").build()?;
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;
        let mut iter_context =
            ParserIteratorContext::from_parser(&parser, true, Some((filter, true)));
        let mut key = parser.next_key_postorder(&mut iter_context).unwrap();

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

        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;
        let mut key = parser.get_root_key().unwrap().unwrap();
        let sub_key = key.get_sub_key_by_path(&mut parser, "").unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}",
            sub_key.path
        );
        Ok(())
    }

    #[test]
    fn test_get_sub_key_by_index() -> Result<(), Error> {
        let filter = FilterBuilder::new()
            .add_key_path("Control Panel\\Accessibility")
            .build()?;
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;
        let mut iter_context =
            ParserIteratorContext::from_parser(&parser, true, Some((filter, true)));
        let mut key = parser.next_key_postorder(&mut iter_context).unwrap();
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
        Ok(())
    }

    #[test]
    fn test_next_sub_key() -> Result<(), Error> {
        let filter = FilterBuilder::new()
            .add_key_path("Control Panel\\Accessibility")
            .build()?;
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;
        let mut iter_context =
            ParserIteratorContext::from_parser(&parser, true, Some((filter, true)));
        let mut key = parser.next_key_postorder(&mut iter_context).unwrap();
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
        Ok(())
    }

    #[test]
    fn test_get_value() -> Result<(), Error> {
        let filter = FilterBuilder::new()
            .add_key_path("Control Panel\\Accessibility\\Keyboard Response")
            .build()?;
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;
        let hash_array: [u8; blake3::OUT_LEN] = [
            0x37, 0x5c, 0xce, 0x20, 0x66, 0xc3, 0x70, 0x09, 0x20, 0xc6, 0xe0, 0xe2, 0x4a, 0xe3,
            0x88, 0xaf, 0xa3, 0x15, 0x8d, 0x04, 0xb9, 0x1d, 0x86, 0xa9, 0xc6, 0xd7, 0xb9, 0xe0,
            0xb5, 0xa3, 0xb2, 0xef,
        ];
        let key = ParserIterator::new(&parser)
            .with_filter(filter.clone())
            .iter()
            .next()
            .unwrap();
        let val = key.get_value("delayBeforeAcceptance");
        let expected = CellKeyValue {
            file_offset_absolute: 117656,
            detail: CellKeyValueDetailEnum::Light(Box::new(CellKeyValueDetailLight {
                size: FieldLight { value: -48 },
                signature: FieldLight {
                    value: "vk".to_string(),
                },
                value_name_size: FieldLight { value: 21 },
                data_size_raw: FieldLight { value: 10 },
                data_offset_relative: FieldLight { value: 113608 },
                data_type_raw: FieldLight { value: 1 },
                flags_raw: FieldLight { value: 1 },
                padding: FieldLight { value: 0 },
                value_name: FieldLight {
                    value: "DelayBeforeAcceptance".to_string(),
                },
                value_bytes: FieldLight {
                    value: Some(vec![49, 0, 48, 0, 48, 0, 48, 0, 0, 0]),
                },
                slack: FieldLight {
                    value: vec![0, 0, 0],
                },
            })),
            data_type: CellKeyValueDataTypes::REG_SZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            data_offsets_absolute: vec![117708],
            logs: Logs::default(),
            versions: Vec::new(),
            cell_state: CellState::Allocated,
            hash: Some(hash_array.into()),
            sequence_num: None,
            updated_by_sequence_num: None,
        };
        assert_eq!(Some(expected), val);

        parser.state.get_full_field_info = true;
        let key = ParserIterator::new(&parser)
            .with_filter(filter)
            .iter()
            .next()
            .unwrap();
        let val = key.get_value("delayBeforeAcceptance");
        let expected = CellKeyValue {
            file_offset_absolute: 117656,
            detail: CellKeyValueDetailEnum::Full(Box::new(CellKeyValueDetailFull {
                size: FieldFull {
                    value: -48,
                    offset: 0,
                    len: 4,
                },
                signature: FieldFull {
                    value: "vk".to_string(),
                    offset: 4,
                    len: 2,
                },
                value_name_size: FieldFull {
                    value: 21,
                    offset: 6,
                    len: 2,
                },
                data_size_raw: FieldFull {
                    value: 10,
                    offset: 8,
                    len: 4,
                },
                data_offset_relative: FieldFull {
                    value: 113608,
                    offset: 12,
                    len: 4,
                },
                data_type_raw: FieldFull {
                    value: 1,
                    offset: 16,
                    len: 4,
                },
                flags_raw: FieldFull {
                    value: 1,
                    offset: 20,
                    len: 2,
                },
                padding: FieldFull {
                    value: 0,
                    offset: 22,
                    len: 2,
                },
                value_name: FieldFull {
                    value: "DelayBeforeAcceptance".to_string(),
                    offset: 24,
                    len: 21,
                },
                slack: FieldFull {
                    value: vec![0, 0, 0],
                    offset: 45,
                    len: 3,
                },
                value_bytes: FieldFull {
                    value: Some(vec![49, 0, 48, 0, 48, 0, 48, 0, 0, 0]),
                    offset: 117656,
                    len: 10,
                },
            })),
            data_type: CellKeyValueDataTypes::REG_SZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            data_offsets_absolute: vec![117708],
            logs: Logs::default(),
            versions: Vec::new(),
            cell_state: CellState::Allocated,
            hash: Some(hash_array.into()),
            sequence_num: None,
            updated_by_sequence_num: None,
        };
        assert_eq!(Some(expected), val);
        Ok(())
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

        let expected_light_output = CellKeyNode {
            detail: CellKeyNodeDetailEnum::Light(Box::new(CellKeyNodeDetailLight {
                size: FieldLight { value: -144 },
                signature: FieldLight {
                    value: "nk".to_string(),
                },
                access_flag_bits: FieldLight { value: 2 },
                key_node_flag_bits: FieldLight { value: 44 },
                parent_key_offset_relative: FieldLight { value: 2080 },
                last_key_written_date_and_time: FieldLight {
                    value: 130685969864025753,
                },
                number_of_sub_keys: FieldLight { value: 10 },
                number_of_key_values: FieldLight { value: 0 },
                number_of_volatile_sub_keys: FieldLight { value: 1 },
                sub_keys_list_offset_relative: FieldLight { value: 1920 },
                volatile_sub_keys_list_offset_relative: FieldLight { value: -2147483032 },
                key_values_list_offset_relative: FieldLight { value: -1 },
                security_key_offset_relative: FieldLight { value: 139856 },
                class_name_offset_relative: FieldLight { value: -1 },
                largest_sub_key_name_size: FieldLight { value: 40 },
                largest_sub_key_class_name_size: FieldLight { value: 0 },
                largest_value_name_size: FieldLight { value: 0 },
                largest_value_data_size: FieldLight { value: 0 },
                work_var: FieldLight { value: 4390980 },
                key_name_size: FieldLight { value: 57 },
                class_name_size: FieldLight { value: 0 },
                slack: FieldLight {
                    value: vec![0, 99, 0, 111, 0, 109, 0],
                },
            })),
            file_offset_absolute: 0,
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
        assert_eq!(expected_light_output, key_node);

        state.get_full_field_info = true;
        let (_, key_node) =
            CellKeyNode::from_bytes(&mut state, &file_info.buffer[0..], 0, &String::new(), None)
                .unwrap();
        let expected_full_output = CellKeyNode {
            detail: CellKeyNodeDetailEnum::Full(Box::new(CellKeyNodeDetailFull {
                size: FieldFull {
                    value: -144,
                    offset: 0,
                    len: 4,
                },
                signature: FieldFull {
                    value: "nk".to_string(),
                    offset: 4,
                    len: 2,
                },
                access_flag_bits: FieldFull {
                    value: 2,
                    offset: 16,
                    len: 4,
                },
                key_node_flag_bits: FieldFull {
                    value: 44,
                    offset: 6,
                    len: 2,
                },
                parent_key_offset_relative: FieldFull {
                    value: 2080,
                    offset: 20,
                    len: 4,
                },
                last_key_written_date_and_time: FieldFull {
                    value: 130685969864025753,
                    offset: 8,
                    len: 8,
                },
                number_of_sub_keys: FieldFull {
                    value: 10,
                    offset: 24,
                    len: 4,
                },
                number_of_key_values: FieldFull {
                    value: 0,
                    offset: 40,
                    len: 4,
                },
                number_of_volatile_sub_keys: FieldFull {
                    value: 1,
                    offset: 28,
                    len: 4,
                },
                sub_keys_list_offset_relative: FieldFull {
                    value: 1920,
                    offset: 32,
                    len: 4,
                },
                volatile_sub_keys_list_offset_relative: FieldFull {
                    value: -2147483032,
                    offset: 36,
                    len: 4,
                },
                key_values_list_offset_relative: FieldFull {
                    value: -1,
                    offset: 44,
                    len: 4,
                },
                security_key_offset_relative: FieldFull {
                    value: 139856,
                    offset: 48,
                    len: 4,
                },
                class_name_offset_relative: FieldFull {
                    value: -1,
                    offset: 52,
                    len: 4,
                },
                largest_sub_key_name_size: FieldFull {
                    value: 40,
                    offset: 56,
                    len: 4,
                },
                largest_sub_key_class_name_size: FieldFull {
                    value: 0,
                    offset: 60,
                    len: 4,
                },
                largest_value_name_size: FieldFull {
                    value: 0,
                    offset: 64,
                    len: 4,
                },
                largest_value_data_size: FieldFull {
                    value: 0,
                    offset: 68,
                    len: 4,
                },
                work_var: FieldFull {
                    value: 4390980,
                    offset: 72,
                    len: 4,
                },
                key_name_size: FieldFull {
                    value: 57,
                    offset: 76,
                    len: 2,
                },
                class_name_size: FieldFull {
                    value: 0,
                    offset: 78,
                    len: 2,
                },
                slack: FieldFull {
                    value: vec![0, 99, 0, 111, 0, 109, 0],
                    offset: 137,
                    len: 7,
                },
            })),
            file_offset_absolute: 0,
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
        assert_eq!(expected_full_output, key_node);

        let mut logs = Logs::default();
        assert_eq!(
            KeyNodeFlags::KEY_HIVE_ENTRY
                | KeyNodeFlags::KEY_NO_DELETE
                | KeyNodeFlags::KEY_COMP_NAME,
            key_node.key_node_flags(&mut logs)
        );
        assert_eq!(
            AccessFlags::ACCESSED_AFTER_INIT,
            key_node.access_flags(&mut logs)
        );

        let ret = CellKeyNode::from_bytes(
            &mut state,
            &file_info.buffer[0..10],
            0,
            &String::new(),
            None,
        );
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
