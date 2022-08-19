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
use crate::cell_big_data::CellBigData;
use crate::cell_value::{CellValue, DecodableValue, DecodeFormat};
use crate::err::Error;
use crate::field_offset_len::{FieldFull, FieldLight};
use crate::field_serializers;
use crate::file_info::FileInfo;
use crate::impl_enum;
use crate::impl_serialize_for_bitflags;
use crate::init_value_enum;
use crate::log::{LogCode, Logs};
use crate::make_field_struct;
use crate::make_file_offset_structs;
use crate::read_value_offset_length;
use crate::state::State;
use crate::util;
use bitflags::bitflags;
use blake3::Hash;
use enum_primitive_derive::Primitive;
use nom::{
    bytes::complete::tag,
    number::complete::{le_i32, le_u16, le_u32},
    take, IResult,
};
use num_traits::FromPrimitive;
use serde::{Serialize, Serializer};
use std::{convert::TryInto, mem};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive, Serialize)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum CellKeyValueDataTypes {
    REG_NONE = 0x0000,
    REG_SZ = 0x0001,
    REG_EXPAND_SZ = 0x0002,
    REG_BIN = 0x0003,
    REG_DWORD = 0x0004,
    REG_DWORD_BIG_ENDIAN = 0x0005,
    REG_LINK = 0x0006,
    REG_MULTI_SZ = 0x0007,
    REG_RESOURCE_LIST = 0x0008,
    REG_FULL_RESOURCE_DESCRIPTOR = 0x0009,
    REG_RESOURCE_REQUIREMENTS_LIST = 0x000A,
    REG_QWORD = 0x000B,
    REG_FILETIME = 0x0010,
    // Per https://github.com/williballenthin/python-registry/blob/master/Registry/RegistryParse.py
    // Composite value types used in settings.dat registry hive, used to store AppContainer settings in Windows Apps aka UWP.
    REG_COMPOSITE_UINT8 = 0x0101,
    REG_COMPOSITE_INT16 = 0x0102,
    REG_COMPOSITE_UINT16 = 0x0103,
    REG_COMPOSITE_INT32 = 0x0104,
    REG_COMPOSITE_UINT32 = 0x0105,
    REG_COMPOSITE_INT64 = 0x0106,
    REG_COMPOSITE_UINT64 = 0x0107,
    REG_COMPOSITE_FLOAT = 0x0108,
    REG_COMPOSITE_DOUBLE = 0x0109,
    REG_COMPOSITE_UNICODE_CHAR = 0x010A,
    REG_COMPOSITE_BOOLEAN = 0x010B,
    REG_COMPOSITE_UNICODE_STRING = 0x010C,
    REG_COMPOSITE_COMPOSITE_VALUE = 0x010D,
    REG_COMPOSITE_DATE_TIME_OFFSET = 0x010E,
    REG_COMPOSITE_TIME_SPAN = 0x010F,
    REG_COMPOSITE_GUID = 0x0110,
    REG_COMPOSITE_UNK_111 = 0x0111,
    REG_COMPOSITE_UNK_112 = 0x0112,
    REG_COMPOSITE_UNK_113 = 0x0113,
    REG_COMPOSITE_BYTES_ARRAY = 0x0114,
    REG_COMPOSITE_INT16_ARRAY = 0x0115,
    REG_COMPOSITE_UINT16_ARRAY = 0x0116,
    REG_COMPOSITE_INT32_ARRAY = 0x0117,
    REG_COMPOSITE_UINT32_ARRAY = 0x0118,
    REG_COMPOSITE_INT64_ARRAY = 0x0119,
    REG_COMPOSITE_UINT64_ARRAY = 0x011A,
    REG_COMPOSITE_FLOAT_ARRAY = 0x011B,
    REG_COMPOSITE_DOUBLE_ARRAY = 0x011C,
    REG_COMPOSITE_UNICODE_CHAR_ARRAY = 0x011D,
    REG_COMPOSITE_BOOLEAN_ARRAY = 0x011E,
    REG_COMPOSITE_UNICODE_STRING_ARRAY = 0x011F,
    REG_UNKNOWN = 999,
}

impl CellKeyValueDataTypes {
    pub fn handle_invalid_input(input_vec: &[u8], logs: &mut Logs) -> CellValue {
        logs.add(
            LogCode::WarningConversion,
            &"Too few input bytes for data type",
        );
        CellValue::Binary(input_vec.to_vec())
    }

    #[rustfmt::skip]
    pub(crate) fn get_value_content(
        &self,
        input_vec: Option<&Vec<u8>>,
        logs: &mut Logs,
    ) -> Result<CellValue, Error> {
        match input_vec {
            None => Ok(CellValue::None),
            Some(input_vec) => {
                let input = &input_vec[..];
                let cv = match self {
                    CellKeyValueDataTypes::REG_SZ
                    | CellKeyValueDataTypes::REG_EXPAND_SZ
                    | CellKeyValueDataTypes::REG_LINK => CellValue::String(
                        util::from_utf16_le_string(input, input.len(), logs, "Get value content"),
                    ),
                    CellKeyValueDataTypes::REG_COMPOSITE_UINT8
                    | CellKeyValueDataTypes::REG_COMPOSITE_BOOLEAN => {
                        match input.get(0..mem::size_of::<u8>()) {
                            Some(val) => CellValue::U32(u8::from_le_bytes(val.try_into()?) as u32),
                            None => Self::handle_invalid_input(input_vec, logs),
                        }
                    }
                    CellKeyValueDataTypes::REG_COMPOSITE_INT16 => {
                        match input.get(0..mem::size_of::<i16>()) {
                            Some(val) => CellValue::I32(i16::from_le_bytes(val.try_into()?) as i32),
                            None => Self::handle_invalid_input(input_vec, logs),
                        }
                    }
                    CellKeyValueDataTypes::REG_COMPOSITE_UINT16 => {
                        match input.get(0..mem::size_of::<u16>()) {
                            Some(val) => CellValue::U32(u16::from_le_bytes(val.try_into()?) as u32),
                            None => Self::handle_invalid_input(input_vec, logs),
                        }
                    }
                    CellKeyValueDataTypes::REG_DWORD
                    | CellKeyValueDataTypes::REG_COMPOSITE_UINT32 => {
                        match input.get(0..mem::size_of::<u32>()) {
                            Some(val) => CellValue::U32(u32::from_le_bytes(val.try_into()?)),
                            None => Self::handle_invalid_input(input_vec, logs),
                        }
                    }
                    CellKeyValueDataTypes::REG_DWORD_BIG_ENDIAN => {
                        match input.get(0..mem::size_of::<u32>()) {
                            Some(val) => CellValue::U32(u32::from_be_bytes(val.try_into()?)),
                            None => Self::handle_invalid_input(input_vec, logs),
                        }
                    }
                    CellKeyValueDataTypes::REG_COMPOSITE_INT32 => {
                        match input.get(0..mem::size_of::<i32>()) {
                            Some(val) => CellValue::I32(i32::from_le_bytes(val.try_into()?)),
                            None => Self::handle_invalid_input(input_vec, logs),
                        }
                    }
                    CellKeyValueDataTypes::REG_COMPOSITE_INT64 => {
                        match input.get(0..mem::size_of::<i64>()) {
                            Some(val) => CellValue::I64(i64::from_le_bytes(val.try_into()?)),
                            None => Self::handle_invalid_input(input_vec, logs),
                        }
                    }
                    CellKeyValueDataTypes::REG_QWORD
                    | CellKeyValueDataTypes::REG_COMPOSITE_UINT64
                    | CellKeyValueDataTypes::REG_FILETIME => {
                        match input.get(0..mem::size_of::<u64>()) {
                            Some(val) => CellValue::U64(u64::from_le_bytes(val.try_into()?)),
                            None => Self::handle_invalid_input(input_vec, logs),
                        }
                    }
                    CellKeyValueDataTypes::REG_BIN => CellValue::Binary(input.to_vec()),
                    CellKeyValueDataTypes::REG_MULTI_SZ => CellValue::MultiString(
                        util::from_utf16_le_strings(input, input.len(), logs, "Get value content"),
                    ),
                    _ => CellValue::Binary(input.to_vec()),
                };
                Ok(cv)
            }
        }
    }

    pub(crate) fn get_data_type_len(&self) -> Option<usize> {
        match self {
            CellKeyValueDataTypes::REG_COMPOSITE_UINT8 => Some(mem::size_of::<u8>()),
            CellKeyValueDataTypes::REG_COMPOSITE_INT16 => Some(mem::size_of::<i16>()),
            CellKeyValueDataTypes::REG_COMPOSITE_UINT16 => Some(mem::size_of::<u16>()),
            CellKeyValueDataTypes::REG_DWORD
            | CellKeyValueDataTypes::REG_COMPOSITE_UINT32
            | CellKeyValueDataTypes::REG_DWORD_BIG_ENDIAN => Some(mem::size_of::<u32>()),
            CellKeyValueDataTypes::REG_COMPOSITE_INT32 => Some(mem::size_of::<i32>()),
            CellKeyValueDataTypes::REG_COMPOSITE_INT64 => Some(mem::size_of::<i64>()),
            CellKeyValueDataTypes::REG_QWORD
            | CellKeyValueDataTypes::REG_COMPOSITE_UINT64
            | CellKeyValueDataTypes::REG_FILETIME => Some(mem::size_of::<u64>()),
            _ => None,
        }
    }

    pub(crate) fn get_value_bytes(&self, input: &[u8]) -> Vec<u8> {
        match self.get_data_type_len() {
            Some(data_type_len) => input[0..std::cmp::min(data_type_len, input.len())].to_vec(), // ok as direct access (checking input.len())
            None => input.to_vec(),
        }
    }
}

bitflags! {
    #[derive(Default)]
    pub struct CellKeyValueFlags: u16 {
        const VALUE_COMP_NAME_ASCII = 1; // Name is an ASCII string / Otherwise the name is an Unicode (UTF-16 little-endian) string
        const IS_TOMBSTONE          = 2; // Is a tombstone value (the flag is used starting from Insider Preview builds of Windows 10 "Redstone 1"), a tombstone value also has the Data type field set to REG_NONE, the Data size field set to 0, and the Data offset field set to 0xFFFFFFFF
    }
}
impl_serialize_for_bitflags! {CellKeyValueFlags}

make_file_offset_structs!(
    CellKeyValueDetail {
        size: i32,
        signature: String,
        value_name_size: u16, // If the value name size is 0 the value name is "(default)"
        data_size_raw: u32, // In bytes, can be 0 (value isn't set); the most significant bit has a special meaning
        data_offset_relative: u32,
        data_type_raw: u32,
        flags_raw: u16,
        padding: u16,
        // value_name is an empty string for an unnamed value. This is displayed as __(Default)__ in Windows Registry Editor;
        // use `CellKeyValue::get_pretty_name()` to get __(default)__ rather than empty string for the name (lowercase to be compatible with `python-registry`)
        value_name: String; serde(serialize_with = "field_serializers::field_value_name_interpreted"),
        slack: Vec<u8>,
        value_bytes: Option<Vec<u8>>; serde(skip),
    }
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellKeyValue {
    pub file_offset_absolute: usize,
    pub detail: CellKeyValueDetailEnum,
    pub data_type: CellKeyValueDataTypes,
    pub flags: CellKeyValueFlags,
    pub data_offsets_absolute: Vec<usize>,
    pub cell_state: CellState,
    pub logs: Logs,

    pub versions: Vec<Self>,
    pub hash: Option<Hash>,
    pub sequence_num: Option<u32>,
    pub updated_by_sequence_num: Option<u32>,
}

impl Serialize for CellKeyValue {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CellKeyValueForSerialization::from(self).serialize(s)
    }
}

impl CellKeyValue {
    pub(crate) const BIG_DATA_SIZE_THRESHOLD: u32 = 16344;
    const MIN_CELL_VALUE_SIZE: usize = 24;
    const SIGNATURE: &'static str = "vk";

    pub fn get_content(&self) -> (CellValue, Option<Logs>) {
        let mut warnings = Logs::default();
        let cell_value = self
            .data_type
            .get_value_content(self.detail.value_bytes().as_ref(), &mut warnings)
            .or_else(|err| -> Result<CellValue, Error> {
                warnings.add(LogCode::WarningContent, &err);
                Ok(CellValue::Error)
            })
            .expect("Error handled in or_else");

        match warnings.get() {
            Some(_) => (cell_value, Some(warnings)),
            _ => (cell_value, None),
        }
    }

    pub fn get_pretty_name(&self) -> String {
        util::get_pretty_name(&self.detail.value_name())
    }

    /// Returns a CellValue containing `self.detail.value_bytes` interpreted as `self.data_type`
    pub(crate) fn from_bytes(
        input_orig: &[u8],
        file_offset_absolute: usize,
        sequence_num: Option<u32>,
        get_full_field_info: bool,
    ) -> IResult<&[u8], Self> {
        let start_pos_ptr = input_orig.as_ptr() as usize;

        init_value_enum! { CellKeyValueDetail, detail_enum, get_full_field_info };

        let input = input_orig;
        read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, size, i32, le_i32 };
        if !Self::check_size(size, input_orig) {
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

            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, value_name_size, u16, le_u16 };
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, data_size_raw, u32, le_u32 };
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, data_offset_relative, u32, le_u32 };
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, data_type_raw, u32, le_u32 };
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, flags_raw, u16, le_u16 };
            read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, padding, u16, le_u16 };
            let value_name_offset = input.as_ptr() as usize - start_pos_ptr;
            let (input, value_name_bytes) = take!(input, value_name_size)?;

            let flags = CellKeyValueFlags::from_bits(flags_raw).unwrap_or_default();

            const DEVPROP_MASK_TYPE: u32 = 0x00000FFF;
            let data_type_bytes = data_type_raw & DEVPROP_MASK_TYPE;
            let data_type = match CellKeyValueDataTypes::from_u32(data_type_bytes) {
                None => CellKeyValueDataTypes::REG_UNKNOWN,
                Some(data_type) => data_type,
            };

            let mut logs = Logs::default();

            let value_name = if value_name_size == 0 {
                String::new()
            } else {
                util::string_from_bytes(
                    flags.contains(CellKeyValueFlags::VALUE_COMP_NAME_ASCII),
                    value_name_bytes,
                    value_name_size,
                    &mut logs,
                    "value_name",
                )
            };
            detail_enum.set_value_name_full(&value_name, value_name_offset, value_name_size as u32);

            let slack_offset = input.as_ptr() as usize - start_pos_ptr;
            let size_abs = size.unsigned_abs();
            let (input, slack_bytes) = util::parser_eat_remaining(input, size_abs, slack_offset)?;
            detail_enum.set_slack_full(
                &slack_bytes.to_vec(),
                slack_offset,
                slack_bytes.len() as u32,
            );

            Ok((
                input,
                CellKeyValue {
                    file_offset_absolute,
                    detail: detail_enum,
                    data_type,
                    flags,
                    cell_state: CellState::Allocated,
                    data_offsets_absolute: Vec::new(),
                    logs,
                    versions: Vec::new(),
                    hash: None,
                    sequence_num,
                    updated_by_sequence_num: None,
                },
            ))
        }
    }

    /// Reads the value content and stores it in self.detail.value_bytes
    pub(crate) fn read_value_bytes(&mut self, file_info: &FileInfo, state: &mut State) {
        let (value_bytes, data_offsets_absolute) = Self::read_value_bytes_direct(
            self.file_offset_absolute,
            self.detail.data_size_raw(),
            self.detail.data_offset_relative(),
            &self.data_type,
            file_info,
            &mut self.logs,
        );

        self.data_offsets_absolute.extend(data_offsets_absolute);
        self.hash = Some(CellKeyValue::hash(
            state,
            self.detail.data_type_raw(),
            self.detail.flags_raw(),
            &value_bytes,
        ));
        let value_bytes_len = value_bytes.len() as u32;
        self.detail.set_value_bytes_full(
            &Some(value_bytes),
            self.file_offset_absolute,
            value_bytes_len,
        );
    }

    /// Returns the byte length of the cell (regardless of if it's allocated or free)
    pub(crate) fn get_cell_size(&self) -> usize {
        self.detail.size().unsigned_abs() as usize
    }

    pub(crate) fn is_free(&self) -> bool {
        self.detail.size() > 0
    }

    pub(crate) fn slack_offset_absolute(&self) -> usize {
        self.file_offset_absolute + self.get_cell_size() - self.detail.slack().len()
    }

    fn check_size(size: i32, input: &[u8]) -> bool {
        let size_abs = size.unsigned_abs() as usize;
        Self::MIN_CELL_VALUE_SIZE <= size_abs && size_abs <= input.len()
    }

    fn read_value_bytes_direct(
        file_offset_absolute: usize,
        data_size_raw: u32,
        data_offset_relative: u32,
        data_type: &CellKeyValueDataTypes,
        file_info: &FileInfo,
        logs: &mut Logs,
    ) -> (Vec<u8>, Vec<usize>) {
        const DATA_IS_RESIDENT_MASK: u32 = 0x80000000;
        let value_bytes;
        let mut data_offsets_absolute = Vec::new();
        if data_size_raw & DATA_IS_RESIDENT_MASK == 0 {
            let mut offset = data_offset_relative as usize + file_info.hbin_offset_absolute;

            if let Some(slice) = file_info.buffer.get(offset..) {
                if CellKeyValue::BIG_DATA_SIZE_THRESHOLD < data_size_raw
                    && CellBigData::is_big_data_block(slice)
                {
                    let (vb, offsets) = CellBigData::get_big_data_bytes(
                        file_info,
                        offset,
                        data_type,
                        data_size_raw,
                    )
                    .or_else(|err| -> Result<(Vec<u8>, Vec<usize>), Error> {
                        logs.add(LogCode::WarningBigDataContent, &err);
                        Ok((Vec::new(), Vec::new()))
                    })
                    .expect("Error handled in or_else");
                    value_bytes = vb;
                    data_offsets_absolute.extend(offsets);
                } else {
                    offset += mem::size_of::<i32>(); // skip over the size bytes
                    data_offsets_absolute.push(offset);

                    match file_info
                        .buffer
                        .get(offset..offset + data_size_raw as usize)
                    {
                        Some(slice) => value_bytes = data_type.get_value_bytes(slice),
                        None => {
                            logs.add(
                                LogCode::WarningParse,
                                &Error::buffer("read_value_bytes_direct: file_offset and length"),
                            );
                            value_bytes = Vec::new();
                        }
                    }
                }
            } else {
                logs.add(
                    LogCode::WarningParse,
                    &Error::buffer("read_value_bytes_direct: file_offset"),
                );
                value_bytes = Vec::new();
            }
        } else {
            const DATA_OFFSET_RELATIVE_OFFSET: usize = 12;
            data_offsets_absolute.push(file_offset_absolute + DATA_OFFSET_RELATIVE_OFFSET);
            let data_size = data_size_raw ^ DATA_IS_RESIDENT_MASK;
            let resident_value = data_offset_relative.to_le_bytes();

            match resident_value.get(..data_size as usize) {
                Some(slice) => value_bytes = data_type.get_value_bytes(slice),
                None => {
                    logs.add(
                        LogCode::WarningBigDataContent,
                        &Error::buffer("read_value_bytes_direct: resident_value"),
                    );
                    value_bytes = Vec::new();
                }
            }
        }
        (value_bytes, data_offsets_absolute)
    }

    fn hash(state: &mut State, data_type_raw: u32, flags_raw: u16, value_bytes: &[u8]) -> Hash {
        state.hasher.reset();
        state.hasher.update(&data_type_raw.to_le_bytes());
        state.hasher.update(&flags_raw.to_le_bytes());
        state.hasher.update(value_bytes);
        state.hasher.finalize()
    }
}

impl DecodableValue for CellKeyValue {
    fn decode_content(&self, format: &DecodeFormat, offset: usize) -> (CellValue, Option<Logs>) {
        let (content, _) = self.get_content();
        format.decode(&content, offset)
    }
}

impl Cell for CellKeyValue {
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

/// Wrapper class to dynamically convert value_bytes into a parsed CellValue when serde serialize is called.
// Why do we have the fields of CellKeyValue duplicated rather than just including a `CellKeyValue` ref?
// Because a ref creates a circular call when serializing!
#[derive(Debug, Serialize)]
struct CellKeyValueForSerialization<'a> {
    file_offset_absolute: usize,
    detail: &'a CellKeyValueDetailEnum,
    data_type: &'a CellKeyValueDataTypes,
    flags: &'a CellKeyValueFlags,
    value_name: String,
    cell_parse_warnings: &'a Logs,
    sequence_num: &'a Option<u32>,
    updated_by_sequence_num: &'a Option<u32>,
    data_offsets_absolute: &'a Vec<usize>,
    state: &'a CellState,
    value: CellValue,
    value_parse_warnings: Option<Logs>,
    versions: &'a Vec<CellKeyValue>,
}

impl<'a> From<&'a CellKeyValue> for CellKeyValueForSerialization<'a> {
    fn from(other: &'a CellKeyValue) -> Self {
        let (value, value_parse_warnings) = other.get_content();
        Self {
            file_offset_absolute: other.file_offset_absolute,
            detail: &other.detail,
            data_type: &other.data_type,
            flags: &other.flags,
            value_name: other.get_pretty_name(),
            cell_parse_warnings: &other.logs,
            data_offsets_absolute: &other.data_offsets_absolute,
            sequence_num: &other.sequence_num,
            updated_by_sequence_num: &other.updated_by_sequence_num,
            state: &other.cell_state,
            value,
            value_parse_warnings,
            versions: &other.versions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_key_node::{CellKeyNode, CellKeyNodeReadOptions};
    use crate::cell_key_value::{
        CellKeyValueDataTypes, CellKeyValueDetailEnum, CellKeyValueDetailFull,
        CellKeyValueDetailLight, CellKeyValueFlags,
    };
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_parse_cell_key_value() {
        let slice = [
            0xD0, 0xFF, 0xFF, 0xFF, 0x76, 0x6B, 0x12, 0x00, 0x08, 0x00, 0x00, 0x00, 0x18, 0x0F,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x49, 0x45, 0x35, 0x5F,
            0x55, 0x41, 0x5F, 0x42, 0x61, 0x63, 0x6B, 0x75, 0x70, 0x5F, 0x46, 0x6C, 0x61, 0x67,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        let file_info = FileInfo {
            hbin_offset_absolute: 4096,
            buffer: slice.to_vec(),
        };
        let mut state = State::default();
        let (_, key_value) =
            CellKeyValue::from_bytes(&file_info.buffer[..], 0, None, false).unwrap();

        let expected_output = CellKeyValue {
            file_offset_absolute: 0,
            detail: CellKeyValueDetailEnum::Light(Box::new(CellKeyValueDetailLight {
                size: FieldLight { value: -48 },
                signature: FieldLight {
                    value: "vk".to_string(),
                },
                value_name_size: FieldLight { value: 18 },
                data_size_raw: FieldLight { value: 8 },
                data_offset_relative: FieldLight { value: 3864 },
                data_type_raw: FieldLight { value: 1 },
                flags_raw: FieldLight { value: 1 },
                padding: FieldLight { value: 0 },
                value_bytes: FieldLight { value: None },
                value_name: FieldLight {
                    value: "IE5_UA_Backup_Flag".to_string(),
                },
                slack: FieldLight {
                    value: vec![0, 0, 1, 0, 0, 0],
                },
            })),
            data_type: CellKeyValueDataTypes::REG_SZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            cell_state: CellState::Allocated,
            data_offsets_absolute: Vec::new(),
            logs: Logs::default(),
            versions: Vec::new(),
            hash: None,
            sequence_num: None,
            updated_by_sequence_num: None,
        };
        assert_eq!(expected_output, key_value);

        let (_, mut key_value) =
            CellKeyValue::from_bytes(&file_info.buffer[..], 0, None, true).unwrap();
        let expected_output = CellKeyValue {
            file_offset_absolute: 0,
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
                    value: 18,
                    offset: 6,
                    len: 2,
                },
                data_size_raw: FieldFull {
                    value: 8,
                    offset: 8,
                    len: 4,
                },
                data_offset_relative: FieldFull {
                    value: 3864,
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
                value_bytes: FieldFull {
                    value: None,
                    offset: 0,
                    len: 0,
                },
                value_name: FieldFull {
                    value: "IE5_UA_Backup_Flag".to_string(),
                    offset: 24,
                    len: 18,
                },
                slack: FieldFull {
                    value: vec![0, 0, 1, 0, 0, 0],
                    offset: 42,
                    len: 6,
                },
            })),
            data_type: CellKeyValueDataTypes::REG_SZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            cell_state: CellState::Allocated,
            data_offsets_absolute: Vec::new(),
            logs: Logs::default(),
            versions: Vec::new(),
            hash: None,
            sequence_num: None,
            updated_by_sequence_num: None,
        };
        assert_eq!(expected_output, key_value);

        let mut file_info = FileInfo::from_path("test_data/NTUSER.DAT").unwrap();
        file_info.hbin_offset_absolute = 4096;
        key_value.read_value_bytes(&file_info, &mut state);
        assert_eq!(
            (CellValue::String("5.0".to_string()), None),
            key_value.get_content()
        );
    }

    #[test]
    fn test_decode_content() {
        let mut lznt1_file = File::open("test_data/lznt1_buffer").unwrap();
        let mut lznt1_buffer = Vec::new();
        lznt1_file.read_to_end(&mut lznt1_buffer).unwrap();
        let mut cell_key_value = CellKeyValue {
            detail: CellKeyValueDetailEnum::Light(Box::new(CellKeyValueDetailLight {
                size: FieldLight { value: 48 },
                signature: FieldLight {
                    value: "vk".to_string(),
                },
                value_name_size: FieldLight { value: 4 },
                data_size_raw: FieldLight {
                    value: lznt1_buffer.len() as u32,
                },
                data_offset_relative: FieldLight { value: 3864 },
                data_type_raw: FieldLight { value: 1 },
                flags_raw: FieldLight { value: 1 },
                padding: FieldLight { value: 0 },
                value_name: FieldLight {
                    value: "test".to_string(),
                },
                value_bytes: FieldLight {
                    value: Some(lznt1_buffer.clone()),
                },
                slack: FieldLight { value: vec![] },
            })),
            file_offset_absolute: 0,
            data_type: CellKeyValueDataTypes::REG_BIN,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            cell_state: CellState::Allocated,
            data_offsets_absolute: Vec::new(),
            logs: Logs::default(),
            versions: Vec::new(),
            hash: None,
            sequence_num: None,
            updated_by_sequence_num: None,
        };
        let (decoded_value, _) = cell_key_value.decode_content(&DecodeFormat::Lznt1, 8);

        let mut lznt1_decoded_file = File::open("test_data/lznt1_decoded_buffer").unwrap();
        let mut lznt1_decoded_buffer = Vec::new();
        lznt1_decoded_file
            .read_to_end(&mut lznt1_decoded_buffer)
            .unwrap();
        let expected_output = CellValue::Binary(lznt1_decoded_buffer);
        assert_eq!(expected_output, decoded_value);

        let cell_value_lznt1 = CellValue::Binary(lznt1_buffer);
        let (decoded_value, _) = cell_value_lznt1.decode_content(&DecodeFormat::Lznt1, 8);
        assert_eq!(expected_output, decoded_value);

        let (decoded_value, _) = cell_key_value
            .decode_content(&DecodeFormat::Lznt1, 8)
            .0
            .decode_content(&DecodeFormat::Utf16Multiple, 1860);
        let expected_output = CellValue::MultiString(vec![
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CSRSS.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\LOGONUI.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\EXPLORER.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\WUAUCLT.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\TASKHOST.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\EXPLORER.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NOTEPAD.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\WINDOWS NT\ACCESSORIES\WORDPAD.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CONSENT.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CONHOST.EXE".to_string(),
        ]);
        assert_eq!(expected_output, decoded_value);

        let (decoded_value, _) = cell_key_value
            .decode_content(&DecodeFormat::Lznt1, 8)
            .0
            .decode_content(&DecodeFormat::Utf16, 1860);
        let expected_output =
            CellValue::String(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CSRSS.EXE".to_string());
        assert_eq!(expected_output, decoded_value);

        let mut utf16_multiple_file = File::open("test_data/utf16_multiple_buffer").unwrap();
        let mut utf16_multiple_buffer = Vec::new();
        utf16_multiple_file
            .read_to_end(&mut utf16_multiple_buffer)
            .unwrap();
        cell_key_value
            .detail
            .set_data_size_raw(&(utf16_multiple_buffer.len() as u32), 0);
        cell_key_value
            .detail
            .set_value_bytes(&Some(utf16_multiple_buffer.clone()), 0);
        let (decoded_value, _) = cell_key_value.decode_content(&DecodeFormat::Utf16Multiple, 0);
        let expected_output = CellValue::MultiString(vec![
            "NAS_requested_data.7z".to_string(),
            "BlackHarrier_D7_i686_FDE_20141219.dd.7z".to_string(),
            "BlackHarrier_D7_amd64_20141217.7z".to_string(),
            "BlackHarrier_D7_amd64_FDE_20141217.7z".to_string(),
            r"C:\Users\jmroberts\Desktop\USB_Research\IEF.zip".to_string(),
            "Company_Report_10222013.vir.zip".to_string(),
            "LYNC.7z".to_string(),
            "viruses.zip".to_string(),
            "ALLDATA.txt.bz2".to_string(),
        ]);
        assert_eq!(expected_output, decoded_value);

        let cell_value_utf16_multiple = CellValue::Binary(utf16_multiple_buffer);
        let (decoded_value, _) =
            cell_value_utf16_multiple.decode_content(&DecodeFormat::Utf16Multiple, 0);
        assert_eq!(expected_output, decoded_value);

        let utf16 = vec![
            0x4E, 0x00, 0x41, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x72, 0x00, 0x65, 0x00, 0x71, 0x00,
            0x75, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00, 0x5F, 0x00,
            0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x7A, 0x00,
        ];
        cell_key_value
            .detail
            .set_data_size_raw(&(utf16.len() as u32), 0);
        cell_key_value
            .detail
            .set_value_bytes(&Some(utf16.clone()), 0);
        let (decoded_value, _) = cell_key_value.decode_content(&DecodeFormat::Utf16, 0);
        let expected_output = CellValue::String("NAS_requested_data.7z".to_string());
        assert_eq!(expected_output, decoded_value);

        let cell_value_utf16 = CellValue::Binary(utf16);
        let (decoded_value, _) = cell_value_utf16.decode_content(&DecodeFormat::Utf16, 0);
        assert_eq!(expected_output, decoded_value);

        let rot13 = vec![
            0x41, 0x00, 0x62, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x76, 0x00, 0x61, 0x00,
            0x20, 0x00, 0x68, 0x00, 0x61, 0x00, 0x76, 0x00, 0x67, 0x00, 0x20, 0x00, 0x67, 0x00,
            0x72, 0x00, 0x66, 0x00, 0x67, 0x00, 0x2E, 0x00,
        ];
        cell_key_value
            .detail
            .set_data_size_raw(&(rot13.len() as u32), 0);
        cell_key_value.detail.set_value_bytes(&Some(rot13), 0);
        cell_key_value.detail.set_data_type_raw(&1, 0);
        cell_key_value.data_type = CellKeyValueDataTypes::REG_SZ;
        let (decoded_value, _) = cell_key_value.decode_content(&DecodeFormat::Rot13, 0);
        let expected_output = CellValue::String("Notatin unit test.".to_string());
        assert_eq!(expected_output, decoded_value);

        let cell_value_rot13 = CellValue::String("Abgngva havg grfg.".to_string());
        let (decoded_value, _) = cell_value_rot13.decode_content(&DecodeFormat::Rot13, 0);
        assert_eq!(expected_output, decoded_value);
    }

    #[test]
    fn test_parse_big_data() {
        let mut file_info = FileInfo::from_path("test_data/system").unwrap();
        file_info.hbin_offset_absolute = 4096;
        let mut state = State::default();
        let key_node = CellKeyNode::read(
            &file_info,
            &mut state,
            CellKeyNodeReadOptions {
                offset: 16155688,
                cur_path: &String::new(),
                filter: None,
                self_is_filter_match_or_descendent: false,
                sequence_num: None,
                get_deleted_and_modified: false,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            "Binary_81725".to_string(),
            key_node.sub_values[1].detail.value_name()
        );
        let (cell_value, _) = key_node.sub_values[1].get_content();
        if let CellValue::Binary(content) = cell_value {
            assert_eq!(81725, content.len());
            content.iter().for_each(|c| assert_eq!(50, *c));
        } else {
            assert_eq!(
                true, false,
                "key_node.sub_values[1].value_content was unexpected type"
            );
        }
    }
}
