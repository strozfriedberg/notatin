use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32}
};

use std::convert::TryInto;
use std::mem;
use bitflags::bitflags;
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use serde::Serialize;
use crate::err::Error;
use crate::warn::{Warnings, WarningCode};
use crate::util;
use crate::registry::State;
use crate::hive_bin_cell;
use crate::cell_value::CellValue;
use crate::cell_big_data::CellBigData;
use crate::impl_serialize_for_bitflags;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive, Serialize)]
#[repr(u32)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum CellKeyValueDataTypes {
    REG_NONE                       = 0x0000,
    REG_SZ                         = 0x0001,
    REG_EXPAND_SZ                  = 0x0002,
    REG_BIN                        = 0x0003,
    REG_DWORD                      = 0x0004,
    REG_DWORD_BIG_ENDIAN           = 0x0005,
    REG_LINK                       = 0x0006,
    REG_MULTI_SZ                   = 0x0007,
    REG_RESOURCE_LIST              = 0x0008,
    REG_FULL_RESOURCE_DESCRIPTOR   = 0x0009,
    REG_RESOURCE_REQUIREMENTS_LIST = 0x000A,
    REG_QWORD                      = 0x000B,
    REG_FILETIME                   = 0x0010,
    // Following are new types from settings.dat
    // Per https://github.com/williballenthin/python-registry/blob/master/Registry/RegistryParse.py
    REG_UINT8                      = 0x0101,
    REG_INT16                      = 0x0102,
    REG_UINT16                     = 0x0103,
    REG_INT32                      = 0x0104,
    REG_UINT32                     = 0x0105,
    REG_INT64                      = 0x0106,
    REG_UINT64                     = 0x0107,
    REG_FLOAT                      = 0x0108,
    REG_DOUBLE                     = 0x0109,
    REG_UNICODE_CHAR               = 0x010A,
    REG_BOOLEAN                    = 0x010B,
    REG_UNICODE_STRING             = 0x010C,
    REG_COMPOSITE_VALUE            = 0x010D,
    REG_DATE_TIME_OFFSET           = 0x010E,
    REG_TIME_SPAN                  = 0x010F,
    REG_GUID                       = 0x0110,
    REG_UNK_111                    = 0x0111,
    REG_UNK_112                    = 0x0112,
    REG_UNK_113                    = 0x0113,
    REG_BYTES_ARRAY                = 0x0114,
    REG_INT16_ARRAY                = 0x0115,
    REG_UINT16_ARRAY               = 0x0116,
    REG_INT32_ARRAY                = 0x0117,
    REG_UINT32_ARRAY               = 0x0118,
    REG_INT64_ARRAY                = 0x0119,
    REG_UINT64_ARRAY               = 0x011A,
    REG_FLOAT_ARRAY                = 0x011B,
    REG_DOUBLE_ARRAY               = 0x011C,
    REG_UNICODE_CHAR_ARRAY         = 0x011D,
    REG_BOOLEAN_ARRAY              = 0x011E,
    REG_UNICODE_STRING_ARRAY       = 0x011F,
}

impl CellKeyValueDataTypes {
    pub fn get_value_content(self, input: &[u8]) -> Result<CellValue, Error> {
        let cv = match self {
            CellKeyValueDataTypes::REG_NONE =>
                CellValue::ValueNone,
            CellKeyValueDataTypes::REG_SZ |
            CellKeyValueDataTypes::REG_EXPAND_SZ |
            CellKeyValueDataTypes::REG_LINK => CellValue::ValueString(
                util::read_utf16_le_string(input, input.len())
            ),
            CellKeyValueDataTypes::REG_UINT8 => CellValue::ValueU32(
                u8::from_le_bytes(input[0..mem::size_of::<u8>()].try_into()?) as u32
            ),
            CellKeyValueDataTypes::REG_INT16 => CellValue::ValueI32(
                i16::from_le_bytes(input[0..mem::size_of::<i16>()].try_into()?) as i32
            ),
            CellKeyValueDataTypes::REG_UINT16 => CellValue::ValueU32(
                u16::from_le_bytes(input[0..mem::size_of::<u16>()].try_into()?) as u32
            ),
            CellKeyValueDataTypes::REG_DWORD |
            CellKeyValueDataTypes::REG_UINT32 => CellValue::ValueU32(
                u32::from_le_bytes(input[0..mem::size_of::<u32>()].try_into()?)
            ),
            CellKeyValueDataTypes::REG_DWORD_BIG_ENDIAN => CellValue::ValueU32(
                u32::from_be_bytes(input[0..mem::size_of::<u32>()].try_into()?)
            ),
            CellKeyValueDataTypes::REG_INT32 => CellValue::ValueI32(
                i32::from_le_bytes(input[0..mem::size_of::<i32>()].try_into()?)
            ),
            CellKeyValueDataTypes::REG_INT64 => CellValue::ValueI64(
                i64::from_le_bytes(input[0..mem::size_of::<i64>()].try_into()?)
            ),
            CellKeyValueDataTypes::REG_QWORD |
            CellKeyValueDataTypes::REG_UINT64 => CellValue::ValueU64(
                u64::from_le_bytes(input[0..mem::size_of::<u64>()].try_into()?)
            ),
            CellKeyValueDataTypes::REG_BIN => CellValue::ValueBinary(
                input.to_vec()
            ),
            CellKeyValueDataTypes::REG_MULTI_SZ => CellValue::ValueMultiString(
                util::read_utf16_le_strings(input, input.len())
            ),
            CellKeyValueDataTypes::REG_RESOURCE_LIST |
            CellKeyValueDataTypes::REG_FILETIME |
            CellKeyValueDataTypes::REG_FULL_RESOURCE_DESCRIPTOR |
            CellKeyValueDataTypes::REG_RESOURCE_REQUIREMENTS_LIST |
            CellKeyValueDataTypes::REG_FLOAT |
            CellKeyValueDataTypes::REG_DOUBLE |
            CellKeyValueDataTypes::REG_UNICODE_CHAR |
            CellKeyValueDataTypes::REG_BOOLEAN |
            CellKeyValueDataTypes::REG_UNICODE_STRING |
            CellKeyValueDataTypes::REG_COMPOSITE_VALUE |
            CellKeyValueDataTypes::REG_DATE_TIME_OFFSET |
            CellKeyValueDataTypes::REG_TIME_SPAN |
            CellKeyValueDataTypes::REG_GUID |
            CellKeyValueDataTypes::REG_UNK_111 |
            CellKeyValueDataTypes::REG_UNK_112 |
            CellKeyValueDataTypes::REG_UNK_113 |
            CellKeyValueDataTypes::REG_BYTES_ARRAY |
            CellKeyValueDataTypes::REG_INT16_ARRAY |
            CellKeyValueDataTypes::REG_UINT16_ARRAY |
            CellKeyValueDataTypes::REG_INT32_ARRAY |
            CellKeyValueDataTypes::REG_UINT32_ARRAY |
            CellKeyValueDataTypes::REG_INT64_ARRAY |
            CellKeyValueDataTypes::REG_UINT64_ARRAY |
            CellKeyValueDataTypes::REG_FLOAT_ARRAY |
            CellKeyValueDataTypes::REG_DOUBLE_ARRAY |
            CellKeyValueDataTypes::REG_UNICODE_CHAR_ARRAY |
            CellKeyValueDataTypes::REG_BOOLEAN_ARRAY |
            CellKeyValueDataTypes::REG_UNICODE_STRING_ARRAY =>
                CellValue::ValueBinary(input.to_vec()),
        };
        Ok(cv)
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

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellKeyValueDetail {
    pub absolute_file_offset: usize,
    pub size: u32,
    pub value_name_size: u16, // If the value name size is 0 the value name is "(default)"
    pub data_size: u32, // In bytes, can be 0 (value isn't set); the most significant bit has a special meaning
    pub data_offset: u32, // In bytes, relative from the start of the hive bin's data (or data itself)
    pub padding: u16,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellKeyValue {
    pub detail: CellKeyValueDetail,
    pub data_type: CellKeyValueDataTypes,
    pub flags: CellKeyValueFlags,
    pub value_name: String,
    pub value_content: Option<CellValue>,
    pub parse_warnings: Warnings
}

impl CellKeyValue {
    pub const BIG_DATA_SIZE_THRESHOLD: u32 = 16344;

    pub fn from_bytes<'a>(state: &State, input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let absolute_file_offset = state.get_file_offset(input);
        let start_pos = input.as_ptr() as usize;
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("vk")(input)?;
        let (input, value_name_size) = le_u16(input)?;
        let (input, data_size) = le_u32(input)?;
        let (input, data_offset) = le_u32(input)?;
        let (input, data_type_bytes) = le_u32(input)?;
        let (input, flags) = le_u16(input)?;
        let flags = CellKeyValueFlags::from_bits(flags).unwrap_or_default();
        let (input, padding) = le_u16(input)?;
        let (input, value_name_bytes) = take!(input, value_name_size)?;

        let data_type = match CellKeyValueDataTypes::from_u32(data_type_bytes) {
            None => CellKeyValueDataTypes::REG_NONE,
            Some(data_type) => data_type
        };

        let mut parse_warnings = Warnings::default();
        let value_name;
        if value_name_size == 0 {
            value_name = String::from("(Default)");
        }
        else if flags.contains(CellKeyValueFlags::VALUE_COMP_NAME_ASCII) {
            value_name = util::from_utf8(&value_name_bytes, &mut parse_warnings, "value_name_bytes");
        }
        else {
            value_name = util::read_utf16_le_string(value_name_bytes, (value_name_size / 2).into());
        }
        let size_abs = size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            CellKeyValue {
                detail: CellKeyValueDetail {
                    absolute_file_offset,
                    size: size_abs,
                    value_name_size,
                    data_size,
                    data_offset,
                    padding,
                },
                data_type,
                flags,
                value_name,
                value_content: None,
                parse_warnings: Warnings::default()
            },
        ))
    }

    pub fn read_content(&mut self, state: &State) {
        /* Per https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md:
            When the most significant bit is 1, data (4 bytes or less) is stored in the Data offset field directly
            (when data contains less than 4 bytes, it is being stored as is in the beginning of the Data offset field).
            The most significant bit (when set to 1) should be ignored when calculating the data size.
            When the most significant bit is 0, data is stored in the Cell data field of another cell (pointed by the Data offset field)
            or in the Cell data fields of multiple cells (referenced in the Big data structure stored in a cell pointed by the Data offset field). */
        const DATA_IS_RESIDENT_MASK: u32 = 0x80000000;
        let value_content;
        if self.detail.data_size & DATA_IS_RESIDENT_MASK == 0 {
            let mut offset = self.detail.data_offset as usize + state.hbin_offset;
            if CellKeyValue::BIG_DATA_SIZE_THRESHOLD < self.detail.data_size && CellBigData::is_big_data_block(&state.file_buffer[offset..]) {
                value_content =
                    CellBigData::get_big_data_content(state, offset, self.data_type, self.detail.data_size)
                        .or_else(
                            |err: Error| -> Result<CellValue, Error> {
                                self.parse_warnings.add_warning(WarningCode::WarningBigDataContent, &err);
                                Ok(CellValue::ValueError)
                            }
                        )
                        .expect("Error handled in or_else");
            }
            else {
                offset += mem::size_of_val(&self.detail.size);
                value_content = self.get_value_content(&state.file_buffer[offset .. offset + self.detail.data_size as usize]);
            }
        }
        else {
            let value = self.detail.data_offset.to_le_bytes();
            value_content = self.get_value_content(&value[..(self.detail.data_size ^ DATA_IS_RESIDENT_MASK) as usize]);
        }
        self.value_content = Some(value_content);
    }

    fn get_value_content(&mut self, input: &[u8]) -> CellValue {
        self.data_type.get_value_content(input)
            .or_else(
                |err: Error| -> Result<CellValue, Error> {
                    self.parse_warnings.add_warning(WarningCode::WarningContent, &err);
                    Ok(CellValue::ValueError)
                }
            )
            .expect("Error handled in or_else")
    }
}

impl hive_bin_cell::Cell for CellKeyValue {
    fn size(&self) -> u32 {
        self.detail.size
    }

    fn name_lowercase(&self) -> Option<String> {
        Some(self.value_name.clone().to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_key_node::CellKeyNode;
    use crate::filter::Filter;

    #[test]
    fn test_parse_cell_key_value() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4400..4448];

        let state = State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset: 4096,
            file_buffer: &f[..]
        };
        let ret = CellKeyValue::from_bytes(&state, slice);
        let expected_output = CellKeyValue {
            detail: CellKeyValueDetail {
                absolute_file_offset: 4400,
                size: 48,
                value_name_size: 18,
                data_size: 8,
                data_offset: 1928,
                padding: 1280,
            },
            data_type: CellKeyValueDataTypes::REG_SZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            value_name: "IE5_UA_Backup_Flag".to_string(),
            value_content: None,
            parse_warnings: Warnings::default()

        };
        let remaining: [u8; 0] = [];
        let expected = Ok((&remaining[..], expected_output));
        assert_eq!(
            expected,
            ret
        );
        let (_, mut cell_key_value) = ret.unwrap();

        let state = State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset: 4096,
            file_buffer: &f[..]
        };
        cell_key_value.read_content(&state);
        assert_eq!(
            CellValue::ValueString("5.0".to_string()),
            cell_key_value.value_content.unwrap()
        );
    }

    #[test]
    fn test_parse_big_data() {
        let f = std::fs::read("test_data/FuseHive").unwrap();
        let state = State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset: 4096,
            file_buffer: &f[..]
        };
        let key_node = CellKeyNode::read(&state, &f[4416..], String::new(), &mut Filter::new()).unwrap().unwrap();

        assert_eq!(
            "v".to_string(),
            key_node.sub_values[1].value_name
        );
        if let CellValue::ValueBinary(content) = key_node.sub_values[1].value_content.as_ref().unwrap() {
            assert_eq!(
                81719,
                content.len()
            );
            content.iter().for_each(|c| assert_eq!(50, *c));
        }
        else {
            assert_eq!(true, false, "key_node.sub_values[1].value_content was unexpected type");
        }
    }
}