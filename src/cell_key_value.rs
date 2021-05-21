use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32},
    take
};
use std::{
    convert::TryInto,
    mem
};
use bitflags::bitflags;
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use serde::{Serialize, Serializer};
use crate::err::Error;
use crate::log::{Logs, LogCode};
use crate::util;
use crate::file_info::FileInfo;
use crate::state::State;
use crate::hive_bin_cell;
use crate::cell_value::CellValue;
use crate::cell_big_data::CellBigData;
use crate::impl_serialize_for_bitflags;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive, Serialize)]
#[repr(u32)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum CellKeyValueDataTypes {
    REG_NONE                           = 0x0000,
    REG_SZ                             = 0x0001,
    REG_EXPAND_SZ                      = 0x0002,
    REG_BIN                            = 0x0003,
    REG_DWORD                          = 0x0004,
    REG_DWORD_BIG_ENDIAN               = 0x0005,
    REG_LINK                           = 0x0006,
    REG_MULTI_SZ                       = 0x0007,
    REG_RESOURCE_LIST                  = 0x0008,
    REG_FULL_RESOURCE_DESCRIPTOR       = 0x0009,
    REG_RESOURCE_REQUIREMENTS_LIST     = 0x000A,
    REG_QWORD                          = 0x000B,
    REG_FILETIME                       = 0x0010,
    // Per https://github.com/williballenthin/python-registry/blob/master/Registry/RegistryParse.py
    // Composite value types used in settings.dat registry hive, used to store AppContainer settings in Windows Apps aka UWP.
    REG_COMPOSITE_UINT8                = 0x0101,
    REG_COMPOSITE_INT16                = 0x0102,
    REG_COMPOSITE_UINT16               = 0x0103,
    REG_COMPOSITE_INT32                = 0x0104,
    REG_COMPOSITE_UINT32               = 0x0105,
    REG_COMPOSITE_INT64                = 0x0106,
    REG_COMPOSITE_UINT64               = 0x0107,
    REG_COMPOSITE_FLOAT                = 0x0108,
    REG_COMPOSITE_DOUBLE               = 0x0109,
    REG_COMPOSITE_UNICODE_CHAR         = 0x010A,
    REG_COMPOSITE_BOOLEAN              = 0x010B,
    REG_COMPOSITE_UNICODE_STRING       = 0x010C,
    REG_COMPOSITE_COMPOSITE_VALUE      = 0x010D,
    REG_COMPOSITE_DATE_TIME_OFFSET     = 0x010E,
    REG_COMPOSITE_TIME_SPAN            = 0x010F,
    REG_COMPOSITE_GUID                 = 0x0110,
    REG_COMPOSITE_UNK_111              = 0x0111,
    REG_COMPOSITE_UNK_112              = 0x0112,
    REG_COMPOSITE_UNK_113              = 0x0113,
    REG_COMPOSITE_BYTES_ARRAY          = 0x0114,
    REG_COMPOSITE_INT16_ARRAY          = 0x0115,
    REG_COMPOSITE_UINT16_ARRAY         = 0x0116,
    REG_COMPOSITE_INT32_ARRAY          = 0x0117,
    REG_COMPOSITE_UINT32_ARRAY         = 0x0118,
    REG_COMPOSITE_INT64_ARRAY          = 0x0119,
    REG_COMPOSITE_UINT64_ARRAY         = 0x011A,
    REG_COMPOSITE_FLOAT_ARRAY          = 0x011B,
    REG_COMPOSITE_DOUBLE_ARRAY         = 0x011C,
    REG_COMPOSITE_UNICODE_CHAR_ARRAY   = 0x011D,
    REG_COMPOSITE_BOOLEAN_ARRAY        = 0x011E,
    REG_COMPOSITE_UNICODE_STRING_ARRAY = 0x011F,
    REG_UNKNOWN                        = 999,
}

impl CellKeyValueDataTypes {
    pub(crate) fn get_value_content(&self, input_vec: Option<&Vec<u8>>, logs: &mut Logs) -> Result<CellValue, Error> {
        match input_vec {
            None => Ok(CellValue::ValueNone),
            Some(input_vec) => {
                let input = &input_vec[..];
                let cv = match self {
                    CellKeyValueDataTypes::REG_NONE =>
                        CellValue::ValueNone,
                    CellKeyValueDataTypes::REG_SZ |
                    CellKeyValueDataTypes::REG_EXPAND_SZ |
                    CellKeyValueDataTypes::REG_LINK =>
                        CellValue::ValueString(util::from_utf16_le_string(input, input.len(), logs, &"Get value content")),
                    CellKeyValueDataTypes::REG_COMPOSITE_UINT8 =>
                        CellValue::ValueU32(u8::from_le_bytes(input[0..mem::size_of::<u8>()].try_into()?) as u32),
                    CellKeyValueDataTypes::REG_COMPOSITE_INT16 =>
                        CellValue::ValueI32(i16::from_le_bytes(input[0..mem::size_of::<i16>()].try_into()?) as i32),
                    CellKeyValueDataTypes::REG_COMPOSITE_UINT16 =>
                        CellValue::ValueU32(u16::from_le_bytes(input[0..mem::size_of::<u16>()].try_into()?) as u32),
                    CellKeyValueDataTypes::REG_DWORD |
                    CellKeyValueDataTypes::REG_COMPOSITE_UINT32 =>
                        CellValue::ValueU32(u32::from_le_bytes(input[0..mem::size_of::<u32>()].try_into()?) as u32),
                    CellKeyValueDataTypes::REG_DWORD_BIG_ENDIAN =>
                        CellValue::ValueU32(u32::from_be_bytes(input[0..mem::size_of::<u32>()].try_into()?) as u32),
                    CellKeyValueDataTypes::REG_COMPOSITE_INT32 =>
                        CellValue::ValueI32(i32::from_le_bytes(input[0..mem::size_of::<i32>()].try_into()?)),
                    CellKeyValueDataTypes::REG_COMPOSITE_INT64 =>
                        CellValue::ValueI64(i64::from_le_bytes(input[0..mem::size_of::<i64>()].try_into()?)),
                    CellKeyValueDataTypes::REG_QWORD |
                    CellKeyValueDataTypes::REG_COMPOSITE_UINT64 =>
                        CellValue::ValueU64(u64::from_le_bytes(input[0..mem::size_of::<u64>()].try_into()?)),
                    CellKeyValueDataTypes::REG_BIN =>
                        CellValue::ValueBinary(input.to_vec()),
                    CellKeyValueDataTypes::REG_MULTI_SZ =>
                        CellValue::ValueMultiString(util::from_utf16_le_strings(input, input.len(), logs, &"Get value content")),
                    _ =>
                        CellValue::ValueBinary(input.to_vec()),
                };
                Ok(cv)
            }
        }
    }

    pub(crate) fn get_value_bytes(&self, input: &[u8]) -> Vec<u8> {
        let slice = match self {
            CellKeyValueDataTypes::REG_NONE =>
                &input[0..0],
            CellKeyValueDataTypes::REG_COMPOSITE_UINT8 =>
                &input[0..mem::size_of::<u8>()],
            CellKeyValueDataTypes::REG_COMPOSITE_INT16 =>
                &input[0..mem::size_of::<i16>()],
            CellKeyValueDataTypes::REG_COMPOSITE_UINT16 =>
                &input[0..mem::size_of::<u16>()],
            CellKeyValueDataTypes::REG_DWORD |
            CellKeyValueDataTypes::REG_COMPOSITE_UINT32 =>
                &input[0..mem::size_of::<u32>()],
            CellKeyValueDataTypes::REG_DWORD_BIG_ENDIAN =>
                &input[0..mem::size_of::<u32>()],
            CellKeyValueDataTypes::REG_COMPOSITE_INT32 =>
                &input[0..mem::size_of::<i32>()],
            CellKeyValueDataTypes::REG_COMPOSITE_INT64 =>
                &input[0..mem::size_of::<i64>()],
            CellKeyValueDataTypes::REG_QWORD |
            CellKeyValueDataTypes::REG_COMPOSITE_UINT64 =>
                &input[0..mem::size_of::<u64>()],
            _ =>
                input
        };
        slice.to_vec()
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CellKeyValueDetail {
    pub file_offset_absolute: usize,
    pub size: u32,
    pub value_name_size: u16, // If the value name size is 0 the value name is "(default)"
    pub data_size: u32, // In bytes, can be 0 (value isn't set); the most significant bit has a special meaning
    pub data_offset: u32, // In bytes, relative from the start of the hive bin's data (or data itself)
    pub data_type_raw: u32,
    pub padding: u16,
    #[serde(skip_serializing)]
    pub value_bytes: Option<Vec<u8>>
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellKeyValue {
    pub detail: CellKeyValueDetail,
    pub data_type: CellKeyValueDataTypes,
    pub flags: CellKeyValueFlags,
    pub value_name: String,
    pub logs: Logs
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
    pub const BIG_DATA_SIZE_THRESHOLD: u32 = 16344;

    pub(crate) fn from_bytes<'a>(
        file_info: &FileInfo,
        state: &mut State,
        input: &'a [u8]
    ) -> IResult<&'a [u8], Self> {
        let file_offset_absolute = file_info.get_file_offset(input);
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("vk")(input)?;
        let (input, value_name_size) = le_u16(input)?;
        let (input, data_size) = le_u32(input)?;
        let (input, data_offset) = le_u32(input)?;
        let (input, data_type_raw) = le_u32(input)?;
        let (input, flags) = le_u16(input)?;
        let flags = CellKeyValueFlags::from_bits(flags).unwrap_or_default();
        let (input, padding) = le_u16(input)?;
        let (input, value_name_bytes) = take!(input, value_name_size)?;

        const DEVPROP_MASK_TYPE: u32 = 0x00000FFF;
        let data_type_bytes = data_type_raw & DEVPROP_MASK_TYPE;
        let data_type = match CellKeyValueDataTypes::from_u32(data_type_bytes) {
            None => CellKeyValueDataTypes::REG_UNKNOWN,
            Some(data_type) => data_type
        };

        let mut logs = Logs::default();
        let value_name;
        if value_name_size == 0 {
            value_name = String::from("(Default)");
        }
        else {
            value_name = util::string_from_bytes(
                flags.contains(CellKeyValueFlags::VALUE_COMP_NAME_ASCII),
                value_name_bytes,
                value_name_size,
                &mut logs,
                "value_name_bytes");
        }

        state.update_track_cells(file_offset_absolute);
        Ok((
            input,
            CellKeyValue {
                detail: CellKeyValueDetail {
                    file_offset_absolute,
                    size: size.abs() as u32,
                    value_name_size,
                    data_size,
                    data_offset,
                    data_type_raw,
                    padding,
                    value_bytes: None,
                },
                data_type,
                flags,
                value_name,
                logs: Logs::default()
            },
        ))
    }

    /// Reads the value content and stores it in self.detail.value_bytes
    pub(crate) fn read_value_bytes(
        &mut self,
        file_info: &FileInfo,
        state: &mut State
    ) {
        const DATA_IS_RESIDENT_MASK: u32 = 0x80000000;
        let value_bytes;
        if self.detail.data_size & DATA_IS_RESIDENT_MASK == 0 {
            let mut offset = self.detail.data_offset as usize + file_info.hbin_offset_absolute;
            if CellKeyValue::BIG_DATA_SIZE_THRESHOLD < self.detail.data_size && CellBigData::is_big_data_block(&file_info.buffer[offset..]) {
                value_bytes =
                    CellBigData::get_big_data_bytes(file_info, state, offset, self.data_type, self.detail.data_size)
                        .or_else(
                            |err| -> Result<Vec<u8>, Error> {
                                self.logs.add(LogCode::WarningBigDataContent, &err);
                                Ok(Vec::new())
                            }
                        )
                        .expect("Error handled in or_else");
            }
            else {
                state.update_track_cells(offset);
                offset += mem::size_of_val(&self.detail.size); // skip over the size bytes
                value_bytes = self.data_type.get_value_bytes(&file_info.buffer[offset .. offset + self.detail.data_size as usize]);
            }
        }
        else {
            let value = self.detail.data_offset.to_le_bytes();
            value_bytes = self.data_type.get_value_bytes(&value[..(self.detail.data_size ^ DATA_IS_RESIDENT_MASK) as usize]);
        }
        self.detail.value_bytes = Some(value_bytes);
    }

    /// Returns a CellValue containing `self.detail.value_bytes` interpreted as `self.data_type`
    pub fn get_content(&self) -> (CellValue, Option<Logs>) {
        let mut warnings = Logs::default();
        let cell_value = self.data_type.get_value_content(self.detail.value_bytes.as_ref(), &mut warnings)
            .or_else(
                |err| -> Result<CellValue, Error> {
                    warnings.add(LogCode::WarningContent, &err);
                    Ok(CellValue::ValueError)
                }
            )
            .expect("We just handled the error case");

        match warnings.get() {
            Some(_) => (cell_value, Some(warnings)),
            _ => (cell_value, None)
        }
    }
}

impl hive_bin_cell::Cell for CellKeyValue {
    fn size(&self) -> u32 {
        self.detail.size
    }

    fn lowercase(&self) -> Option<String> {
        Some(self.value_name.clone().to_ascii_lowercase())
    }

    fn is_key(&self) -> bool {
        false
    }
}

/// Wrapper class to dynamically convert value_bytes into a parsed CellValue when serde serialize is called
#[derive(Debug, Serialize)]
struct CellKeyValueForSerialization<'a> {
    detail: &'a CellKeyValueDetail,
    data_type: &'a CellKeyValueDataTypes,
    flags: &'a CellKeyValueFlags,
    value_name: &'a String,
    cell_parse_warnings: &'a Logs,
    value: CellValue,
    value_parse_warnings: Option<Logs>
}

impl<'a> From<&'a CellKeyValue> for CellKeyValueForSerialization<'a> {
    fn from(other: &'a CellKeyValue) -> Self {
        let (value, value_parse_warnings) = other.get_content();
        Self {
            detail: &other.detail,
            data_type: &other.data_type,
            flags: &other.flags,
            value_name: &other.value_name,
            cell_parse_warnings: &other.logs,
            value,
            value_parse_warnings
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_key_node::CellKeyNode;
    use crate::filter::Filter;

    #[test]
    fn test_parse_cell_key_value() {
        let mut file_info = FileInfo::from_path("test_data/NTUSER.DAT").unwrap();
        file_info.hbin_offset_absolute = 4096;
        let mut state = State::default();
        let (_, mut key_value) = CellKeyValue::from_bytes(&file_info, &mut state, &file_info.buffer[4400..4448]).unwrap();
        let expected_output = CellKeyValue {
            detail: CellKeyValueDetail {
                file_offset_absolute: 4400,
                size: 48,
                value_name_size: 18,
                data_size: 8,
                data_offset: 1928,
                data_type_raw: 1,
                padding: 1280,
                value_bytes: None
            },
            data_type: CellKeyValueDataTypes::REG_SZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            value_name: "IE5_UA_Backup_Flag".to_string(),
            logs: Logs::default()
        };
        assert_eq!(
            expected_output,
            key_value
        );

        let mut file_info = FileInfo::from_path("test_data/NTUSER.DAT").unwrap();
        file_info.hbin_offset_absolute = 4096;
        key_value.read_value_bytes(&file_info, &mut state);
        assert_eq!(
            (CellValue::ValueString("5.0".to_string()), None),
            key_value.get_content()
        );
    }

    #[test]
    fn test_parse_big_data() {
        let mut file_info = FileInfo::from_path("test_data/FuseHive").unwrap();
        file_info.hbin_offset_absolute = 4096;
        let mut state = State::default();
        let (key_node, _) = CellKeyNode::read(&file_info, &mut state, 4416, &String::new(), &Filter::new()).unwrap();
        let key_node = key_node.unwrap();
        assert_eq!(
            "v".to_string(),
            key_node.sub_values[1].value_name
        );
        let (cell_value, _) = key_node.sub_values[1].get_content();
        if let CellValue::ValueBinary(content) = cell_value {
            assert_eq!(
                81725,
                content.len()
            );
            content.iter().for_each(|c| assert_eq!(50, *c));
        }
        else {
            assert_eq!(true, false, "key_node.sub_values[1].value_content was unexpected type");
        }
    }
}