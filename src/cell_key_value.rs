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
use blake3::Hash;
use crate::err::Error;
use crate::log::{Logs, LogCode};
use crate::util;
use crate::file_info::FileInfo;
use crate::state::State;
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
                if let Some(data_type_len) = self.get_data_type_len() {
                    if input_vec.len() < data_type_len {
                        logs.add(LogCode::WarningConversion, &"Too few input bytes for data type");
                        return Ok(CellValue::ValueBinary(input_vec.to_vec()));
                    }
                }
                let input = &input_vec[..];
                let cv = match self {
                    CellKeyValueDataTypes::REG_SZ |
                    CellKeyValueDataTypes::REG_EXPAND_SZ |
                    CellKeyValueDataTypes::REG_LINK =>
                        CellValue::ValueString(util::from_utf16_le_string(input, input.len(), logs, &"Get value content")),
                    CellKeyValueDataTypes::REG_COMPOSITE_UINT8 |
                    CellKeyValueDataTypes::REG_COMPOSITE_BOOLEAN =>
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
                    CellKeyValueDataTypes::REG_COMPOSITE_UINT64 |
                    CellKeyValueDataTypes::REG_FILETIME =>
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

    pub(crate) fn get_data_type_len(&self) -> Option<usize> {
        match self {
            CellKeyValueDataTypes::REG_COMPOSITE_UINT8 =>
                Some(mem::size_of::<u8>()),
            CellKeyValueDataTypes::REG_COMPOSITE_INT16 =>
                Some(mem::size_of::<i16>()),
            CellKeyValueDataTypes::REG_COMPOSITE_UINT16 =>
                Some(mem::size_of::<u16>()),
            CellKeyValueDataTypes::REG_DWORD |
            CellKeyValueDataTypes::REG_COMPOSITE_UINT32 |
            CellKeyValueDataTypes::REG_DWORD_BIG_ENDIAN =>
                Some(mem::size_of::<u32>()),
            CellKeyValueDataTypes::REG_COMPOSITE_INT32 =>
                Some(mem::size_of::<i32>()),
            CellKeyValueDataTypes::REG_COMPOSITE_INT64 =>
                Some(mem::size_of::<i64>()),
            CellKeyValueDataTypes::REG_QWORD |
            CellKeyValueDataTypes::REG_COMPOSITE_UINT64 |
            CellKeyValueDataTypes::REG_FILETIME =>
                Some(mem::size_of::<u64>()),
            _ =>
                None
        }
    }

    pub(crate) fn get_value_bytes(&self, input: &[u8]) -> Vec<u8> {
        match self.get_data_type_len() {
            Some(data_type_len) => input[0..std::cmp::min(data_type_len, input.len())].to_vec(),
            None => input.to_vec()
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

pub enum DecodeFormat {
    Lznt1,
    Rot13,
    Utf16,
    Utf16Multiple
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CellKeyValueDetail {
    pub file_offset_absolute: usize,
    pub size: u32,
    pub value_name_size: u16, // If the value name size is 0 the value name is "(default)"
    pub data_size_raw: u32, // In bytes, can be 0 (value isn't set); the most significant bit has a special meaning
    pub data_offset_relative: u32,
    pub data_type_raw: u32,
    pub flags_raw: u16,
    pub padding: u16,
    #[serde(skip_serializing)]
    pub value_bytes: Option<Vec<u8>>,
    pub slack: Vec<u8>
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellKeyValue {
    pub detail: CellKeyValueDetail,
    pub data_type: CellKeyValueDataTypes,
    pub flags: CellKeyValueFlags,
    pub data_offsets_absolute: Vec<usize>,
    /// value_name is an empty string for an unnamed value. This is displayed as `(Default)` in Windows Registry Editor;
    /// use `CellKeyValue::get_pretty_name()` to get `(default)` rather than empty string for the name
    pub value_name: String,
    pub logs: Logs,

    pub versions: Vec<Self>,
    pub hash: Option<Hash>,
    pub sequence_num: Option<u32>,
    pub updated_by_sequence_num: Option<u32>
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
        input: &'a [u8],
        sequence_num: Option<u32>
    ) -> IResult<&'a [u8], Self> {
        let start_pos = input.as_ptr() as usize;
        let file_offset_absolute = file_info.get_file_offset_from_ptr(start_pos);

        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("vk")(input)?;
        let (input, value_name_size) = le_u16(input)?;
        let (input, data_size_raw) = le_u32(input)?;
        let (input, data_offset_relative) = le_u32(input)?;
        let (input, data_type_raw) = le_u32(input)?;
        let (input, flags_raw) = le_u16(input)?;
        let flags = CellKeyValueFlags::from_bits(flags_raw).unwrap_or_default();
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
            value_name = String::new();
        }
        else {
            value_name = util::string_from_bytes(
                flags.contains(CellKeyValueFlags::VALUE_COMP_NAME_ASCII),
                value_name_bytes,
                value_name_size,
                &mut logs,
                "value_name_bytes");
        }
        let size_abs =  size.abs() as u32;
        let (input, slack) = util::parser_eat_remaining(input, size_abs, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            CellKeyValue {
                detail: CellKeyValueDetail {
                    file_offset_absolute,
                    size: size_abs,
                    value_name_size,
                    data_size_raw,
                    data_offset_relative,
                    data_type_raw,
                    flags_raw,
                    padding,
                    value_bytes: None,
                    slack: slack.to_vec()
                },
                data_type,
                flags,
                value_name,
                data_offsets_absolute: Vec::new(),
                logs,
                versions: Vec::new(),
                hash: None,
                sequence_num,
                updated_by_sequence_num: None
            },
        ))
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
            if CellKeyValue::BIG_DATA_SIZE_THRESHOLD < data_size_raw && CellBigData::is_big_data_block(&file_info.buffer[offset..]) {
                let (vb, offsets) =
                    CellBigData::get_big_data_bytes(file_info, offset, data_type, data_size_raw)
                        .or_else(
                            |err| -> Result<(Vec<u8>, Vec<usize>), Error> {
                                logs.add(LogCode::WarningBigDataContent, &err);
                                Ok((Vec::new(), Vec::new()))
                            }
                        )
                        .expect("Error handled in or_else");
                value_bytes = vb;
                data_offsets_absolute.extend(offsets);
            }
            else {
                offset += mem::size_of::<i32>(); // skip over the size bytes
                data_offsets_absolute.push(offset);
                value_bytes = data_type.get_value_bytes(&file_info.buffer[offset .. offset + data_size_raw as usize]);
            }
        }
        else {
            const DATA_OFFSET_RELATIVE_OFFSET: usize = 12;
            data_offsets_absolute.push(file_offset_absolute + DATA_OFFSET_RELATIVE_OFFSET);
            let resident_value = data_offset_relative.to_le_bytes();
            value_bytes = data_type.get_value_bytes(&resident_value[..(data_size_raw ^ DATA_IS_RESIDENT_MASK) as usize]);
        }
        (value_bytes, data_offsets_absolute)
    }

    /// Reads the value content and stores it in self.detail.value_bytes
    pub(crate) fn read_value_bytes(
        &mut self,
        file_info: &FileInfo,
        state: &mut State
    ) {
        let (value_bytes, data_offsets_absolute) =
            Self::read_value_bytes_direct(
                self.detail.file_offset_absolute,
                self.detail.data_size_raw,
                self.detail.data_offset_relative,
                &self.data_type,
                file_info,
                &mut self.logs
            );

        self.data_offsets_absolute.extend(data_offsets_absolute);
        self.hash = Some(CellKeyValue::hash(state, self.detail.data_type_raw, self.detail.flags_raw, &value_bytes));
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
            .expect("Error handled in or_else");

        match warnings.get() {
            Some(_) => (cell_value, Some(warnings)),
            _ => (cell_value, None)
        }
    }

    pub fn decode_content(&self, format: DecodeFormat, offset: usize) -> (CellValue, Option<Logs>) {
        if let Some(value_bytes) = &self.detail.value_bytes {
            let mut warnings = Logs::default();
            match format {
                DecodeFormat::Lznt1 => {
                    match util::decode_lznt1(value_bytes, offset, value_bytes.len()) {
                        Ok(decompressed) => return (CellValue::ValueBinary(decompressed), None),
                        _ => {
                            warnings.add(LogCode::WarningConversion, &"Error decompressing lznt1");
                            return (CellValue::ValueError, Some(warnings))
                        }
                    }
                },
                DecodeFormat::Utf16 => {
                    let s = util::from_utf16_le_string(value_bytes, value_bytes.len(), &mut warnings, &"decode_content");
                    return (CellValue::ValueString(s), warnings.get_option());
                }
                DecodeFormat::Utf16Multiple => {
                    let m = util::from_utf16_le_strings(value_bytes, value_bytes.len(), &mut warnings, &"decode_content");
                    return (CellValue::ValueMultiString(m), warnings.get_option());
                },
                DecodeFormat::Rot13 => {
                    let (content, _) = self.get_content();
                    match content {
                        CellValue::ValueString(s) => return (CellValue::ValueString(util::decode_rot13(&s)), None),
                        CellValue::ValueMultiString(m) => {
                            let mut decoded = vec![];
                            for s in m {
                                decoded.push(util::decode_rot13(&s));
                            }
                            return (CellValue::ValueMultiString(decoded), None);
                        },
                        _ => {
                            let mut warnings = Logs::default();
                            warnings.add(LogCode::WarningConversion, &"Unsupported CellValue type");
                            return (CellValue::ValueError, Some(warnings))
                        }
                    }
                },
            }
        }
        (CellValue::ValueNone, None)
    }

    fn hash(state: &mut State, data_type_raw: u32, flags_raw: u16, value_bytes: &[u8]) -> Hash {
        state.hasher.reset();
        state.hasher.update(&data_type_raw.to_le_bytes());
        state.hasher.update(&flags_raw.to_le_bytes());
        state.hasher.update(&value_bytes);
        state.hasher.finalize()
    }

    pub fn get_pretty_name(&self) -> String {
        if self.value_name.is_empty() {
            "(default)".to_string()
        }
        else {
            self.value_name.clone()
        }
    }
}

/// Wrapper class to dynamically convert value_bytes into a parsed CellValue when serde serialize is called
#[derive(Debug, Serialize)]
struct CellKeyValueForSerialization<'a> {
    detail: &'a CellKeyValueDetail,
    data_type: &'a CellKeyValueDataTypes,
    flags: &'a CellKeyValueFlags,
    value_name: String,
    cell_parse_warnings: &'a Logs,
    sequence_num: &'a Option<u32>,
    updated_by_sequence_num: &'a Option<u32>,
    data_offsets_absolute: &'a Vec<usize>,

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
            value_name: other.get_pretty_name(),
            cell_parse_warnings: &other.logs,
            data_offsets_absolute: &other.data_offsets_absolute,
            sequence_num: &other.sequence_num,
            updated_by_sequence_num: &other.updated_by_sequence_num,
            value,
            value_parse_warnings
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_key_node::{CellKeyNode, CellKeyNodeReadOptions};

    #[test]
    fn test_parse_cell_key_value() {
        let slice = [
            0xD0, 0xFF, 0xFF, 0xFF, 0x76, 0x6B, 0x12, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x18, 0x0F, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x49, 0x45, 0x35, 0x5F, 0x55, 0x41, 0x5F, 0x42, 0x61, 0x63, 0x6B, 0x75,
            0x70, 0x5F, 0x46, 0x6C, 0x61, 0x67, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
        ];
        let file_info = FileInfo {
            hbin_offset_absolute: 4096,
            buffer: slice.to_vec()
        };
        let mut state = State::default();
        let (_, mut key_value) = CellKeyValue::from_bytes(&file_info, &file_info.buffer[..], None).unwrap();

        let expected_output = CellKeyValue {
            detail: CellKeyValueDetail {
                file_offset_absolute: 0,
                size: 48,
                value_name_size: 18,
                data_size_raw: 8,
                data_offset_relative: 3864,
                data_type_raw: 1,
                flags_raw: 1,
                padding: 0,
                value_bytes: None,
                slack: vec![0, 0, 1, 0, 0, 0]
            },
            data_type: CellKeyValueDataTypes::REG_SZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            value_name: "IE5_UA_Backup_Flag".to_string(),
            data_offsets_absolute: Vec::new(),
            logs: Logs::default(),
            versions: Vec::new(),
            hash: None,
            sequence_num: None,
            updated_by_sequence_num: None
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
    fn test_decode_content() {
        let lznt1 = [0x60, 0x05, 0x00, 0x00, 0xD3, 0x0C, 0x00, 0x00, 0x55, 0xB5, 0x00, 0x0A, 0x00, 0x0C, 0x00, 0xD3, 0x0C, 0x00, 0x00, 0x00, 0x76, 0x12, 0x6F, 0x68, 0x11, 0x1F, 0xD7, 0x01, 0x00, 0xF7, 0x6D, 0x1F, 0x02, 0x10, 0x00, 0x00, 0x00, 0xAA, 0x0A, 0x00, 0x18, 0x70, 0x00, 0x18, 0x18, 0x00, 0x0C, 0x58, 0x04, 0x1C, 0x00, 0x10, 0x01, 0x00, 0x00, 0x72, 0xB8, 0x4F, 0x46, 0x00, 0x60, 0x1A, 0xD7, 0x01, 0x00, 0x40, 0x5D, 0x24, 0x00, 0x2E, 0x19, 0xD7, 0x01, 0x80, 0x3A, 0x09, 0x00, 0xA0, 0x10, 0x0E, 0x00, 0x00, 0x15, 0x00, 0x46, 0x00, 0x00, 0x3E, 0x83, 0x01, 0x56, 0x01, 0x14, 0x30, 0x03, 0x00, 0x00, 0x30, 0x00, 0x10, 0x06, 0xB8, 0x00, 0x0E, 0x01, 0x26, 0x20, 0x06, 0x00, 0x00, 0x1C, 0xC1, 0x00, 0x1E, 0x18, 0x02, 0x00, 0x00, 0x28, 0x00, 0x4E, 0x02, 0x16, 0x55, 0x00, 0x1E, 0x34, 0x00, 0x0F, 0x40, 0x08, 0x0F, 0x50, 0x00, 0x0F, 0x58, 0x55, 0x08, 0x0F, 0x6C, 0x00, 0x0F, 0x70, 0x08, 0x0F, 0x88, 0x00, 0x0F, 0x88, 0x55, 0x08, 0x0F, 0xA4, 0x00, 0x0F, 0xA0, 0x08, 0x0F, 0xC0, 0x00, 0x0F, 0xB8, 0x55, 0x08, 0x0F, 0xDC, 0x00, 0x0F, 0xD0, 0x08, 0x0F, 0xF8, 0x00, 0x0F, 0xE8, 0xB5, 0x08, 0x0F, 0x14, 0x80, 0x4F, 0x00, 0x80, 0x09, 0x85, 0x47, 0x60, 0x80, 0x07, 0xD2, 0x08, 0x80, 0x4B, 0x10, 0x04, 0x83, 0x5F, 0x3C, 0x80, 0x5B, 0x81, 0x81, 0xAA, 0x68, 0x84, 0x0B, 0x40, 0x84, 0x0B, 0x54, 0x84, 0x0B, 0x70, 0x84, 0x0B, 0xAA, 0x70, 0x84, 0x0B, 0x6C, 0x84, 0x0B, 0x78, 0x84, 0x0B, 0xA0, 0x84, 0x0B, 0xAA, 0x84, 0x84, 0x0B, 0x80, 0x84, 0x0B, 0xD0, 0x84, 0x0B, 0x9C, 0x84, 0x0B, 0x52, 0x88, 0x84, 0x0B, 0x00, 0x05, 0x83, 0x3B, 0xB4, 0x84, 0x0B, 0x90, 0x55, 0x84, 0x0B, 0x30, 0x84, 0x0B, 0xCC, 0x84, 0x0B, 0x98, 0x84, 0x0B, 0x60, 0x55, 0x84, 0x0B, 0xE4, 0x84, 0x0B, 0xA0, 0x84, 0x0B, 0x90, 0x84, 0x0B, 0xFC, 0x15, 0x84, 0x0B, 0xA8, 0x84, 0x0B, 0xC0, 0x84, 0x0B, 0x14, 0x07, 0x00, 0xAA, 0x00, 0x81, 0x6B, 0xB0, 0xC4, 0x05, 0xF0, 0xC4, 0x05, 0x2C, 0xC4, 0x05, 0x1A, 0x44, 0xC0, 0x01, 0x32, 0xC0, 0x41, 0x85, 0x00, 0x15, 0xC1, 0x5B, 0xA8, 0x4A, 0xB8, 0x72, 0x43, 0x03, 0xAA, 0xC0, 0x06, 0x34, 0x05, 0x06, 0xC1, 0xC0, 0x01, 0x70, 0x9F, 0xE7, 0x4C, 0xF6, 0x01, 0x75, 0xC0, 0x02, 0x1A, 0x14, 0x00, 0x4F, 0x2C, 0xC0, 0x01, 0x85, 0x00, 0x44, 0xA1, 0xE7, 0x68, 0x4C, 0xDE, 0x23, 0x43, 0x04, 0x6E, 0xC0, 0x06, 0xC9, 0x0D, 0x4E, 0x60, 0x54, 0xEF, 0x5D, 0xA1, 0xC6, 0x00, 0x5F, 0x00, 0x0B, 0xD8, 0x0D, 0xC0, 0x06, 0x35, 0x05, 0x0D, 0xC0, 0x01, 0xF3, 0xE9, 0xAE, 0x50, 0x0C, 0x99, 0x85, 0x00, 0x6A, 0xC0, 0x02, 0x44, 0x09, 0x00, 0x00, 0x01, 0xC9, 0x14, 0xFE, 0x4E, 0xC4, 0x57, 0x00, 0x49, 0x31, 0x31, 0x40, 0x06, 0x00, 0x00, 0x9E, 0xC0, 0x06, 0xC9, 0x14, 0xBE, 0xA8, 0xB0, 0x9E, 0x55, 0xA2, 0x6D, 0x00, 0x35, 0x40, 0x07, 0x08, 0x00, 0xB1, 0x06, 0x48, 0x42, 0x09, 0x03, 0x01, 0x7C, 0xE3, 0x84, 0x5B, 0x53, 0x34, 0x6B, 0x46, 0x02, 0x03, 0x9A, 0xC0, 0x06, 0xC9, 0x0D, 0xBF, 0xE0, 0x10, 0xC1, 0x5D, 0x0D, 0x35, 0xC3, 0x22, 0x04, 0x0B, 0x00, 0x02, 0x00, 0xC9, 0x06, 0x96, 0xAE, 0x0E, 0x5E, 0xA3, 0x51, 0x5B, 0x00, 0x48, 0x40, 0x0E, 0x6E, 0xC0, 0x06, 0xC1, 0xBA, 0x83, 0xC4, 0x01, 0x98, 0x55, 0xC4, 0x01, 0xAD, 0xC4, 0x01, 0xC2, 0xC4, 0x01, 0xD7, 0xC4, 0x01, 0xEC, 0xAD, 0xC4, 0x01, 0x01, 0xC0, 0xD8, 0xC1, 0x0D, 0x16, 0xC4, 0x01, 0x2B, 0xC4, 0x01, 0xAA, 0x40, 0xC4, 0x01, 0x55, 0xC4, 0x01, 0x6A, 0xC4, 0x01, 0x7F, 0xC4, 0x01, 0x6A, 0x94, 0xC4, 0x01, 0xA9, 0xC4, 0x01, 0xBE, 0xC4, 0x01, 0x80, 0x60, 0x00, 0x20, 0x24, 0x13, 0xA7, 0x1E, 0x0D, 0xC0, 0x24, 0xE3, 0x5D, 0x0C, 0x27, 0x00, 0xC5, 0x01, 0x80, 0x35, 0x00, 0xF6, 0x54, 0x7B, 0xAF, 0x81, 0x07, 0x40, 0x06, 0x97, 0x00, 0x01, 0x08, 0x18, 0xC0, 0x0F, 0x4F, 0x40, 0x04, 0x10, 0x06, 0x84, 0xBB, 0x00, 0x61, 0x7E, 0xF8, 0x50, 0xA2, 0xD7, 0x17, 0x06, 0x3C, 0x03, 0x61, 0x1B, 0xB0, 0xC3, 0x27, 0x00, 0xED, 0x00, 0x49, 0x07, 0x21, 0xE1, 0x0E, 0x98, 0xEA, 0x71, 0x01, 0x40, 0x86, 0x00, 0x43, 0x84, 0x37, 0x19, 0x41, 0x6F, 0x00, 0xE1, 0xC1, 0x05, 0xE6, 0x00, 0x1B, 0x65, 0x05, 0xE1, 0x04, 0xC5, 0x80, 0x04, 0x41, 0x0A, 0x86, 0x2E, 0xE2, 0x21, 0xC1, 0x62, 0x00, 0xD1, 0x84, 0x1A, 0x41, 0x8C, 0x00, 0xD2, 0x1C, 0x5C, 0x04, 0xE6, 0x00, 0xE5, 0x05, 0xE1, 0x04, 0x80, 0x94, 0x1A, 0x91, 0xE2, 0x08, 0xD5, 0xB6, 0xE1, 0xE2, 0x00, 0x90, 0x0F, 0xA3, 0x03, 0x87, 0xED, 0x00, 0xA1, 0x02, 0xE1, 0x05, 0x26, 0x11, 0x00, 0x00, 0xC0, 0x63, 0xA0, 0x00, 0xB1, 0x2A, 0xA0, 0x01, 0xE1, 0x00, 0x4E, 0x60, 0x50, 0x1F, 0x61, 0x03, 0xED, 0x00, 0x61, 0x02, 0xE5, 0x03, 0xC0, 0x76, 0x00, 0x8D, 0xAB, 0x88, 0x5E, 0x02, 0x12, 0x80, 0x02, 0xA1, 0x61, 0x67, 0xE2, 0xA4, 0x78, 0x04, 0x9D, 0x15, 0xE6, 0x00, 0x61, 0x05, 0x61, 0x00, 0xE1, 0x04, 0x31, 0x44, 0x0D, 0x3B, 0xE2, 0x10, 0xF7, 0x44, 0x00, 0xE2, 0x00, 0x91, 0x7E, 0x43, 0xA3, 0x03, 0xED, 0x00, 0xA1, 0x02, 0xE1, 0x11, 0xE1, 0x02, 0x21, 0x5E, 0x89, 0xFB, 0x00, 0x6F, 0xE1, 0x00, 0x78, 0x81, 0x0E, 0x80, 0x03, 0xED, 0x00, 0xE1, 0x05, 0xE1, 0x03, 0x68, 0x9B, 0x2F, 0x00, 0xE2, 0x20, 0x6E, 0x40, 0x53, 0xE1, 0x01, 0x27, 0xEF, 0x81, 0x0E, 0x80, 0x03, 0xED, 0x00, 0xE5, 0x05, 0x6D, 0x01, 0x01, 0x64, 0x00, 0xC0, 0x66, 0x90, 0x00, 0x93, 0xFD, 0x1F, 0xA2, 0x01, 0x6E, 0x39, 0xA1, 0x2D, 0x5C, 0x00, 0x00, 0xE5, 0x00, 0x44, 0x04, 0xC2, 0x00, 0x07, 0xA0, 0x84, 0x23, 0xEC, 0x00, 0x23, 0x44, 0x02, 0x00, 0x26, 0x00, 0x63, 0x05, 0x04, 0x02, 0xD6, 0x00, 0x8F, 0xE1, 0x11, 0x83, 0x03, 0x27, 0x01, 0xE1, 0x01, 0x24, 0x00, 0x19, 0xC3, 0x02, 0xD8, 0x00, 0x13, 0x00, 0xC4, 0x2D, 0xE2, 0x01, 0x50, 0x22, 0x58, 0x41, 0x01, 0xF2, 0x46, 0xE2, 0xC4, 0x00, 0x00, 0x63, 0x78, 0x23, 0x43, 0xE1, 0x02, 0x27, 0x01, 0x7D, 0xA1, 0x01, 0x03, 0x22, 0x1F, 0x21, 0x01, 0x21, 0x27, 0xE1, 0x00, 0x63, 0x00, 0x09, 0x04, 0x01, 0x27, 0x84, 0x01, 0xF6, 0x00, 0x82, 0x00, 0x25, 0xB3, 0x60, 0x01, 0x83, 0x28, 0x0F, 0x00, 0x21, 0x1E, 0x41, 0x03, 0x0A, 0x24, 0x0B, 0xDF, 0x61, 0x01, 0xE3, 0x32, 0x25, 0x01, 0x29, 0x15, 0x67, 0x01, 0x01, 0x26, 0x0D, 0xE1, 0x04, 0x08, 0x90, 0x00, 0x29, 0xC3, 0x05, 0x00, 0x7F, 0x00, 0x11, 0x01, 0x24, 0x09, 0x5C, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x10, 0x00, 0x49, 0x00, 0x43, 0xE0, 0x00, 0x5C, 0x00, 0x48, 0x50, 0x00, 0x41, 0x00, 0x52, 0x60, 0x02, 0x44, 0x20, 0x02, 0x53, 0x04, 0x00, 0x4B, 0x20, 0x03, 0x4F, 0x00, 0x4C, 0x00, 0x55, 0x84, 0x00, 0x4D, 0xA0, 0x03, 0x32, 0x00, 0x5C, 0x00, 0x80, 0x97, 0x54, 0x00, 0x4E, 0xE0, 0x03, 0x4F, 0x20, 0x01, 0x53, 0xE0, 0x01, 0x53, 0x40, 0x00, 0x59, 0x00, 0x53, 0x00, 0x54, 0xA0, 0x03, 0x4D, 0xA8, 0x00, 0x33, 0x00, 0x21, 0x04, 0x43, 0xE0, 0x01, 0x52, 0x60, 0x00, 0xA8, 0x53, 0x00, 0x2E, 0xA0, 0x02, 0x58, 0x60, 0x00, 0x00, 0xE0, 0x04, 0x07, 0xBF, 0x0C, 0xBF, 0x0C, 0xA9, 0x0C, 0x4C, 0x00, 0x4F, 0x00, 0x47, 0xF5, 0x30, 0x00, 0x4E, 0xB0, 0x09, 0x49, 0x9F, 0x06, 0xFF, 0x0C, 0xFF, 0x0C, 0xD2, 0x0A, 0x41, 0xFD, 0x0C, 0x45, 0x00, 0x58, 0x00, 0x50, 0x10, 0x0F, 0x4F, 0xDD, 0x50, 0x10, 0x45, 0x30, 0x00, 0x3F, 0x0C, 0x9F, 0x12, 0x49, 0xD0, 0x0E, 0x9F, 0x12, 0xAB, 0x9F, 0x12, 0x9D, 0x12, 0x57, 0xB0, 0x0B, 0x41, 0x30, 0x00, 0x43, 0xF0, 0x06, 0x7E, 0x54, 0x3F, 0x0C, 0x3F, 0x0C, 0x3F, 0x0C, 0x3F, 0x0C, 0x3F, 0x19, 0x10, 0x01, 0x54, 0xFB, 0x50, 0x1D, 0xD1, 0x1C, 0x48, 0x10, 0x13, 0xD1, 0x1A, 0x5F, 0x0D, 0x5F, 0x0D, 0x5F, 0x0D, 0xED, 0xFF, 0x1F, 0x5C, 0x12, 0x1E, 0xFF, 0x12, 0x45, 0x70, 0x26, 0x9F, 0x25, 0x9F, 0x25, 0xD5, 0x3F, 0x1F, 0x44, 0x10, 0x0A, 0x57, 0xF0, 0x14, 0x5C, 0x30, 0x00, 0xFD, 0x12, 0xD6, 0x4E, 0xB0, 0x01, 0x31, 0x20, 0x50, 0xD0, 0x0C, 0x44, 0xFF, 0x12, 0xFF, 0x12, 0x5B, 0xFF, 0x12, 0xF2, 0x12, 0x50, 0x70, 0x1D, 0xD1, 0x23, 0x52, 0x70, 0x04, 0x4D, 0xD0, 0x00, 0x20, 0x00, 0x46, 0x70, 0x02, 0x4C, 0x90, 0x0C, 0xF1, 0x2C, 0xD5, 0x5B, 0x1B, 0x20, 0xB0, 0x2E, 0x54, 0xF0, 0x13, 0x41, 0xD0, 0x31, 0xF1, 0x31, 0xB6, 0x53, 0x50, 0x09, 0x91, 0x21, 0x49, 0xD6, 0x02, 0xD1, 0x00, 0x44, 0x10, 0x23, 0x7E, 0x41, 0x30, 0x31, 0x5F, 0x15, 0x5F, 0x15, 0x5F, 0x15, 0x5F, 0x15, 0xBF, 0x0F, 0x5C, 0xD5, 0xF0, 0x07, 0x4F, 0xB0, 0x08, 0x53, 0x70, 0x07, 0x4E, 0xD0, 0x36, 0x9F, 0x06, 0x7F, 0x9F, 0x06, 0x9F, 0x06, 0x9F, 0x06, 0x9F, 0x06, 0x95, 0x06, 0x9F, 0x22, 0xA1, 0x43, 0x70, 0xC0, 0x03, 0x08, 0x1E, 0x00, 0x00, 0x3C, 0xA1, 0x00, 0x3F, 0x00, 0x77, 0x1A, 0x01, 0xB0, 0xA5, 0x90, 0x02, 0x24, 0x5F, 0x02, 0x1F, 0x01, 0x1F, 0x01, 0x00, 0x1E, 0x00, 0x83, 0x06, 0x89, 0x8C, 0x5F, 0x02, 0x13, 0x01, 0x70, 0x01, 0x08, 0x6F, 0xA4, 0x66, 0x18, 0x02, 0x4F, 0x01, 0xC0, 0x01, 0x60, 0x39, 0x52, 0xC5, 0x02, 0x20, 0xF9, 0x4F, 0x01, 0x00, 0x00, 0x40, 0x01, 0x3F, 0x05, 0x60, 0x70, 0x30, 0x7D, 0x2F, 0x09, 0xFF, 0x9F, 0x02, 0xB0, 0x05, 0x8B, 0x5D, 0xC4, 0x06, 0x24, 0x6E, 0xD4, 0x00, 0x64, 0x00, 0xC0, 0xBB, 0x01, 0x78, 0x01];
        let mut cell_key_value = CellKeyValue {
            detail: CellKeyValueDetail {
                file_offset_absolute: 0,
                size: 48,
                value_name_size: 4,
                data_size_raw: lznt1.len() as u32,
                data_offset_relative: 3864,
                data_type_raw: 1,
                flags_raw: 1,
                padding: 0,
                value_bytes: Some(lznt1.to_vec()),
                slack: vec![]
            },
            data_type: CellKeyValueDataTypes::REG_BIN,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            value_name: "test".to_string(),
            data_offsets_absolute: Vec::new(),
            logs: Logs::default(),
            versions: Vec::new(),
            hash: None,
            sequence_num: None,
            updated_by_sequence_num: None
        };
        let (decoded_value, _) = cell_key_value.decode_content(DecodeFormat::Lznt1, 8);
        let expected_output = CellValue::ValueBinary([10, 0, 12, 0, 211, 12, 0, 0, 118, 18, 111, 104, 17, 31, 215, 1, 247, 109, 31, 2, 16, 0, 0, 0, 10, 0, 0, 0, 112, 0, 0, 0, 24, 0, 0, 0, 88, 0, 0, 0, 24, 0, 0, 0, 16, 1, 0, 0, 114, 184, 79, 70, 96, 26, 215, 1, 0, 64, 93, 36, 46, 25, 215, 1, 128, 58, 9, 0, 16, 14, 0, 0, 21, 0, 0, 0, 0, 1, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 48, 3, 0, 0, 48, 0, 0, 0, 184, 3, 0, 0, 88, 0, 0, 0, 32, 6, 0, 0, 28, 0, 0, 0, 24, 2, 0, 0, 40, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 52, 2, 0, 0, 64, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 80, 2, 0, 0, 88, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 108, 2, 0, 0, 112, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 136, 2, 0, 0, 136, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 164, 2, 0, 0, 160, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 192, 2, 0, 0, 184, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 220, 2, 0, 0, 208, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 248, 2, 0, 0, 232, 1, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 20, 3, 0, 0, 0, 2, 0, 0, 28, 0, 0, 0, 24, 0, 0, 0, 96, 3, 0, 0, 8, 0, 0, 0, 16, 4, 0, 0, 48, 0, 0, 0, 60, 6, 0, 0, 24, 0, 0, 0, 104, 3, 0, 0, 8, 0, 0, 0, 64, 4, 0, 0, 48, 0, 0, 0, 84, 6, 0, 0, 24, 0, 0, 0, 112, 3, 0, 0, 8, 0, 0, 0, 112, 4, 0, 0, 48, 0, 0, 0, 108, 6, 0, 0, 24, 0, 0, 0, 120, 3, 0, 0, 8, 0, 0, 0, 160, 4, 0, 0, 48, 0, 0, 0, 132, 6, 0, 0, 24, 0, 0, 0, 128, 3, 0, 0, 8, 0, 0, 0, 208, 4, 0, 0, 48, 0, 0, 0, 156, 6, 0, 0, 24, 0, 0, 0, 136, 3, 0, 0, 8, 0, 0, 0, 0, 5, 0, 0, 48, 0, 0, 0, 180, 6, 0, 0, 24, 0, 0, 0, 144, 3, 0, 0, 8, 0, 0, 0, 48, 5, 0, 0, 48, 0, 0, 0, 204, 6, 0, 0, 24, 0, 0, 0, 152, 3, 0, 0, 8, 0, 0, 0, 96, 5, 0, 0, 48, 0, 0, 0, 228, 6, 0, 0, 24, 0, 0, 0, 160, 3, 0, 0, 8, 0, 0, 0, 144, 5, 0, 0, 48, 0, 0, 0, 252, 6, 0, 0, 24, 0, 0, 0, 168, 3, 0, 0, 8, 0, 0, 0, 192, 5, 0, 0, 48, 0, 0, 0, 20, 7, 0, 0, 24, 0, 0, 0, 176, 3, 0, 0, 8, 0, 0, 0, 240, 5, 0, 0, 48, 0, 0, 0, 44, 7, 0, 0, 24, 0, 0, 0, 68, 7, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 193, 91, 74, 184, 114, 0, 0, 0, 0, 0, 0, 170, 7, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 159, 231, 76, 246, 40, 1, 0, 0, 0, 0, 0, 20, 8, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 161, 231, 76, 222, 35, 44, 0, 0, 0, 0, 0, 110, 8, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 84, 239, 93, 161, 198, 2, 0, 0, 0, 0, 0, 216, 8, 0, 0, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 233, 174, 80, 153, 133, 1, 0, 0, 0, 0, 0, 68, 9, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 78, 196, 87, 0, 73, 49, 0, 0, 0, 0, 0, 158, 9, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 190, 168, 158, 85, 162, 109, 3, 0, 0, 0, 0, 0, 8, 10, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 124, 227, 132, 91, 83, 107, 70, 0, 0, 0, 0, 0, 154, 10, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 191, 224, 193, 93, 13, 53, 2, 0, 0, 0, 0, 0, 4, 11, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 150, 174, 14, 94, 163, 81, 5, 0, 0, 0, 0, 0, 110, 11, 0, 0, 21, 0, 0, 0, 131, 11, 0, 0, 21, 0, 0, 0, 152, 11, 0, 0, 21, 0, 0, 0, 173, 11, 0, 0, 21, 0, 0, 0, 194, 11, 0, 0, 21, 0, 0, 0, 215, 11, 0, 0, 21, 0, 0, 0, 236, 11, 0, 0, 21, 0, 0, 0, 1, 12, 0, 0, 21, 0, 0, 0, 22, 12, 0, 0, 21, 0, 0, 0, 43, 12, 0, 0, 21, 0, 0, 0, 64, 12, 0, 0, 21, 0, 0, 0, 85, 12, 0, 0, 21, 0, 0, 0, 106, 12, 0, 0, 21, 0, 0, 0, 127, 12, 0, 0, 21, 0, 0, 0, 148, 12, 0, 0, 21, 0, 0, 0, 169, 12, 0, 0, 21, 0, 0, 0, 190, 12, 0, 0, 21, 0, 0, 0, 7, 0, 0, 0, 36, 19, 167, 30, 13, 0, 0, 0, 227, 93, 39, 0, 13, 0, 0, 0, 227, 93, 39, 0, 10, 0, 0, 0, 246, 84, 123, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 24, 19, 167, 30, 79, 0, 0, 0, 6, 132, 187, 0, 16, 0, 0, 0, 248, 80, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 176, 2, 0, 0, 0, 0, 0, 0, 176, 2, 0, 0, 0, 0, 0, 0, 176, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 152, 234, 113, 1, 14, 0, 0, 0, 67, 55, 25, 0, 2, 0, 0, 0, 225, 193, 5, 0, 2, 0, 0, 0, 225, 193, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 197, 14, 0, 0, 2, 0, 0, 0, 134, 46, 226, 0, 5, 0, 0, 0, 209, 132, 26, 0, 1, 0, 0, 0, 210, 92, 4, 0, 1, 0, 0, 0, 210, 92, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 128, 148, 26, 0, 2, 0, 0, 0, 213, 182, 225, 0, 2, 0, 0, 0, 144, 15, 0, 0, 0, 0, 0, 0, 144, 15, 0, 0, 0, 0, 0, 0, 144, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 38, 17, 0, 0, 6, 0, 0, 0, 177, 42, 160, 1, 6, 0, 0, 0, 78, 8, 0, 0, 0, 0,
        0, 0, 78, 8, 0, 0, 0, 0, 0, 0, 78, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 78, 8, 0, 0, 4, 0, 0, 0, 141, 171, 94, 2, 18, 0, 0, 0, 161, 97, 103, 0, 10, 0, 0, 0, 4, 157, 21, 0, 10, 0, 0, 0, 4, 157, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 49, 13, 59, 0, 2, 0, 0, 0, 247, 68, 0, 0, 2, 0, 0, 0, 145, 67, 0, 0, 0, 0, 0, 0, 145, 67, 0, 0, 0, 0, 0, 0, 145, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 145, 67, 0, 0, 1, 0, 0, 0, 137, 50, 0, 0, 1, 0, 0, 0, 120, 6, 0, 0, 0, 0, 0, 0, 120, 6, 0, 0, 0, 0, 0, 0, 120, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 155, 47, 0, 0, 1, 0, 0, 0, 110, 5, 0, 0, 1, 0, 0, 0, 39, 4, 0, 0, 0, 0, 0, 0, 39, 4, 0, 0, 0, 0, 0, 0, 39, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 147, 253, 31, 0, 0, 0, 0, 0, 110, 57, 7, 0, 0, 0, 0, 0, 110, 57, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 24, 0, 35, 0, 35, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 25, 0, 0, 0, 0, 0, 0, 0, 19, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 0, 13, 0, 0, 0, 0, 0, 0, 0, 70, 0, 28, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 5, 0, 2, 0, 0, 0, 0, 0, 0, 0, 5, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 1, 39, 0, 0, 0, 0, 0, 0, 0, 246, 0, 130, 0, 37, 0, 0, 0, 6, 0, 0, 0, 0, 0, 15, 0, 9, 0, 0, 0, 0, 0, 0, 0, 10, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 0, 41, 0, 0, 0, 0, 0, 0, 0, 127, 0, 17, 0, 3, 0, 0, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 83, 0, 89, 0, 83, 0, 84, 0, 69, 0, 77, 0, 51, 0, 50, 0, 92, 0, 67, 0, 83, 0, 82, 0, 83, 0, 83, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 83, 0, 89, 0, 83, 0, 84, 0, 69, 0, 77, 0, 51, 0, 50, 0, 92, 0, 76, 0, 79, 0, 71, 0, 79, 0, 78, 0, 85, 0, 73, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 69, 0, 88, 0, 80, 0, 76, 0, 79, 0, 82, 0, 69, 0, 82, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 83, 0, 89, 0, 83, 0, 84, 0, 69, 0, 77, 0, 51, 0, 50, 0, 92, 0, 87, 0, 85, 0, 65, 0, 85, 0, 67, 0, 76, 0, 84, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 83, 0, 89, 0, 83, 0, 84, 0, 69, 0, 77, 0, 51, 0, 50, 0, 92, 0, 84, 0, 65, 0, 83, 0, 75, 0, 72, 0, 79, 0, 83, 0, 84, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 69, 0, 88, 0, 80, 0, 76, 0, 79, 0, 82, 0, 69, 0, 82, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 83, 0, 89, 0, 83, 0, 84, 0, 69, 0, 77, 0, 51, 0, 50, 0, 92, 0, 78, 0, 79, 0, 84, 0, 69, 0, 80, 0, 65, 0, 68, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0,
        69, 0, 50, 0, 92, 0, 80, 0, 82, 0, 79, 0, 71, 0, 82, 0, 65, 0, 77, 0, 32, 0, 70, 0, 73, 0, 76, 0, 69, 0, 83, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 32, 0, 78, 0, 84, 0, 92, 0, 65, 0, 67, 0, 67, 0, 69, 0, 83, 0, 83, 0, 79, 0, 82, 0, 73, 0, 69, 0, 83, 0, 92, 0, 87, 0, 79, 0, 82, 0, 68, 0, 80, 0, 65, 0, 68, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 83, 0, 89, 0, 83, 0, 84, 0, 69, 0, 77, 0, 51, 0, 50, 0, 92, 0, 67, 0, 79, 0, 78, 0, 83, 0, 69, 0, 78, 0, 84, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 92, 0, 68, 0, 69, 0, 86, 0, 73, 0, 67, 0, 69, 0, 92, 0, 72, 0, 65, 0, 82, 0, 68, 0, 68, 0, 73, 0, 83, 0, 75, 0, 86, 0, 79, 0, 76, 0, 85, 0, 77, 0, 69, 0, 50, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0, 92, 0, 83, 0, 89, 0, 83, 0, 84, 0, 69, 0, 77, 0, 51, 0, 50, 0, 92, 0, 67, 0, 79, 0, 78, 0, 72, 0, 79, 0, 83, 0, 84, 0, 46, 0, 69, 0, 88, 0, 69, 0, 0, 0, 0, 0, 0, 0, 112, 3, 8, 30, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 3, 0, 30, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 3, 8, 30, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 1, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 1, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 14, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec());
        assert_eq!(expected_output, decoded_value);

        let utf16_multiple = [0x4E, 0x00, 0x41, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x72, 0x00, 0x65, 0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00, 0x5F, 0x00, 0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x7A, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x63, 0x00, 0x6B, 0x00, 0x48, 0x00, 0x61, 0x00, 0x72, 0x00, 0x72, 0x00, 0x69, 0x00, 0x65, 0x00, 0x72, 0x00, 0x5F, 0x00, 0x44, 0x00, 0x37, 0x00, 0x5F, 0x00, 0x69, 0x00, 0x36, 0x00, 0x38, 0x00, 0x36, 0x00, 0x5F, 0x00, 0x46, 0x00, 0x44, 0x00, 0x45, 0x00, 0x5F, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x34, 0x00, 0x31, 0x00, 0x32, 0x00, 0x31, 0x00, 0x39, 0x00, 0x2E, 0x00, 0x64, 0x00, 0x64, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x7A, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x63, 0x00, 0x6B, 0x00, 0x48, 0x00, 0x61, 0x00, 0x72, 0x00, 0x72, 0x00, 0x69, 0x00, 0x65, 0x00, 0x72, 0x00, 0x5F, 0x00, 0x44, 0x00, 0x37, 0x00, 0x5F, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x36, 0x00, 0x34, 0x00, 0x5F, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x34, 0x00, 0x31, 0x00, 0x32, 0x00, 0x31, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x7A, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x63, 0x00, 0x6B, 0x00, 0x48, 0x00, 0x61, 0x00, 0x72, 0x00, 0x72, 0x00, 0x69, 0x00, 0x65, 0x00, 0x72, 0x00, 0x5F, 0x00, 0x44, 0x00, 0x37, 0x00, 0x5F, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x36, 0x00, 0x34, 0x00, 0x5F, 0x00, 0x46, 0x00, 0x44, 0x00, 0x45, 0x00, 0x5F, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x34, 0x00, 0x31, 0x00, 0x32, 0x00, 0x31, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x7A, 0x00, 0x00, 0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x6A, 0x00, 0x6D, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x62, 0x00, 0x65, 0x00, 0x72, 0x00, 0x74, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x44, 0x00, 0x65, 0x00, 0x73, 0x00, 0x6B, 0x00, 0x74, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x5C, 0x00, 0x55, 0x00, 0x53, 0x00, 0x42, 0x00, 0x5F, 0x00, 0x52, 0x00, 0x65, 0x00, 0x73, 0x00, 0x65, 0x00, 0x61, 0x00, 0x72, 0x00, 0x63, 0x00, 0x68, 0x00, 0x5C, 0x00, 0x49, 0x00, 0x45, 0x00, 0x46, 0x00, 0x2E, 0x00, 0x7A, 0x00, 0x69, 0x00, 0x70, 0x00, 0x00, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x70, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x79, 0x00, 0x5F, 0x00, 0x52, 0x00, 0x65, 0x00, 0x70, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x74, 0x00, 0x5F, 0x00, 0x31, 0x00, 0x30, 0x00, 0x32, 0x00, 0x32, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x33, 0x00, 0x2E, 0x00, 0x76, 0x00, 0x69, 0x00, 0x72, 0x00, 0x2E, 0x00, 0x7A, 0x00, 0x69, 0x00, 0x70, 0x00, 0x00, 0x00, 0x4C, 0x00, 0x59, 0x00, 0x4E, 0x00, 0x43, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x7A, 0x00, 0x00, 0x00, 0x76, 0x00, 0x69, 0x00, 0x72, 0x00, 0x75, 0x00, 0x73, 0x00, 0x65, 0x00, 0x73, 0x00, 0x2E, 0x00, 0x7A, 0x00, 0x69, 0x00, 0x70, 0x00, 0x00, 0x00, 0x41, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x41, 0x00, 0x2E, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x2E, 0x00, 0x62, 0x00, 0x7A, 0x00, 0x32, 0x00, 0x00, 0x00];
        cell_key_value.detail.data_size_raw = utf16_multiple.len() as u32;
        cell_key_value.detail.value_bytes = Some(utf16_multiple.to_vec());
        let (decoded_value, _) = cell_key_value.decode_content(DecodeFormat::Utf16Multiple, 0);
        let expected_output =
            CellValue::ValueMultiString(
                vec![
                    "NAS_requested_data.7z".to_string(),
                    "BlackHarrier_D7_i686_FDE_20141219.dd.7z".to_string(),
                    "BlackHarrier_D7_amd64_20141217.7z".to_string(),
                    "BlackHarrier_D7_amd64_FDE_20141217.7z".to_string(),
                    r"C:\Users\jmroberts\Desktop\USB_Research\IEF.zip".to_string(),
                    "Company_Report_10222013.vir.zip".to_string(),
                    "LYNC.7z".to_string(),
                    "viruses.zip".to_string(),
                    "ALLDATA.txt.bz2".to_string()]);
        assert_eq!(expected_output, decoded_value);

        let utf16 = [0x4E, 0x00, 0x41, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x72, 0x00, 0x65, 0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00, 0x5F, 0x00, 0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x7A, 0x00];
        cell_key_value.detail.data_size_raw = utf16.len() as u32;
        cell_key_value.detail.value_bytes = Some(utf16.to_vec());
        let (decoded_value, _) = cell_key_value.decode_content(DecodeFormat::Utf16, 0);
        let expected_output = CellValue::ValueString("NAS_requested_data.7z".to_string());
        assert_eq!(expected_output, decoded_value);

        let rot13 = [0x41, 0x00, 0x62, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x76, 0x00, 0x61, 0x00, 0x20, 0x00, 0x68, 0x00, 0x61, 0x00, 0x76, 0x00, 0x67, 0x00, 0x20, 0x00, 0x67, 0x00, 0x72, 0x00, 0x66, 0x00, 0x67, 0x00, 0x2E, 0x00];
        cell_key_value.detail.data_size_raw = rot13.len() as u32;
        cell_key_value.detail.value_bytes = Some(rot13.to_vec());
        cell_key_value.detail.data_type_raw = 1;
        cell_key_value.data_type = CellKeyValueDataTypes::REG_SZ;
        let (decoded_value, _) = cell_key_value.decode_content(DecodeFormat::Rot13, 0);
        let expected_output = CellValue::ValueString("Notatin unit test.".to_string());
        assert_eq!(expected_output, decoded_value);
    }

    #[test]
    fn test_parse_big_data() {
        let mut file_info = FileInfo::from_path("test_data/system").unwrap();
        file_info.hbin_offset_absolute = 4096;
        let mut state = State::default();
        let key_node =
            CellKeyNode::read(
                &file_info,
                &mut state,
                CellKeyNodeReadOptions {
                    offset: 16155688,
                    cur_path:  &String::new(),
                    filter: None,
                    self_is_filter_match_or_descendent: false,
                    sequence_num: None,
                    update_modified_lists: false
                }
            ).unwrap().unwrap();
        assert_eq!(
            "Binary_81725".to_string(),
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