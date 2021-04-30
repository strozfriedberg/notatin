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
use crate::util;
use crate::registry::State;
use crate::hive_bin_cell;
use crate::cell_value::CellValue;
use crate::cell_big_data::CellBigData;
use crate::impl_serialize_for_bitflags;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive, Serialize)]
#[repr(u32)]
pub enum CellKeyValueDataTypes {
    RegNone                     = 0x0000,
    RegSZ                       = 0x0001,
    RegExpandSZ                 = 0x0002,
    RegBin                      = 0x0003,
    RegDWord                    = 0x0004,
    RegDWordBigEndian           = 0x0005,
    RegLink                     = 0x0006,
    RegMultiSZ                  = 0x0007,
    RegResourceList             = 0x0008,
    RegFullResourceDescriptor   = 0x0009,
    RegResourceRequirementsList = 0x000A,
    RegQWord                    = 0x000B,
    RegFileTime                 = 0x0010,
    // Following are new types from settings.dat
    // Per https://github.com/williballenthin/python-registry/blob/master/Registry/RegistryParse.py
    RegUint8                    = 0x0101,
    RegInt16                    = 0x0102,
    RegUint16                   = 0x0103,
    RegInt32                    = 0x0104,
    RegUint32                   = 0x0105,
    RegInt64                    = 0x0106,
    RegUint64                   = 0x0107,
    RegFloat                    = 0x0108,
    RegDouble                   = 0x0109,
    RegUnicodeChar              = 0x010A,
    RegBoolean                  = 0x010B,
    RegUnicodeString            = 0x010C,
    RegCompositeValue           = 0x010D,
    RegDateTimeOffset           = 0x010E,
    RegTimeSpan                 = 0x010F,
    RegGuid                     = 0x0110,
    RegUnk111                   = 0x0111,
    RegUnk112                   = 0x0112,
    RegUnk113                   = 0x0113,
    RegBytesArray               = 0x0114,
    RegInt16Array               = 0x0115,
    RegUint16Array              = 0x0116,
    RegInt32Array               = 0x0117,
    RegUInt32Array              = 0x0118,
    RegInt64Array               = 0x0119,
    RegUInt64Array              = 0x011A,
    RegFloatArray               = 0x011B,
    RegDoubleArray              = 0x011C,
    RegUnicodeCharArray         = 0x011D,
    RegBooleanArray             = 0x011E,
    RegUnicodeStringArray       = 0x011F,
}

impl CellKeyValueDataTypes {
    // todo: handle unwraps
    pub fn get_value_content(self, input: &[u8]) -> (CellValue, Option<Vec<String>>) {
        let mut warnings = Vec::new();
        let cv = match self {
            CellKeyValueDataTypes::RegNone =>
                CellValue::ValueNone,
            CellKeyValueDataTypes::RegSZ |
            CellKeyValueDataTypes::RegExpandSZ |
            CellKeyValueDataTypes::RegLink => CellValue::ValueString(
                util::read_utf16_le_string(input, input.len())
            ),
            CellKeyValueDataTypes::RegUint8 => CellValue::ValueU32(
                u8::from_le_bytes(input[0..mem::size_of::<u8>()].try_into().unwrap()) as u32
            ),
            CellKeyValueDataTypes::RegInt16 => CellValue::ValueI32(
                i16::from_le_bytes(input[0..mem::size_of::<i16>()].try_into().unwrap()) as i32
            ),
            CellKeyValueDataTypes::RegUint16 => CellValue::ValueU32(
                u16::from_le_bytes(input[0..mem::size_of::<u16>()].try_into().unwrap()) as u32
            ),
            CellKeyValueDataTypes::RegDWord |
            CellKeyValueDataTypes::RegUint32 => CellValue::ValueU32(
                u32::from_le_bytes(input[0..mem::size_of::<u32>()].try_into().unwrap())
            ),
            CellKeyValueDataTypes::RegDWordBigEndian => CellValue::ValueU32(
                u32::from_be_bytes(input[0..mem::size_of::<u32>()].try_into().unwrap())
            ),
            CellKeyValueDataTypes::RegInt32 => CellValue::ValueI32(
                i32::from_le_bytes(input[0..mem::size_of::<i32>()].try_into().unwrap())
            ),
            CellKeyValueDataTypes::RegInt64 => CellValue::ValueI64(
                i64::from_le_bytes(input[0..mem::size_of::<i64>()].try_into().unwrap())
            ),
            CellKeyValueDataTypes::RegQWord |
            CellKeyValueDataTypes::RegUint64 => CellValue::ValueU64(
                u64::from_le_bytes(input[0..mem::size_of::<u64>()].try_into().unwrap())
            ),
            CellKeyValueDataTypes::RegBin => CellValue::ValueBinary(
                input.to_vec()
            ),
            CellKeyValueDataTypes::RegMultiSZ => CellValue::ValueMultiString(
                util::read_utf16_le_strings(input, input.len())
            ),
            CellKeyValueDataTypes::RegResourceList |
            CellKeyValueDataTypes::RegFileTime |
            CellKeyValueDataTypes::RegFullResourceDescriptor |
            CellKeyValueDataTypes::RegResourceRequirementsList |
            CellKeyValueDataTypes::RegFloat |
            CellKeyValueDataTypes::RegDouble |
            CellKeyValueDataTypes::RegUnicodeChar |
            CellKeyValueDataTypes::RegBoolean |
            CellKeyValueDataTypes::RegUnicodeString |
            CellKeyValueDataTypes::RegCompositeValue |
            CellKeyValueDataTypes::RegDateTimeOffset |
            CellKeyValueDataTypes::RegTimeSpan |
            CellKeyValueDataTypes::RegGuid |
            CellKeyValueDataTypes::RegUnk111 |
            CellKeyValueDataTypes::RegUnk112 |
            CellKeyValueDataTypes::RegUnk113 |
            CellKeyValueDataTypes::RegBytesArray |
            CellKeyValueDataTypes::RegInt16Array |
            CellKeyValueDataTypes::RegUint16Array |
            CellKeyValueDataTypes::RegInt32Array |
            CellKeyValueDataTypes::RegUInt32Array |
            CellKeyValueDataTypes::RegInt64Array |
            CellKeyValueDataTypes::RegUInt64Array |
            CellKeyValueDataTypes::RegFloatArray |
            CellKeyValueDataTypes::RegDoubleArray |
            CellKeyValueDataTypes::RegUnicodeCharArray |
            CellKeyValueDataTypes::RegBooleanArray |
            CellKeyValueDataTypes::RegUnicodeStringArray =>
                CellValue::ValueBinary(input.to_vec()),
        };
        if !warnings.is_empty() {
            (cv, Some(warnings))
        }
        else {
            (cv, None)
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

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellKeyValueDetail {
    pub absolute_file_offset: usize,
    pub value_name_size: u16, // If the value name size is 0 the value name is "(default)"
    pub data_size: u32, // In bytes, can be 0 (value isn't set); the most significant bit has a special meaning
    pub data_offset: u32, // In bytes, relative from the start of the hive bin's data (or data itself)
    pub padding: u16,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellKeyValue {
    pub detail: CellKeyValueDetail,
    pub size: u32,
    pub data_type: CellKeyValueDataTypes,
    pub flags: CellKeyValueFlags,
    pub value_name: String, // in file, ASCII (extended) string or UTF-16LE string
    pub value_content: Option<CellValue>
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
            None => CellKeyValueDataTypes::RegNone,
            Some(data_type) => data_type
        };

        let value_name;
        if value_name_size == 0 {
            value_name = String::from("(Default)");
        }
        else if flags.contains(CellKeyValueFlags::VALUE_COMP_NAME_ASCII) {
            value_name = String::from_utf8(value_name_bytes.to_vec()).unwrap(); // todo: handle unwrap
        }
        else {
            value_name = util::read_utf16_le_string(value_name_bytes, (value_name_size / 2).into());
        }
        let size_abs = size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs as usize, input.as_ptr() as usize - start_pos)?;

        Ok((
            input,
            CellKeyValue {
                detail: CellKeyValueDetail {
                    absolute_file_offset,
                    value_name_size,
                    data_size,
                    data_offset,
                    padding,
                },
                size: size_abs,
                data_type,
                flags,
                value_name,
                value_content: None
            },
        ))
    }

    pub fn read_content(&mut self, state: &State) -> Option<Vec<String>> {
        /* Per https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md:
            When the most significant bit is 1, data (4 bytes or less) is stored in the Data offset field directly
            (when data contains less than 4 bytes, it is being stored as is in the beginning of the Data offset field).
            The most significant bit (when set to 1) should be ignored when calculating the data size.
            When the most significant bit is 0, data is stored in the Cell data field of another cell (pointed by the Data offset field)
            or in the Cell data fields of multiple cells (referenced in the Big data structure stored in a cell pointed by the Data offset field). */
        const DATA_IS_RESIDENT_MASK: u32 = 0x80000000;
        let value_content_and_warning;
        if self.detail.data_size & DATA_IS_RESIDENT_MASK == 0 {
            if CellKeyValue::BIG_DATA_SIZE_THRESHOLD < self.detail.data_size {
                let offset = self.detail.data_offset as usize + state.hbin_offset;
                value_content_and_warning = CellBigData::get_big_data_content(state, offset, self.data_type, self.detail.data_size);
            }
            else {
                let offset = self.detail.data_offset as usize + state.hbin_offset + mem::size_of_val(&self.size);
                let value_slice = &state.file_buffer[offset..offset + self.detail.data_size as usize];
                value_content_and_warning = self.data_type.get_value_content(value_slice);
            }
        }
        else {
            let size = self.detail.data_size ^ DATA_IS_RESIDENT_MASK;
            let value = self.detail.data_offset.to_le_bytes();
            value_content_and_warning = self.data_type.get_value_content(&value[..size as usize]);
        }
        self.value_content = Some(value_content_and_warning.0);
        value_content_and_warning.1
    }
}

impl hive_bin_cell::Cell for CellKeyValue {
    fn size(&self) -> u32 {
        self.size
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
                value_name_size: 18,
                data_size: 8,
                data_offset: 1928,
                padding: 1280,
            },
            size: 48,
            data_type: CellKeyValueDataTypes::RegSZ,
            flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            value_name: "IE5_UA_Backup_Flag".to_string(),
            value_content: None
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
        let warnings = cell_key_value.read_content(&state);
        assert_eq!(
            CellValue::ValueString("5.0".to_string()),
            cell_key_value.value_content.unwrap()
        );
        assert_eq!(
            None,
            warnings
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
        let key_node = CellKeyNode::read(&state, &f[4416..], String::new(), &mut Filter {..Default::default() }).unwrap().unwrap();
        let t=3;

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