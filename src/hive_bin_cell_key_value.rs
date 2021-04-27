use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32}
};

use std::convert::{TryFrom, TryInto};
use std::mem;
use bitflags::bitflags;
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use crate::util;
use crate::hive_bin_cell;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
#[repr(u32)]
pub enum HiveBinCellKeyValueDataTypes {    
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
    RegGUID                     = 0x0110,
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

bitflags! {
    pub struct HiveBinCellKeyValueFlags: u16 { 
        const VALUE_COMP_NAME_ASCII = 1; // Name is an ASCII string / Otherwise the name is an Unicode (UTF-16 little-endian) string
        const IS_TOMBSTONE          = 2; // Is a tombstone value (the flag is used starting from Insider Preview builds of Windows 10 "Redstone 1"), a tombstone value also has the Data type field set to REG_NONE, the Data size field set to 0, and the Data offset field set to 0xFFFFFFFF
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum CellValue {
    ValueNone,
    ValueBinary {
        content: Vec<u8>
    },
    ValueString {
        content: String
    },
    ValueMultiString {
        content: Vec<String>
    },
    ValueU32 {
        content: u32
    },
    ValueI32 {
        content: i32
    },
    ValueU64 {
        content: u64
    },
    ValueI64 {
        content: i64
    }
}

// Registry key value
#[derive(Debug, Eq, PartialEq)]
pub struct HiveBinCellKeyValue {
    pub size: u32,
    pub signature: [u8; 2], // "vk"
    pub value_name_size: u16, // If the value name size is 0 the value name is "(default)"
    pub data_size: u32, // In bytes, can be 0 (value isn't set), the most significant bit has a special meaning 
    pub data_offset: u32, // In bytes, relative from the start of the hive bins data (or data itself)
    pub data_type: HiveBinCellKeyValueDataTypes,
    pub flags: HiveBinCellKeyValueFlags,
    pub padding: u16,
    pub value_name: String, // in file, ASCII (extended) string or UTF-16LE string
    pub value_content: CellValue
}

impl hive_bin_cell::HiveBinCell for HiveBinCellKeyValue {    
    fn size(&self) -> u32 {
        self.size
    }

    fn signature(&self) -> [u8;2] {
        self.signature
    }

    fn name_lowercase(&self) -> Option<String> {
        Some(self.value_name.clone().to_ascii_lowercase())
    }
}

pub fn get_value_content(input: &[u8], data_type: HiveBinCellKeyValueDataTypes) -> CellValue {
    match data_type {
        HiveBinCellKeyValueDataTypes::RegNone => 
            CellValue::ValueNone,
        HiveBinCellKeyValueDataTypes::RegSZ | 
        HiveBinCellKeyValueDataTypes::RegExpandSZ | 
        HiveBinCellKeyValueDataTypes::RegLink => 
            CellValue::ValueString {
                content: util::read_utf16_le_string(input, (input.len() / 2).into()).unwrap()
            },
        HiveBinCellKeyValueDataTypes::RegUint8 => 
            CellValue::ValueU32 {
                content: u8::from_le_bytes(input[0..mem::size_of::<u8>()].try_into().unwrap()) as u32
            },        
        HiveBinCellKeyValueDataTypes::RegInt16 => 
            CellValue::ValueI32 {
                content: i16::from_le_bytes(input[0..mem::size_of::<i16>()].try_into().unwrap()) as i32
            },
        HiveBinCellKeyValueDataTypes::RegUint16 => 
            CellValue::ValueU32 {
                content: u16::from_le_bytes(input[0..mem::size_of::<u16>()].try_into().unwrap()) as u32
            },
        HiveBinCellKeyValueDataTypes::RegDWord | 
        HiveBinCellKeyValueDataTypes::RegUint32 => 
            CellValue::ValueU32 {
                content: u32::from_le_bytes(input[0..mem::size_of::<u32>()].try_into().unwrap())
            },
        HiveBinCellKeyValueDataTypes::RegDWordBigEndian => 
            CellValue::ValueU32 {
                content: u32::from_be_bytes(input[0..mem::size_of::<u32>()].try_into().unwrap())
            },   
        HiveBinCellKeyValueDataTypes::RegInt32 => 
            CellValue::ValueI32 {
                content: i32::from_le_bytes(input[0..mem::size_of::<i32>()].try_into().unwrap())
            },                      
        HiveBinCellKeyValueDataTypes::RegInt64 => 
            CellValue::ValueI64 {
                content: i64::from_le_bytes(input[0..mem::size_of::<i64>()].try_into().unwrap())
            },            
        HiveBinCellKeyValueDataTypes::RegQWord | 
        HiveBinCellKeyValueDataTypes::RegUint64 => 
            CellValue::ValueU64 {
                content: u64::from_le_bytes(input[0..mem::size_of::<u64>()].try_into().unwrap())
            },           
        HiveBinCellKeyValueDataTypes::RegBin => 
            CellValue::ValueBinary {
                content: input.to_vec()
            },         
       HiveBinCellKeyValueDataTypes::RegMultiSZ =>
            CellValue::ValueMultiString {
                content: util::read_utf16_le_strings(input, input.len()/2).unwrap()
            },  
        HiveBinCellKeyValueDataTypes::RegResourceList |
        HiveBinCellKeyValueDataTypes::RegFileTime |
        HiveBinCellKeyValueDataTypes::RegFullResourceDescriptor |
        HiveBinCellKeyValueDataTypes::RegResourceRequirementsList |
        HiveBinCellKeyValueDataTypes::RegFloat |
        HiveBinCellKeyValueDataTypes::RegDouble |
        HiveBinCellKeyValueDataTypes::RegUnicodeChar |
        HiveBinCellKeyValueDataTypes::RegBoolean |
        HiveBinCellKeyValueDataTypes::RegUnicodeString |
        HiveBinCellKeyValueDataTypes::RegCompositeValue |
        HiveBinCellKeyValueDataTypes::RegDateTimeOffset |
        HiveBinCellKeyValueDataTypes::RegTimeSpan |
        HiveBinCellKeyValueDataTypes::RegGUID |
        HiveBinCellKeyValueDataTypes::RegUnk111 |
        HiveBinCellKeyValueDataTypes::RegUnk112 |
        HiveBinCellKeyValueDataTypes::RegUnk113 |
        HiveBinCellKeyValueDataTypes::RegBytesArray |
        HiveBinCellKeyValueDataTypes::RegInt16Array |
        HiveBinCellKeyValueDataTypes::RegUint16Array |
        HiveBinCellKeyValueDataTypes::RegInt32Array |
        HiveBinCellKeyValueDataTypes::RegUInt32Array |
        HiveBinCellKeyValueDataTypes::RegInt64Array |
        HiveBinCellKeyValueDataTypes::RegUInt64Array |
        HiveBinCellKeyValueDataTypes::RegFloatArray |
        HiveBinCellKeyValueDataTypes::RegDoubleArray |
        HiveBinCellKeyValueDataTypes::RegUnicodeCharArray |
        HiveBinCellKeyValueDataTypes::RegBooleanArray |
        HiveBinCellKeyValueDataTypes::RegUnicodeStringArray  => 
            CellValue::ValueBinary {
                content: input.to_vec()
            },  
    } 
}

pub fn parse_hive_bin_cell_key_value<'a>(
    input: &'a [u8], 
    file_buffer: &[u8], 
    start_offset: u32
) -> IResult<&'a [u8], HiveBinCellKeyValue> {
    let (input, size) = le_i32(input)?;
    let (input, signature) = tag("vk")(input)?;
    let (input, value_name_size) = le_u16(input)?;
    let (input, data_size) = le_u32(input)?;
    let (input, data_offset) = le_u32(input)?;
    let (input, data_type_bytes) = le_u32(input)?;
    let (input, flags) = le_u16(input)?;
    let flags = HiveBinCellKeyValueFlags::from_bits(flags).unwrap();
    let (input, padding) = le_u16(input)?;
    let (input, value_name_bytes) = take!(input, value_name_size)?;     
    let bytes_consumed: u32 = (24 + value_name_size).into();
    
    let data_type = match HiveBinCellKeyValueDataTypes::from_u32(data_type_bytes) {
        None => HiveBinCellKeyValueDataTypes::RegNone,
        Some(data_type) => data_type
    };

    let value_name;
    if value_name_size == 0 {
        value_name = String::from("(Default)");
    }
    else if flags.contains(HiveBinCellKeyValueFlags::VALUE_COMP_NAME_ASCII) {
        value_name = String::from_utf8(value_name_bytes.to_vec()).unwrap();
    }
    else {
        value_name = util::read_utf16_le_string(value_name_bytes, (value_name_size / 2).into()).unwrap();
    }
    let abs_size = size.abs() as u32;
    let (input, _) = take!(input, abs_size - bytes_consumed)?;
  
    /* Per https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md:
        When the most significant bit is 1, data (4 bytes or less) is stored in the Data offset field directly 
        (when data contains less than 4 bytes, it is being stored as is in the beginning of the Data offset field). 
        The most significant bit (when set to 1) should be ignored when calculating the data size.
        When the most significant bit is 0, data is stored in the Cell data field of another cell (pointed by the Data offset field) 
        or in the Cell data fields of multiple cells (referenced in the Big data structure stored in a cell pointed by the Data offset field). */
    const DATA_IS_RESIDENT_MASK: u32 = 0x80000000;
    let value_content;
    if data_size & DATA_IS_RESIDENT_MASK == 0 {
        let offset = (data_offset + start_offset) as usize + mem::size_of_val(&size);
        let value_slice = &file_buffer[offset..offset + data_size as usize]; 
        value_content = get_value_content(value_slice, data_type);
    }
    else {
        let size = data_size ^ DATA_IS_RESIDENT_MASK;
        let value = data_offset.to_le_bytes(); 
        value_content = get_value_content(&value[..size as usize], data_type);
    }

    Ok((
        input,
        HiveBinCellKeyValue {
            size: abs_size,
            signature: <[u8; 2]>::try_from(signature).unwrap(),
            value_name_size,
            data_size,
            data_offset,
            data_type,
            flags,
            padding,
            value_name,
            value_content
        },
    ))
}


#[cfg(test)]
mod tests {
    use super::*;
        
    #[test]
    fn test_parse_hive_bin_cell_key_value() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4400..4448];
        
        let ret = parse_hive_bin_cell_key_value(slice, &f[0..], 4096);
        let expected_output = HiveBinCellKeyValue {
            size: 48,
            signature: [118, 107],
            value_name_size: 18,
            data_size: 8,
            data_offset: 1928,
            data_type: HiveBinCellKeyValueDataTypes::RegSZ,
            flags: HiveBinCellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            padding: 1280,
            value_name: "IE5_UA_Backup_Flag".to_string(),
            value_content: CellValue::ValueString { content: "5.0".to_string() }
        };
        let remaining: [u8; 0] = [];
        let expected = Ok((&remaining[..], expected_output));

        assert_eq!(
            expected,
            ret
        );
    }
}