use std::mem;
use std::io::Cursor;
use std::char::REPLACEMENT_CHARACTER;
use std::fmt::Write;
use std::string::FromUtf8Error;
use std::time::SystemTime;
use serde::ser;
use chrono::{DateTime, Utc};
use winstructs::{
    timestamp::WinTimestamp,
    guid::Guid
};
use nom::IResult;
use crate::warn::{Warnings, WarningCode};
use crate::cell_key_node;

const SIZE_OF_UTF16_CHAR: usize = mem::size_of::<u16>();

// todo: failure as warning
fn read_utf16_le_string_single(slice: &[u8], count: usize) -> String {
    let iter = (0..count / SIZE_OF_UTF16_CHAR)
        .map(|i| u16::from_le_bytes([slice[2*i], slice[2*i+1]]));
    let intermediate = std::char::decode_utf16(iter).map(|r| r.unwrap_or(REPLACEMENT_CHARACTER)).take_while(|c| c != &'\0');
    intermediate.collect::<String>()
}

/// Reads a null-terminated UTF-16 string (REG_SZ)
pub fn read_utf16_le_string(slice: &[u8], count: usize) -> String {
    assert!(count <= slice.len());
    read_utf16_le_string_single(slice, count)
}

/// Reads a sequence of null-terminated UTF-16 strings, terminated by an empty string (\0). (REG_MULTI_SZ)
pub fn read_utf16_le_strings(slice: &[u8], count: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut offset = 0;

    while offset < count {
        let decoded = read_utf16_le_string_single(&slice[offset..], count - offset);
        if decoded.trim().is_empty() {
            break;
        }
        const NULL_TERMINATOR_LEN: usize = mem::size_of::<u16>();
        offset += (decoded.len() * SIZE_OF_UTF16_CHAR) + NULL_TERMINATOR_LEN;
        strings.push(decoded);
    }
    strings
}

/// Converts a slice of UTF-8 bytes into a String; upon failure, logs the error into the `parse_warnings` parameter and returns `"<Invalid string>"`
pub fn from_utf8(slice: &[u8], parse_warnings: &mut Warnings, err_detail: &str) -> String {
    String::from_utf8(slice.to_vec())
        .or_else(
            |err: FromUtf8Error| -> Result<String, FromUtf8Error> {
                parse_warnings.add_warning(WarningCode::WarningConversion, format!("{}: {}", err_detail, err.to_string()));
                Ok(String::from("<Invalid string>"))
            }
        ).expect("Error handled in or_else")
}

/// Consumes any padding at the end of a hive bin cell. Used during sequential registry read to find deleted cells.
pub fn parser_eat_remaining(
    input: &[u8],
    cell_size: u32,
    bytes_consumed: usize
) -> IResult<&[u8], &[u8]> {
    take!(input, cell_size as usize - bytes_consumed)
}

pub fn count_all_keys_and_values(
    key_node: &cell_key_node::CellKeyNode,
    total_keys: usize,
    total_values: usize
) -> (usize, usize) {
    let mut total_keys = total_keys + key_node.sub_keys.len();
    let mut total_values = total_values + key_node.sub_values.len();
    for key in key_node.sub_keys.iter() {
        let (k, v) = count_all_keys_and_values(key, total_keys, total_values);
        total_keys = k;
        total_values = v;
    }
    (total_keys, total_values)
}

/// Converts a u64 filetime to a DateTime<Utc>; upon error, logs error to parse_warnings and returns UNIX_EPOCH
pub fn get_date_time_from_filetime(filetime: u64, parse_warnings: &mut Warnings) -> DateTime<Utc> {
    match WinTimestamp::from_reader(&mut Cursor::new(filetime.to_le_bytes())) {
        Ok(win_timestamp) => win_timestamp.to_datetime(),
        Err(e) => {
            parse_warnings.add_warning(WarningCode::WarningConversion, e.to_string());
            DateTime::from(SystemTime::UNIX_EPOCH)
        }
    }
}

/// Converts a buffer to a guid; upon error, logs error to parse_warnings and returns an null guid
pub fn get_guid_from_buffer(buffer: &[u8], parse_warnings: &mut Warnings) -> Guid {
    match Guid::from_buffer(buffer) {
        Ok(guid) => guid,
        Err(e) => {
            parse_warnings.add_warning(WarningCode::WarningConversion, e.to_string());
            Guid::from_buffer(&[0; 16]).unwrap()
        }
    }
}

/// Via https://github.com/omerbenamram/mft
#[macro_export]
macro_rules! impl_serialize_for_bitflags {
    ($flags: ident) => {
        impl serde::ser::Serialize for $flags {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_str(&format!("{:?}", &self))
            }
        }
    };
}

#[macro_export]
macro_rules! impl_flags_from_bits {
    ($bitflag_type: ident, $var_type: ident) => {
        impl $bitflag_type {
            fn from_bits_checked(flags: $var_type, parse_warnings: &mut Warnings) -> Self {
                let flags_mapped = $bitflag_type::from_bits_truncate(flags);
                if flags != flags_mapped.bits() {
                    fn f() {}
                    fn type_name_of<T>(_: T) -> &'static str {
                        std::any::type_name::<T>()
                    }
                    let name = type_name_of(f);
                    const FOOTER_LEN: usize = "::f".len();
                    let fn_name = &name[..name.len() - FOOTER_LEN];
                    parse_warnings.add_warning(WarningCode::WarningUnrecognizedBitflag, format!("{}: {:#X}", fn_name, flags));
                }
                return flags_mapped;
            }
        }
    };
}

pub fn data_as_hex<S: ser::Serializer>(x: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&to_hex_string(x))
}

/// Adapted from https://github.com/omerbenamram/mft
pub fn to_hex_string(bytes: &[u8]) -> String {
    let len = bytes.len();
    let mut s = String::with_capacity(len * 2); // Each byte is represented by 2 ascii bytes.

    for byte in bytes {
        write!(s, "{:02X} ", byte).expect("Writing to an allocated string cannot fail");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warn::Warning;

    #[test]
    fn test_get_date_time_from_filetime() {
       assert_eq!(1333727545, get_date_time_from_filetime(129782011451468083, &mut Warnings::new()).timestamp());
    }

    #[test]
    fn test_get_guid_from_buffer() {
        let raw_guid: &[u8] = &[0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49,
                                0xa5, 0xba, 0x3e, 0x3b, 0x3, 0x28, 0xc3, 0xd];

        let mut parse_warnings = Warnings::new();
        let guid = get_guid_from_buffer(raw_guid, &mut parse_warnings);

        assert_eq!(format!("{}", guid), "54849625-5478-4994-A5BA-3E3B0328C30D");
        assert_eq!(None, parse_warnings.get_warnings());

        let err_guid = get_guid_from_buffer(&raw_guid[..14], &mut parse_warnings);
        assert_eq!(format!("{}", err_guid), "00000000-0000-0000-0000-000000000000", "Return Guid for error case is incorrect");
        let expected_warning = Warning {
            code: WarningCode::WarningConversion,
            text: "An I/O error has occurred".to_string()
        };
        assert_eq!(&vec![expected_warning], parse_warnings.get_warnings().unwrap());
    }

    #[test]
    fn test_from_utf8() {
        let mut parse_warnings = Warnings::new();
        let good = from_utf8(&[0x74, 0x65, 0x73, 0x74], &mut parse_warnings, "Unit test");
        assert_eq!("test", good);
        assert_eq!(None, parse_warnings.get_warnings());

        let bad = from_utf8(&[0xff, 0xff, 0xff], &mut parse_warnings, "Unit test");
        assert_eq!("<Invalid string>", bad);
        let expected_warning = Warning {
            code: WarningCode::WarningConversion,
            text: "Unit test: invalid utf-8 sequence of 1 bytes from index 0".to_string()
        };
        assert_eq!(&vec![expected_warning], parse_warnings.get_warnings().unwrap());
    }

    #[test]
    fn test_read_utf16_le_strings() {
        let buffer = [77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 69, 0, 110, 0, 104, 0, 97, 0, 110, 0, 99, 0, 101, 0, 100, 0, 32, 0, 67, 0, 114, 0, 121, 0, 112, 0, 116, 0, 111, 0, 103, 0, 114, 0, 97, 0, 112, 0, 104, 0, 105, 0, 99, 0, 32, 0, 80, 0, 114, 0, 111, 0, 118, 0, 105, 0, 100, 0, 101, 0, 114, 0, 32, 0, 118, 0, 49, 0, 46, 0, 48, 0, 0, 0, 77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 66, 0, 97, 0, 115, 0, 101, 0, 32, 0, 67, 0, 114, 0, 121, 0, 112, 0, 116, 0, 111, 0, 103, 0, 114, 0, 97, 0, 112, 0, 104, 0, 105, 0, 99, 0, 32, 0, 80, 0, 114, 0, 111, 0, 118, 0, 105, 0, 100, 0, 101, 0, 114, 0, 32, 0, 118, 0, 49, 0, 46, 0, 48, 0, 0, 0, 0, 0];
        let strings = read_utf16_le_strings(&buffer, buffer.len());
        let expected_strings = vec!["Microsoft Enhanced Cryptographic Provider v1.0", "Microsoft Base Cryptographic Provider v1.0"];
        assert_eq!(expected_strings, strings);
    }
}
