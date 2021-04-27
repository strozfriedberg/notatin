use std::path::PathBuf;
use std::mem;
use std::io::Cursor;
use std::char::REPLACEMENT_CHARACTER;
use chrono::{DateTime, Utc};
use nom::IResult;
use winstructs::timestamp::WinTimestamp;
use crate::err::Error;
use crate::hive_bin_cell_key_node;

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

pub trait PathBufExt {
    /// Returns true if the PathBuf is empty
    fn is_empty(self) -> bool;
}

impl PathBufExt for PathBuf {
    fn is_empty(self) -> bool {
        return self == PathBuf::new();
    }
}

/// Consumes any padding at the end of a hive bin cell. Used during sequential registry read to find deleted cells.
pub fn parser_eat_remaining(
    input: &[u8], 
    cell_size: usize, 
    bytes_consumed: usize
) -> IResult<&[u8], &[u8]> {
    take!(input, cell_size - bytes_consumed)
}

pub fn count_all_keys_and_values(
    key_node: &hive_bin_cell_key_node::HiveBinCellKeyNode, 
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

/// Converts a u64 filetime to a DateTime<Utc>
pub fn get_date_time_from_filetime(filetime: u64) -> Result<DateTime<Utc>, Error> {
    match WinTimestamp::from_reader(&mut Cursor::new(filetime.to_le_bytes())) {
        Ok(date_time) => Ok(date_time.to_datetime()),
        Err(e) => return Err(Error::FailedToReadWindowsTime {
            source: e
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_date_time_from_filetime() {
       assert_eq!(1333727545, get_date_time_from_filetime(129782011451468083).unwrap().timestamp());
    }
}
