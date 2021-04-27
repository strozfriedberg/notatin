use std::path::PathBuf;
use std::mem;
use std::io::Cursor;
use chrono::{DateTime, Utc};
use nom::IResult;
use winstructs::timestamp::WinTimestamp;
use crate::err::Error;
use crate::hive_bin_cell_key_node;

// todo: failure as warning
fn read_utf16_le_string_single(slice: &[u8], size: usize) -> (String, Option<String>) {
    let iter = (0..size)
        .map(|i| u16::from_le_bytes([slice[2*i], slice[2*i+1]]));
    let intermediate = std::char::decode_utf16(iter).take_while(|c| c.as_ref().ok().unwrap() != &'\0');
    match intermediate.collect::<Result<String, _>>() {
        Ok(decoded) => (decoded, None),
        Err(e) => ("<Parse error>".to_string(), Some(e.to_string()))
    }
}

/// Reads a null-terminated UTF-16 string (REG_SZ)
pub fn read_utf16_le_string(slice: &[u8], size: usize) -> (String, Option<String>) {
    assert!(2*size <= slice.len());
    read_utf16_le_string_single(slice, size)
}

/// Reads a sequence of null-terminated UTF-16 strings, terminated by an empty string (\0). (REG_MULTI_SZ)
pub fn read_utf16_le_strings(slice: &[u8], size: usize) -> (Vec<String>, Option<Vec<String>>) {
    let mut strings = Vec::new();
    let mut warnings = Vec::new();
    let mut offset = 0;

    while offset < size {    
        let res = read_utf16_le_string_single(slice, size);
        let decoded = res.0;
        if decoded.trim().is_empty() {
            break;
        }
        const NULL_TERMINATOR_LEN: usize = mem::size_of::<char>();
        offset += decoded.len() + NULL_TERMINATOR_LEN;
        strings.push(decoded);
        res.1.map(|warning| warnings.push(warning));
    }
    (strings, Some(warnings))
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_date_time_from_filetime() {
       assert_eq!(1333727545, get_date_time_from_filetime(129782011451468083).unwrap().timestamp());
    }
}