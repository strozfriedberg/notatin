use std::path::PathBuf;
use nom::{
    IResult
};
use crate::hive_bin_cell_key_node;

fn read_utf16_le_string_internal(slice: &[u8], size: usize) -> Option<String> {
    let iter = (0..size)
        .map(|i| u16::from_le_bytes([slice[2*i], slice[2*i+1]]));
    let intermediate = std::char::decode_utf16(iter).take_while(|c| c.as_ref().ok().unwrap() != &'\0');
    intermediate.collect::<Result<String, _>>().ok()
}

/// Reads a null-terminated UTF-16 string (REG_SZ)
pub fn read_utf16_le_string(slice: &[u8], size: usize) -> Option<String> {
    assert!(2*size <= slice.len());
    read_utf16_le_string_internal(slice, size)
}

/// Reads a sequence of null-terminated UTF-16 strings, terminated by an empty string (\0). (REG_MULTI_SZ)
pub fn read_utf16_le_strings(slice: &[u8], size: usize) -> Option<Vec<String>> {
    let mut strings = Vec::new();
    let mut offset = 0;

    while offset < size {    
        let ret = read_utf16_le_string_internal(slice, size).unwrap();
        if ret.trim().is_empty() {
            break;
        }
        offset += ret.len() + 1; // +1 for the null terminator
        strings.push(ret);
    }
    Some(strings)
}

/// Additional  methods for `PathBuf`.
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
pub fn eat_remaining(
    input: &[u8], 
    cell_size: usize, 
    bytes_consumed: usize
) -> IResult<&[u8], &[u8]> {
    take!(input, cell_size - bytes_consumed)
}

/// Consumes any padding at the end of a hive bin cell. Used during sequential registry read (find deleted cells).
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
