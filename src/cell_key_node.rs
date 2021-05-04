use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32, le_u64},
    branch::alt,
    multi::count
};
use winstructs::security::SecurityDescriptor;
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::Serialize;
use crate::registry::State;
use crate::err::Error;
use crate::warn::Warnings;
use crate::util;
use crate::hive_bin_cell;
use crate::cell_key_value::CellKeyValue;
use crate::cell_key_security;
use crate::sub_key_list_lf::SubKeyListLf;
use crate::sub_key_list_lh::SubKeyListLh;
use crate::sub_key_list_li::SubKeyListLi;
use crate::sub_key_list_ri::SubKeyListRi;
use crate::filter::{Filter, FilterFlags};
use crate::impl_serialize_for_bitflags;

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct CellKeyNodeDetail {
    pub absolute_file_offset: usize,
    pub size: u32,
    pub number_of_volatile_sub_keys: u32, // The offset value is in bytes and relative from the start of the hive bin data / Refers to a sub keys list or contains -1 (0xffffffff) if empty.
    pub sub_keys_list_offset: u32, // In bytes, relative from the start of the hive bins data (also, this field may point to an Index root)
    pub volatile_sub_keys_list_offset: i32, // This field has no meaning on a disk (volatile keys are not written to a file)
    pub key_values_list_offset: i32,
    pub security_key_offset: u32,
    pub class_name_offset: i32,
    /*  Starting from Windows Vista, Windows Server 2003 SP2, and Windows XP SP3, the Largest subkey name length field has been split
        into 4 bit fields (the offsets below are relative from the beginning of the old Largest subkey name length field,
        i.e. the first bit field starts within the byte at the lowest address):
        Offset (bits)	Length (bits)	Field	                     Description
        0	            16	            Largest subkey name length
        16	            4	            Virtualization control flags Bit mask, see below
        20	            4	            User flags (Wow64 flags)     Bit mask, see below
        24              8	            Debug                        See below */
    pub largest_sub_key_name_size: u32, // In bytes, a subkey name is treated as a UTF-16LE string (see below)
    pub largest_sub_key_class_name_size: u32,
    pub largest_value_name_size: u32, // In bytes, a value name is treated as a UTF-16LE string
    pub largest_value_data_size: u32,
    pub work_var: u32, // Unused as of WinXP
    pub key_name_size: u16,
    pub class_name_size: u16,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CellKeyNode {
    pub detail: CellKeyNodeDetail,
    pub flags: KeyNodeFlags,
    pub last_key_written_date_and_time: DateTime<Utc>,
    pub access_bits: AccessFlags, // Bit mask (this field is used as of Windows 8 and Windows Server 2012; in previous versions of Windows, this field is reserved and called Spare)
    pub parent_key_offset: i32, // Offset of a parent key node in bytes, relative from the start of the hive bins data (this field has no meaning on a disk for a root key node)
    pub number_of_sub_keys: u32,
    pub number_of_key_values: u32,
    pub key_name: String, // ASCII (extended) string or UTF-16LE string,

    pub allocated: bool,
    pub path: String,
    pub sub_keys: Vec<CellKeyNode>,
    pub sub_values: Vec<CellKeyValue>,
    pub parse_warnings: Warnings
}

/*impl Iterator for CellKeyNode {
    // The return type is `Option<T>`:
    //     * When the `Iterator` is finished, `None` is returned.
    //     * Otherwise, the next value is wrapped in `Some` and returned.
    fn next(&mut self) -> Option<CellKeyNode> {
        let new_next = self.curr + self.next;

        self.curr = self.next;
        self.next = new_next;

        // Since there's no endpoint to a Fibonacci sequence, the `Iterator`
        // will never return `None`, and `Some` is always returned.
        Some(self.curr)
    }
}*/

impl Default for CellKeyNode {
    fn default() -> Self {
        CellKeyNode {
            detail: CellKeyNodeDetail::default(),
            flags: KeyNodeFlags::default(),
            last_key_written_date_and_time: Utc::now(),
            access_bits: AccessFlags::default(),
            parent_key_offset: i32::default(),
            number_of_sub_keys: u32::default(),
            number_of_key_values: u32::default(),
            key_name: String::default(),
            allocated: bool::default(),
            path: String::default(),
            sub_keys: Vec::default(),
            sub_values: Vec::default(),
            parse_warnings: Warnings::new()
         }
    }
}

impl hive_bin_cell::Cell for CellKeyNode {
    fn size(&self) -> u32 {
        self.detail.size
    }

    fn name_lowercase(&self) -> Option<String> {
        Some(self.key_name.clone().to_ascii_lowercase())
    }
}

impl CellKeyNode {
    pub fn from_bytes<'a> (
        state: &State,
        input: &'a [u8],
        cur_path: String
    ) -> IResult<&'a [u8], Self> {
        let absolute_file_offset = state.get_file_offset(input);
        let start_pos = input.as_ptr() as usize;
        let (input, size) = le_i32(input)?;
        let (input, _signature) = tag("nk")(input)?;
        let (input, flags) = le_u16(input)?;
        let (input, last_key_written_date_and_time) = le_u64(input)?;
        let (input, access_bits) = le_u32(input)?;
        let (input, parent_key_offset) = le_i32(input)?;
        let (input, number_of_sub_keys) = le_u32(input)?;
        let (input, number_of_volatile_sub_keys) = le_u32(input)?;
        let (input, sub_keys_list_offset) = le_u32(input)?;
        let (input, volatile_sub_keys_list_offset) = le_i32(input)?;
        let (input, number_of_key_values) = le_u32(input)?;
        let (input, key_values_list_offset) = le_i32(input)?;
        let (input, security_key_offset) = le_u32(input)?;
        let (input, class_name_offset) = le_i32(input)?;
        let (input, largest_sub_key_name_size) = le_u32(input)?;
        let (input, largest_sub_key_class_name_size) = le_u32(input)?;
        let (input, largest_value_name_size) = le_u32(input)?;
        let (input, largest_value_data_size) = le_u32(input)?;
        let (input, work_var) = le_u32(input)?;
        let (input, key_name_size) = le_u16(input)?;
        let (input, class_name_size) = le_u16(input)?;
        let (input, key_name_bytes) = take!(input, key_name_size)?;

        let mut parse_warnings = Warnings::new();
        let flags = KeyNodeFlags::from_bits(flags).unwrap_or_default();
        let key_name: String;

        if flags.contains(KeyNodeFlags::KEY_COMP_NAME) {
           // let key_name_bytes = [0, 159, 146, 150];
            key_name = util::from_utf8(&key_name_bytes, &mut parse_warnings, "key_name_bytes");
        }
        else {
            let key_name_warning = util::read_utf16_le_string(key_name_bytes, (key_name_size / 2).into());
            key_name = key_name_warning;
        }

        let size_abs =  size.abs() as u32;
        let (input, _) = util::parser_eat_remaining(input, size_abs, input.as_ptr() as usize - start_pos)?;

        let timestamp = util::get_date_time_from_filetime(last_key_written_date_and_time);

        let mut path = cur_path;
        path.push('\\');
        path += &key_name;
        let cell_key_node = CellKeyNode {
            detail: CellKeyNodeDetail {
                absolute_file_offset,
                size: size_abs,
                number_of_volatile_sub_keys,
                sub_keys_list_offset,
                volatile_sub_keys_list_offset,
                key_values_list_offset,
                security_key_offset,
                class_name_offset,
                largest_sub_key_name_size,
                largest_sub_key_class_name_size,
                largest_value_name_size,
                largest_value_data_size,
                work_var,
                key_name_size,
                class_name_size,
            },
            flags,
            last_key_written_date_and_time: timestamp.unwrap(),
            access_bits: AccessFlags::from_bits(access_bits).unwrap_or_default(),
            parent_key_offset,
            number_of_sub_keys,
            number_of_key_values,
            key_name,
            allocated: size < 0,
            path,
            sub_keys: Vec::new(),
            sub_values: Vec::new(),
            parse_warnings: Warnings::new()
        };

        Ok((
            input,
            cell_key_node
        ))
    }

    pub fn read<'a>(
        state: &State,
        input: &'a [u8],
        cur_path: String,
        filter: &mut Filter
    ) -> Result<Option<Self>, Error> {
        let (_, mut cell_key_node) = CellKeyNode::from_bytes(state, input, cur_path.clone())?;
        let filter_flags = filter.check_cell(cur_path.is_empty(), &cell_key_node)?;
        if filter_flags.contains(FilterFlags::FILTER_NO_MATCH) {
            return Ok(None);
        }
        if filter_flags.contains(FilterFlags::FILTER_ITERATE_KEYS) && cell_key_node.number_of_sub_keys > 0 {
            cell_key_node.read_sub_keys(state, filter)?;
        }
        if filter_flags.contains(FilterFlags::FILTER_ITERATE_VALUES) && cell_key_node.number_of_key_values > 0 {
            cell_key_node.read_values(state, filter)?;
        }
        if filter_flags.contains(FilterFlags::FILTER_ITERATE_KEYS_COMPLETE) {
            filter.is_complete = true;
        }
        return Ok(Some(cell_key_node));
    }

    /// Returns a vector of Security Descriptors for the key node.
    pub fn read_security_key(
        self: &mut CellKeyNode,
        file_buffer: &[u8],
        hbin_offset: u32
    ) -> Result<Vec<SecurityDescriptor>, Error> {
        match cell_key_security::read_cell_key_security(file_buffer, self.detail.security_key_offset, hbin_offset) {
            Ok(security_descriptors) => Ok(security_descriptors),
            Err(e) => Err(e)
        }
    }

    fn read_sub_keys(
        self: &mut CellKeyNode,
        state: &State,
        filter: &mut Filter
    ) -> Result<Vec<u32>, Error> {
        let (_, cell_sub_key_offset_list) = parse_sub_key_list(state, self.number_of_sub_keys, self.detail.sub_keys_list_offset, &mut self.parse_warnings)?;
        for val in cell_sub_key_offset_list.iter() {
            match CellKeyNode::read(state, &state.file_buffer[(*val as usize)..], self.path.clone(), filter) {
                Ok(key_node) =>
                    match key_node {
                        Some(kn) =>
                        {
                            self.sub_keys.push(kn);
                        },
                        None => continue
                    },
                Err(e) => return Err(Error::Any {
                    detail: format!("read_sub_keys: hive_bin_header::read_cell_key_node {:#?}", e)
                })
            };
            if filter.is_complete {
                break;
            }
        }
        Ok(cell_sub_key_offset_list)
    }

    fn read_values(
        self: &mut CellKeyNode,
        state: &State,
        filter: &mut Filter
    ) -> Result<(), Error> {
        let (_, key_values) = parse_key_values(state, self.number_of_key_values, self.detail.key_values_list_offset as usize)?;
        for val in key_values.iter() {
            let (_, mut cell_key_value) = CellKeyValue::from_bytes(state, &state.file_buffer[(*val as usize + state.hbin_offset)..])?;
            let res_iterate_flags = filter.check_cell(true, &cell_key_value);
            match res_iterate_flags {
                Ok(iterate_flags) => {
                    if iterate_flags.contains(FilterFlags::FILTER_ITERATE_KEYS_COMPLETE) {
                        filter.is_complete = true;
                    }
                    if !iterate_flags.contains(FilterFlags::FILTER_NO_MATCH) {
                        let warnings = cell_key_value.read_content(state);
                        self.sub_values.push(cell_key_value);
                    }
                }
                Err(e) => return Err(Error::Any {
                    detail: format!("read_values: filter.check_cell {:#?}", e)
                })
            }
        }
        Ok(())
    }
}

bitflags! {
    #[allow(non_camel_case_types)]
    #[derive(Default)]
    pub struct AccessFlags: u32 {
        const ACCESSED_BEFORE_INIT = 0x00000001; // This key was accessed before a Windows registry was initialized with the NtInitializeRegistry() routine during the boot
        const ACCESSED_AFTER_INIT  = 0x00000002; // This key was accessed after a Windows registry was initialized with the NtInitializeRegistry() routine during the boot
    }
}
impl_serialize_for_bitflags! {AccessFlags}

bitflags! {
    #[allow(non_camel_case_types)]
    #[derive(Default)]
    pub struct KeyNodeFlags: u16 {
        const KEY_VOLATILE       = 0x0001; // Is volatile (not used, a key node on a disk isn't expected to have this flag set)
        const KEY_HIVE_EXIT      = 0x0002; // Is the mount point of another hive (a key node on a disk isn't expected to have this flag set)
        const KEY_HIVE_ENTRY     = 0x0004; // Is the root key for this hive
        const KEY_NO_DELETE      = 0x0008; // This key can't be deleted
        const KEY_SYM_LINK       = 0x0010; // This key is a symlink (a target key is specified as a UTF-16LE string (REG_LINK) in a value named "SymbolicLinkValue", example: \REGISTRY\MACHINE\SOFTWARE\Classes\Wow6432Node)
        const KEY_COMP_NAME      = 0x0020; // Key name is an ASCII string, possibly an extended ASCII string (otherwise it is a UTF-16LE string)
        const KEY_PREDEF_HANDLE  = 0x0040; // Is a predefined handle (a handle is stored in the Number of key values field)
        const KEY_VIRTUAL_SOURCE = 0x0080; // This key was virtualized at least once
        const KEY_VIRTUAL_TARGET = 0x0100; // Is virtual
        const KEY_VIRTUAL_STORE  = 0x0200; // Is a part of a virtual store path
        const KEY_UNKNOWN1       = 0x1000;
        const KEY_UNKNOWN2       = 0x4000;
    }
}
impl_serialize_for_bitflags! {KeyNodeFlags}

fn parse_key_values<'a>(
    state: &'a State,
    key_values_count: u32,
    list_offset: usize
) -> IResult<&'a[u8], Vec<u32>> {
    let slice: &[u8] = &state.file_buffer[list_offset + state.hbin_offset..];
    let (slice, _size) = le_u32(slice)?;
    let (_, list) = count(le_u32, key_values_count as usize)(slice)?;
    Ok((
        slice,
        list
    ))
}

pub fn parse_sub_key_list<'a>(
    state: &'a State,
    count: u32,
    list_offset: u32,
    parse_warnings: &mut Warnings
) -> IResult<&'a[u8], Vec<u32>> {
    let slice = &state.file_buffer[list_offset as usize + state.hbin_offset..];
    // We either have an lf/lh/li list here (offsets to subkey lists), or an ri list (offsets to offsets...)
    // Look for the ri list first and follow the pointers
    let res_sub_key_list_ri = SubKeyListRi::from_bytes(slice);
    match res_sub_key_list_ri {
        Ok((_, sub_key_list_ri)) => {
            sub_key_list_ri.parse_offsets(state)
        },
        Err(_) => {
            let (remaining, cell_sub_key_list) =
                alt((SubKeyListLf::from_bytes(),
                     SubKeyListLh::from_bytes(),
                     SubKeyListLi::from_bytes(),
                    ))(slice)?;
            let list = cell_sub_key_list.get_offset_list(state.hbin_offset as u32, parse_warnings);
            if count > 0 { assert_eq!(list.len(), count as usize, "SubKeyList offset list doesn't match expected count"); }
            Ok((
                remaining,
                list
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::ErrorKind;
    use crate::filter::FindPath;

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_kv_filter() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4128..4264];
        let mut filter = Filter {
            find_path: Some(FindPath::new("Control Panel/Accessibility/HighContrast", Some(String::from("Flags")))),
            is_complete: false
        };
        let state = State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset: 4096,
            file_buffer: &f[..]
        };
        let ret = CellKeyNode::read(&state, slice, String::new(), &mut filter);
        let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().unwrap(), 0, 0);
        assert_eq!(
            (3, 1),
            (keys, values)
        );
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_key_filter() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4128..4264];
        let mut filter = Filter {
            find_path: Some(FindPath::new("Software/Microsoft/Office/14.0/Common", None)),
            is_complete: false
        };
        let state = State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset: 4096,
            file_buffer: &f[..]
        };
        let ret = CellKeyNode::read(&state, slice, String::new(), &mut filter);

        let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().unwrap(), 0, 0);
        assert_eq!(
            (44, 304),
            (keys, values)
        );
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4128..4264];
        let state = State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset: 4096,
            file_buffer: &f[..]
        };
        let ret = CellKeyNode::read(&state, slice, String::new(), &mut Filter { ..Default::default() });
        let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().unwrap(), 0, 0);
        assert_eq!(
            (2287, 5470),
            (keys, values)
        );
    }

    #[test]
    fn test_parse_cell_key_node() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4128..4264];

        let state = State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset: 4096,
            file_buffer: &f[..]
        };
        let ret = CellKeyNode::from_bytes(&state, slice, String::new());
        let expected_output = CellKeyNode {
            detail: CellKeyNodeDetail {
                absolute_file_offset: 4128,
                size: 136,
                number_of_volatile_sub_keys: 2,
                sub_keys_list_offset: 73256,
                volatile_sub_keys_list_offset: -2147476312,
                key_values_list_offset: -1,
                security_key_offset: 1376,
                class_name_offset: -1,
                largest_sub_key_name_size: 40,
                largest_sub_key_class_name_size: 0,
                largest_value_name_size: 0,
                largest_value_data_size: 0,
                work_var: 7667779,
                key_name_size: 52,
                class_name_size: 0,
            },
            flags: KeyNodeFlags::KEY_HIVE_ENTRY | KeyNodeFlags::KEY_NO_DELETE | KeyNodeFlags::KEY_COMP_NAME,
            last_key_written_date_and_time: util::get_date_time_from_filetime(129782011451468083).unwrap(),
            access_bits: AccessFlags::empty(),
            parent_key_offset: 1536,
            number_of_sub_keys: 11,
            number_of_key_values: 0,
            key_name: "CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}".to_string(),
            allocated: true,
            path: String::from("\\CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}"),
            sub_keys: Vec::new(),
            sub_values: Vec::new(),
            parse_warnings: Warnings::new()
        };
        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_output));
        assert_eq!(
            expected,
            ret
        );

        let slice = &f[0..10];
        let ret = CellKeyNode::from_bytes(&state, slice, String::new());
        let remaining = &f[4..10];
        let expected_error = Err(nom::Err::Error(nom::error::Error {input: remaining, code: ErrorKind::Tag}));
        assert_eq!(
            expected_error,
            ret
        );
    }
}