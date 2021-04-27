use nom::{
    IResult,
    Finish,
    bytes::complete::tag,
    number::complete::{le_u16, le_u32, le_i32, le_u64},
    error::{ErrorKind, make_error},
    branch::alt,
    multi::count
};
use std::convert::TryFrom;
use bitflags::bitflags;
use std::path::PathBuf;
use winstructs::security::SecurityDescriptor;
use crate::err;
use crate::err::Error;
use crate::util;
use crate::util::PathBufExt;
use crate::hive_bin_cell;
use crate::hive_bin_cell_key_value;
use crate::hive_bin_cell_key_security;
use crate::sub_key_list_lf;
use crate::sub_key_list_lh;
use crate::sub_key_list_li;
use crate::sub_key_list_ri;
use crate::filter;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct HiveBinCellKeyNode {
    pub size: u32,
    pub signature: [u8; 2], // "nk"
    pub flags: KeyNodeFlags,
    pub last_key_written_date_and_time: u64, // filetime
    /* 0x1	This key was accessed before a Windows registry was initialized with the NtInitializeRegistry() routine during the boot
       0x2	This key was accessed after a Windows registry was initialized with the NtInitializeRegistry() routine during the boot */   
    pub access_bits: u32, // Bit mask (this field is used as of Windows 8 and Windows Server 2012; in previous versions of Windows, this field is reserved and called Spare)
    pub parent_key_offset: i32, // Offset of a parent key node in bytes, relative from the start of the hive bins data (this field has no meaning on a disk for a root key node)
    pub number_of_sub_keys: u32,
    pub number_of_volatile_sub_keys: u32, // The offset value is in bytes and relative from the start of the hive bin data / Refers to a sub keys list or contains -1 (0xffffffff) if empty.
    pub sub_keys_list_offset: u32, // In bytes, relative from the start of the hive bins data (also, this field may point to an Index root)
    pub volatile_sub_keys_list_offset: i32, // This field has no meaning on a disk (volatile keys are not written to a file)
    pub number_of_key_values: u32,
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
    pub key_name: String, // ASCII (extended) string or UTF-16LE string,
    pub allocated: bool,
    pub path: PathBuf,
    pub sub_keys: Vec<HiveBinCellKeyNode>,
    pub sub_values: Vec<hive_bin_cell_key_value::HiveBinCellKeyValue>,
    pub parse_warnings: Vec<String>
}  

impl hive_bin_cell::HiveBinCell for HiveBinCellKeyNode {    
    fn size(&self) -> u32 {
        self.size
    }

    fn signature(&self) -> [u8;2] {
        self.signature
    }

    fn name_lowercase(&self) -> Option<String> {
        Some(self.key_name.clone().to_ascii_lowercase())
    }
}

impl err::ParseWarnings for HiveBinCellKeyNode {    
    fn add_warning(&mut self, warning: String) {
        self.parse_warnings.push(warning);
    }

    fn get_warnings(&self) -> &Vec<String> {
        &self.parse_warnings
    }
}

impl HiveBinCellKeyNode {
    /// Returns a vector of Security Descriptors for the key node.
    pub fn read_security_key<'a>(
        self: &mut HiveBinCellKeyNode, 
        file_buffer: &'a [u8], 
        hbin_offset: u32
    ) -> Result<Vec<SecurityDescriptor>, Error> {
        match hive_bin_cell_key_security::read_hive_bin_cell_key_security(file_buffer, self.security_key_offset, hbin_offset) {
            Ok(security_descriptors) => Ok(security_descriptors),
            Err(e) => Err(e)
        }
    }

    fn read_sub_keys<'a>(
        self: &mut HiveBinCellKeyNode, 
        file_buffer: &'a [u8], 
        hbin_offset: u32, 
        filter: &mut filter::Filter
    ) -> Result<Vec<u32>, Error> {
        match parse_sub_key_list(file_buffer, self.number_of_sub_keys, self.sub_keys_list_offset, hbin_offset) {
            Ok((_, hive_bin_cell_sub_key_offset_list)) => {
                for val in hive_bin_cell_sub_key_offset_list.iter() {
                    match read_hive_bin_cell_key_node(&file_buffer[(*val as usize)..], file_buffer, hbin_offset, self.path.clone(), filter) {
                        Ok(key_value) => 
                            match key_value {
                                Some(kv) => self.sub_keys.push(kv),
                                None => continue
                            },
                        Err(e) => return Err(Error::Any {
                            detail: format!("read_sub_keys: hive_bin_header::read_hive_bin_cell_key_node {:#?}", e)
                        })
                    };   
                    if filter.is_complete {
                        break;
                    }
                }
                Ok(hive_bin_cell_sub_key_offset_list)
            },
            Err(e) => return Err(Error::Nom {
                detail: format!("read_sub_keys: hive_bin_header::parse_sub_key_list {:#?}", e)
            })
        }
    }

    fn read_values<'a>(
        self: &mut HiveBinCellKeyNode, 
        file_buffer: &'a [u8], 
        hbin_offset: u32, 
        filter: &mut filter::Filter
    ) -> Result<(), Error> {
        match parse_key_values(file_buffer, self.number_of_key_values, self.key_values_list_offset as usize, hbin_offset).finish() {
            Ok((_, key_values)) => {
                for val in key_values.iter() {
                    // move get_content out of parse_hive_bin_cell_key_value so we don't call that if the filter doesn't match
                    let nom_ret_parse_cell_key_value = hive_bin_cell_key_value::parse_hive_bin_cell_key_value(&file_buffer[((*val + hbin_offset)as usize)..], file_buffer, hbin_offset);
                    match nom_ret_parse_cell_key_value {
                        Ok(parse_cell_key_value) => {
                            let cell_key_value = parse_cell_key_value.1;
                            let ret = filter.check_cell(true, &cell_key_value);
                            match ret {
                                Ok(iterate_flags) => {   
                                    if iterate_flags.contains(filter::FilterFlags::FILTER_ITERATE_COMPLETE) {                                    
                                        self.sub_values.push(cell_key_value);
                                        filter.is_complete = true;
                                        break;
                                    }
                                }
                                Err(e) => return Err(Error::Nom {
                                    detail: format!("read_values: filter.check_cell {:#?}", e)
                                })
                            };                   
                            self.sub_values.push(cell_key_value);
                        },
                        Err(e) => return Err(Error::Nom {
                            detail: format!("read_values: hive_bin_cell_key_value::parse_hive_bin_cell_key_value {:#?}", e)
                        })
                    }
                }
                return Ok(());
            },
            Err(e) => return Err(Error::Nom {
                detail: format!("read_values: parse_key_values {:#?}", e)
            })
        }
    }   
}

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

fn parse_key_values<'a>(
    file_buffer: &'a [u8], 
    key_values_count: u32, 
    list_offset: usize, 
    hbin_offset: u32
) -> IResult<&'a [u8], Vec<u32>> {
    let slice: &[u8] = &file_buffer[list_offset + (hbin_offset as usize)..];
    let (slice, size) = le_u32(slice)?;
    let (_, list) = count(le_u32, key_values_count as usize)(slice)?;

    for val in list.iter() {
        let (input, key_value) = hive_bin_cell_key_value::parse_hive_bin_cell_key_value(&file_buffer[((*val + hbin_offset)as usize)..], file_buffer, hbin_offset)?;
    }
    
    Ok((
        slice,
        list
    ))
}

pub fn parse_sub_key_list(
    file_buffer: &[u8], 
    count: u32, 
    list_offset: u32, 
    hbin_offset: u32
) -> IResult<&[u8], Vec<u32>> {
    let slice = &file_buffer[list_offset as usize + hbin_offset as usize..];
    // we either have an lf/lh/li list here (offsets to subkey lists), or an ri list (offsets to offsets...)
    // We look for the ri list first and follow the 

    let res_sub_key_list_ri = sub_key_list_ri::parse_sub_key_list_ri(slice);
    match res_sub_key_list_ri {
        Ok((remaining, sub_key_list_ri)) => {
            let res_list = sub_key_list_ri.parse_offsets(file_buffer, hbin_offset);
            match res_list {
                Ok((_, list)) => {
                    Ok((
                        remaining,
                        list
                    ))
                },
                Err(e) => {return Err(e);}
            }
        },
        Err(_) => {
            let (remaining, hive_bin_cell_sub_key_list) =
                alt((sub_key_list_lf::parse_sub_key_list_lf(),
                    sub_key_list_lh::parse_sub_key_list_lh(),
                    sub_key_list_li::parse_sub_key_list_li(),
                    ))(slice).unwrap();
            let list = hive_bin_cell_sub_key_list.offsets(hbin_offset);
            if count > 0 { assert_eq!(list.len(), count as usize); }                
            Ok((
                remaining,
                list
            ))
        }
    }    
}

pub fn parse_hive_bin_cell_key_node(
    input: &[u8], 
    cur_path: PathBuf
) -> IResult<&[u8], HiveBinCellKeyNode> {
    let start_pos = input.as_ptr() as usize;
    let (input, size) = le_i32(input)?;
    let (input, signature) = tag("nk")(input)?;
    let (input, flags) = le_u16(input)?;
    let flags = KeyNodeFlags::from_bits(flags).unwrap();
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
    
    let key_name: String;
    if flags.contains(KeyNodeFlags::KEY_COMP_NAME) {
        key_name = String::from_utf8(key_name_bytes.to_vec()).unwrap();
    }
    else {
        let key_name_warning = util::read_utf16_le_string(key_name_bytes, (key_name_size / 2).into());
        key_name = key_name_warning.0;
    }
    
    let size_abs = size.abs() as u32;
    let (input, _) = util::parser_eat_remaining(input, size_abs as usize, input.as_ptr() as usize - start_pos)?;

    let path = cur_path.join(key_name.clone());
    let cell_key_node = HiveBinCellKeyNode {
        size: size_abs,
        signature: <[u8; 2]>::try_from(signature).unwrap(),
        flags,
        last_key_written_date_and_time,
        access_bits,
        parent_key_offset,
        number_of_sub_keys,
        number_of_volatile_sub_keys,
        sub_keys_list_offset,
        volatile_sub_keys_list_offset,
        number_of_key_values,
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
        key_name: key_name.clone(),
        allocated: size < 0,
        path: path.clone(),
        sub_keys: Vec::new(),
        sub_values: Vec::new(),
        parse_warnings: Vec::new(),
    };

    Ok((
        input,
        cell_key_node
    ))
}

pub fn read_hive_bin_cell_key_node<'a>(
    input: &'a [u8], 
    file_buffer: &[u8], 
    hbin_offset: u32, 
    cur_path: PathBuf, 
    filter: &mut filter::Filter
) -> Result<Option<HiveBinCellKeyNode>, Error> {
    match parse_hive_bin_cell_key_node(input, cur_path.clone()).finish() {
        Ok((_, mut hive_bin_cell_key_node)) => {
            let res_filter_flags = filter.check_cell(cur_path.is_empty(), &hive_bin_cell_key_node);
            match res_filter_flags {
                Ok(filter_flags) => {   
                    if filter_flags.contains(filter::FilterFlags::FILTER_NO_MATCH) {
                        return Ok(None);
                    } 
                    if filter_flags.contains(filter::FilterFlags::FILTER_ITERATE_KEYS) && hive_bin_cell_key_node.number_of_sub_keys > 0 {
                        hive_bin_cell_key_node.read_sub_keys(file_buffer, hbin_offset, filter);
                    }
                    if filter_flags.contains(filter::FilterFlags::FILTER_ITERATE_VALUES) && hive_bin_cell_key_node.number_of_key_values > 0 {
                       hive_bin_cell_key_node.read_values(file_buffer, hbin_offset, filter);
                    }
                    if filter_flags.contains(filter::FilterFlags::FILTER_ITERATE_COMPLETE) {
                        filter.is_complete = true;
                    }
                    return Ok(Some(hive_bin_cell_key_node));
                }
                Err(e) => return Err(Error::Any {
                    detail: format!("read_hive_bin_cell_key_node: filter.check_cell {:#?}", e)
                })
            };   
        },
        Err(e) => return Err(Error::Nom {
            detail: format!("read_hive_bin_cell_key_node: parse_hive_bin_cell_key_node {:#?}", e)
        })
    };
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hive_bin_cell_key_node_count_all_keys_and_values_with_kv_filter() {        
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4128..4264];             
        let mut filter = filter::Filter {        
            find_path: Some(filter::FindPath::build("Control Panel/Accessibility/HighContrast", Some(String::from("Flags")))),
            is_complete: false
        };
        let ret = read_hive_bin_cell_key_node(slice, &f[0..], 4096, PathBuf::new(), &mut filter);
        //let write_file = File::create("out.txt").unwrap();
        //let mut writer = BufWriter::new(&write_file);
        //write!(&mut writer, "{:#?}", ret.ok());

        let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().unwrap(), 0, 0);
        assert_eq!(
            (3, 1),
            (keys, values)
        );
    }
    #[test]
    fn test_hive_bin_cell_key_node_count_all_keys_and_values_with_key_filter() {        
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4128..4264];             
        let mut filter = filter::Filter {        
            find_path: Some(filter::FindPath::build("Software/Microsoft/Office/14.0/Common", None)),
            is_complete: false
        };
        let ret = read_hive_bin_cell_key_node(slice, &f[0..], 4096, PathBuf::new(), &mut filter);

        let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().unwrap(), 0, 0);
        assert_eq!(
            (44, 304),
            (keys, values)
        );
    }

    #[test]
    fn test_hive_bin_cell_key_node_count_all_keys_and_values() {        
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4128..4264];             
        let ret = read_hive_bin_cell_key_node(slice, &f[0..], 4096, PathBuf::new(), &mut filter::Filter { ..Default::default() });
        let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().unwrap(), 0, 0);
        assert_eq!(
            (2287, 5470),
            (keys, values)
        );
    }
        
    #[test]
    fn test_parse_hive_bin_cell_key_node() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let slice = &f[4128..4264];
        
        let ret = parse_hive_bin_cell_key_node(slice, PathBuf::new());        
        let expected_output = HiveBinCellKeyNode {
            size: 136,
            signature: [110, 107],
            flags: KeyNodeFlags::KEY_HIVE_ENTRY | KeyNodeFlags::KEY_NO_DELETE | KeyNodeFlags::KEY_COMP_NAME,
            last_key_written_date_and_time: 129782011451468083,
            access_bits: 0,
            parent_key_offset: 1536,
            number_of_sub_keys: 11,
            number_of_volatile_sub_keys: 2,
            sub_keys_list_offset: 73256,
            volatile_sub_keys_list_offset: -2147476312,
            number_of_key_values: 0,
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
            key_name: "CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}".to_string(),
            allocated: true,
            path: PathBuf::from("CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}"),
            sub_keys: Vec::new(),
            sub_values: Vec::new(),
            parse_warnings: Vec::new(),
        };
        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_output));
        assert_eq!(
            expected,
            ret
        );
        
        let slice = &f[0..10];
        let ret = parse_hive_bin_cell_key_node(slice, PathBuf::new());
        let remaining = &f[4..10];
        let expected_error = Err(nom::Err::Error(nom::error::Error {input: remaining, code: ErrorKind::Tag}));
        assert_eq!(
            expected_error,
            ret
        );
    }
}