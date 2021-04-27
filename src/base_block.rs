use nom::{
    IResult,
    Finish,
    bytes::complete::tag,
    bytes::streaming::take,
    combinator::map_opt,
    number::complete::{le_u32, le_i32, le_u64},
    error::ErrorKind
};
use std::convert::{TryFrom, TryInto};
use std::mem::size_of;
use bitflags::bitflags;
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use crate::util;
use crate::hive_bin_cell;
use std::path::{PathBuf};
use crate::hive_bin;
use crate::hive_bin_header;
use crate::hive_bin_cell_key_node;
use crate::filter;
use crate::err::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
#[repr(u32)] 
pub enum FileType {
    Normal = 0,
    TransactionLog = 1,
    Unknown = 0x0fffffff
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
#[repr(u32)]
pub enum FileFormat {
    DirectMemoryLoad = 1,
    Unknown = 0x0fffffff
}

#[derive(Debug, Eq, PartialEq)]
pub struct Registry {
    pub header: FileBaseBlock,
    pub hive_bin_root: Option<hive_bin::HiveBin>
}

#[derive(Debug, Eq, PartialEq)]
pub struct FileBaseBlock {
    pub signature: [u8; 4],
    pub primary_sequence_number: u32,
    pub secondary_sequence_number: u32,
    pub last_modification_date_and_time: u64, // Filetime
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: FileType,
    pub format: FileFormat,
    pub root_cell_offset: i32,
    pub hive_bins_data_size: u32,
    pub clustering_factor: u32, // Logical sector size of the underlying disk in bytes divided by 512
    pub filename: String, // UTF-16LE string (contains a partial file path to the primary file, or a file name of the primary file), used for debugging purposes
    pub unk2: [u8; 396],
    pub checksum: u32, // XOR-32 checksum of the previous 508 bytes
    pub reserved: [u8; 3576], // see https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#base-block for additional info in this area
    pub boot_type: u32,
    pub boot_recover: u32,  
}

// relevant to win10+
#[derive(Debug, Eq, PartialEq)]
pub struct FileBaseBlockReserved {
    pub rm_id: [u8; 16], // guid
    pub log_id: [u8; 16], // guid
    pub flags: FileBaseBlockReservedFlags,
    pub tm_id: [u8; 16], // guid
    pub signature: [u8; 4],
    pub last_reorganized_timestamp: u64, // Filetime
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FileBaseBlockReservedFlags {
    KtmLockedHive = 1, // KTM locked the hive (there are pending or anticipated transactions)
    Ktm2 = 2 // The hive has been defragmented (all its pages are dirty therefore) and it is being written to a disk (Windows 8 and Windows Server 2012 only, this flag is used to speed up hive recovery by reading a transaction log file instead of a primary file); this hive supports the layered keys feature (starting from Insider Preview builds of Windows 10 "Redstone 1")
}

/// Reads a Windows registry; returns a Registry object containing the information from the header and a tree of parsed hive bins
pub fn read_registry<'a>(
    file_buffer: &[u8], 
    filter: &mut filter::Filter
) -> Result<Registry, Error> {
    match parse_base_block(file_buffer).finish() {
    Ok((input, file_base_block)) => {
            let ret = hive_bin::read_hive_bin(&input, file_buffer, PathBuf::new(), filter);
            match ret { 
                Ok(hive_bin) => 
                    Ok(Registry {
                        header: file_base_block,
                        hive_bin_root: hive_bin
                    }),
                Err(e) => Err(e)
            }
        },
        Err(e) => return Err(Error::Nom {
            detail: format!("read_registry: parse_base_block {:#?}", e)        
        })
    }
}

/// Uses nom to parse the registry file header.
fn parse_base_block<'a>(input: &'a [u8]) -> IResult<&'a [u8], FileBaseBlock> {
    let (input, signature) = tag("regf")(input)?;
    let (input, primary_sequence_number) = le_u32(input)?;
    let (input, secondary_sequence_number) = le_u32(input)?;
    let (input, last_modification_date_and_time) = le_u64(input)?;
    let (input, major_version) = le_u32(input)?;
    let (input, minor_version) = le_u32(input)?;
    let (input, file_type_bytes) = le_u32(input)?;
    let (input, format_bytes) = le_u32(input)?;
    let (input, root_cell_offset) = le_i32(input)?;
    let (input, hive_bins_data_size) = le_u32(input)?;
    let (input, clustering_factor) = le_u32(input)?;
    let (input, filename_bytes) = take(64usize)(input)?;
    let (input, unk2) = take(396usize)(input)?;
    let (input, checksum) = le_u32(input)?;
    let (input, reserved) = take(3576usize)(input)?;
    let (input, boot_type) = le_u32(input)?;
    let (input, boot_recover) = le_u32(input)?;
    
    let filename = util::read_utf16_le_string(filename_bytes, 32).unwrap();
        
    let file_type = match FileType::from_u32(file_type_bytes) {
        Some(file_type) => file_type,
        None => FileType::Unknown
    };        
    let format = match FileFormat::from_u32(format_bytes) {
        Some(format) => format,
        None => FileFormat::Unknown
    };

    Ok((
        input,
        FileBaseBlock {
            signature: <[u8; 4]>::try_from(signature).unwrap(),
            primary_sequence_number,
            secondary_sequence_number,
            last_modification_date_and_time,
            major_version,
            minor_version,
            file_type,
            format,
            root_cell_offset,
            hive_bins_data_size,
            clustering_factor,
            filename: filename,
            unk2: <[u8; 396]>::try_from(unk2).unwrap(),
            checksum,
            reserved: <[u8; 3576]>::try_from(reserved).unwrap(),
            boot_type,
            boot_recover
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_read_big_reg() {
        let f = std::fs::read("test_data/SOFTWARE_1_nfury").unwrap();

        let mut filter = filter::Filter {        
            ..Default::default()
        };
        let ret = read_registry(&f[..], &mut filter);
        /*let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().hive_bin_root.unwrap().root, 0, 0);
        assert_eq!(
            (177876, 293276),
            (keys, values)
        );*/
        //println!("{:?}", ret.unwrap());
    }
    
    #[test]
    fn test_read_small_reg() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let mut filter = filter::Filter {        
            ..Default::default()
        };
        let ret = read_registry(&f[..], &mut filter);
        /*let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().hive_bin_root.unwrap().root, 0, 0);
        assert_eq!(
            (177876, 293276),
            (keys, values)
        );*/
        //println!("{:?}", ret.unwrap());
    }
        
    #[test]
    fn test_read_base_block() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let mut filter = filter::Filter {        
            find_path: Some(filter::FindPath::build("Control Panel/Accessibility/HighContrast", Some(String::from("Flags")))),
            is_complete: false
        };
        let ret = read_registry(&f[0..], &mut filter);
        println!("{:?}", ret.unwrap());
    }

    #[test]
    fn test_parse_base_block() {
        let mut reserved: Vec<u8> = Vec::new();
        reserved.extend([188, 136, 104, 1, 111, 108, 222, 17, 141, 29, 0, 30, 11, 205, 227, 236, 188, 136, 104, 1, 111, 108, 222, 17, 141, 29, 0, 30, 11, 205, 227, 236, 0, 0, 0, 0, 189, 136, 104, 1, 111, 108, 222, 17, 141, 29, 0, 30, 11, 205, 227, 236, 114, 109, 116, 109].iter().copied());
        let reserved_zero:[u8; 340] = [0; 340];
        reserved.extend(reserved_zero.iter().copied());

        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let ret = parse_base_block(&f[0..4096]);
        let expected_header = FileBaseBlock {
            signature: [114, 101, 103, 102],
            primary_sequence_number: 10407,
            secondary_sequence_number: 10407,
            last_modification_date_and_time: 129782121007374460,
            major_version: 1,
            minor_version: 3,
            file_type: FileType::Normal,
            format: FileFormat::DirectMemoryLoad,
            root_cell_offset: 32,
            hive_bins_data_size: 1060864,
            clustering_factor: 1,
            filename: "\\??\\C:\\Users\\nfury\\ntuser.dat".to_string(),
            unk2: <[u8; 396]>::try_from(reserved).unwrap(),
            checksum: 738555936,
            reserved: [0; 3576],
            boot_type: 0,
            boot_recover: 0,
        };
        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_header));
        assert_eq!(
            expected,
            ret
        );

        let ret = parse_base_block(&f[0..10]);
        let remaining = &f[8..10];
        let expected_error = Err(nom::Err::Error(nom::error::Error {input: remaining, code: ErrorKind::Eof}));
        assert_eq!(
            expected_error,
            ret
        );
    }
}
