use nom::{
    IResult,
    Finish,
    bytes::complete::tag,
    bytes::streaming::take,
    number::complete::{le_u32, le_i32, le_u64},
};
use std::convert::TryFrom;
use chrono::{DateTime, Utc};
use serde::Serialize;
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use winstructs::guid::Guid;
use crate::util;
use crate::warn::Warnings;
use crate::filter::Filter;
use crate::registry::Registry;


#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive, Serialize)]
#[repr(u32)]
pub enum FileType {
    Normal = 0,
    TransactionLog = 1,
    Unknown = 0x0fffffff // todo: log warning
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive, Serialize)]
#[repr(u32)]
pub enum FileFormat {
    DirectMemoryLoad = 1,
    Unknown = 0x0fffffff // todo: log warning
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct FileBaseBlock {
    pub primary_sequence_number: u32,
    pub secondary_sequence_number: u32,
    pub last_modification_date_and_time: DateTime<Utc>,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: FileType,
    pub format: FileFormat,
    pub root_cell_offset: i32,
    pub hive_bins_data_size: u32,
    pub clustering_factor: u32, // Logical sector size of the underlying disk in bytes divided by 512
    pub filename: String, // UTF-16LE string (contains a partial file path to the primary file, or a file name of the primary file), used for debugging purposes
    pub unk2: Vec<u8>,
    pub checksum: u32, // XOR-32 checksum of the previous 508 bytes
    pub reserved: FileBaseBlockReserved,
    pub boot_type: u32,
    pub boot_recover: u32,
    pub parse_warnings: Warnings
}

impl FileBaseBlock {
    /// Uses nom to parse the registry file header.
    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _signature) = tag("regf")(input)?;
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
        let (input, reserved) = FileBaseBlockReserved::from_bytes(input)?;
        let (input, boot_type) = le_u32(input)?;
        let (input, boot_recover) = le_u32(input)?;

        let filename = util::read_utf16_le_string(filename_bytes, 64);

        let file_type = match FileType::from_u32(file_type_bytes) {
            Some(file_type) => file_type,
            None => FileType::Unknown
        };
        let format = match FileFormat::from_u32(format_bytes) {
            Some(format) => format,
            None => FileFormat::Unknown
        };
        let modification_date = util::get_date_time_from_filetime(last_modification_date_and_time).unwrap();
        let mut parse_warnings = Warnings::new();
        Ok((
            input,
            FileBaseBlock {
                primary_sequence_number,
                secondary_sequence_number,
                last_modification_date_and_time: modification_date,
                major_version,
                minor_version,
                file_type,
                format,
                root_cell_offset,
                hive_bins_data_size,
                clustering_factor,
                filename,
                unk2: unk2.to_vec(),
                checksum,
                reserved,
                boot_type,
                boot_recover,
                parse_warnings
            },
        ))
    }
}

// Relevant to win10+. See https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#base-block for additional info in this area
#[derive(Debug, Serialize)]
pub struct FileBaseBlockReserved {
    pub rm_id: Guid,
    pub log_id: Guid,
    pub flags: FileBaseBlockReservedFlags,
    pub tm_id: Guid,
    pub signature: u32,
    pub last_reorganized_timestamp: DateTime<Utc>,
    pub remaining: Vec<u8>//[u8; 3576],
}

impl Eq for FileBaseBlockReserved {}

impl PartialEq for FileBaseBlockReserved {
    fn eq(&self, other: &Self) -> bool {
        self.rm_id == other.rm_id &&
        self.log_id == other.log_id &&
        self.flags == other.flags &&
        self.tm_id == other.tm_id &&
        self.signature == other.signature &&
        self.last_reorganized_timestamp == other.last_reorganized_timestamp &&
        self.remaining == other.remaining
    }
}

impl FileBaseBlockReserved {
    /// Uses nom to parse the file base block reserved structure.
    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, rm_id) = take(16usize)(input)?;
        let (input, log_id) = take(16usize)(input)?;
        let (input, flags) = le_u32(input)?;
        let (input, tm_id) = take(16usize)(input)?;
        let (input, signature) = take(4usize)(input)?;
        let (input, last_reorganized_timestamp) = le_u64(input)?;
        let (input, remaining) = take(3512usize)(input)?;

        let flags = match FileBaseBlockReservedFlags::from_u32(flags) {
            None => FileBaseBlockReservedFlags::None,
            Some(flags) => flags
        };
        let last_reorganized_timestamp = util::get_date_time_from_filetime(last_reorganized_timestamp).unwrap();
        Ok((
            input,
            FileBaseBlockReserved {
                rm_id: Guid::from_buffer(rm_id).unwrap(),
                log_id: Guid::from_buffer(log_id).unwrap(),
                flags,
                tm_id: Guid::from_buffer(tm_id).unwrap(),
                signature: 1,// signature as u32,
                last_reorganized_timestamp,
                remaining: remaining.to_vec()
            },
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive, Serialize)]
#[repr(u32)]
pub enum FileBaseBlockReservedFlags {
    None = 0,
    KtmLockedHive = 1, // KTM locked the hive (there are pending or anticipated transactions)
    Ktm2 = 2 // The hive has been defragmented (all its pages are dirty therefore) and it is being written to a disk (Windows 8 and Windows Server 2012 only, this flag is used to speed up hive recovery by reading a transaction log file instead of a primary file); this hive supports the layered keys feature (starting from Insider Preview builds of Windows 10 "Redstone 1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::ErrorKind;
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use crate::filter::FindPath;

    #[test]
    fn test_read_big_reg() {
        let f = std::fs::read("test_data/SOFTWARE_1_nfury").unwrap();
        let mut filter = Filter {
            ..Default::default()
        };
        let ret = Registry::from_bytes(&f[..], &mut filter);
        let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().hive_bin_root.unwrap().root, 0, 0);
        assert_eq!(
            (177876, 293276),
            (keys, values)
        );
    }

    #[test]
    fn test_read_small_reg() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let mut filter = Filter {
            ..Default::default()
        };
        let ret = Registry::from_bytes(&f[..], &mut filter);
        let (keys, values) = util::count_all_keys_and_values(&ret.unwrap().hive_bin_root.unwrap().root, 0, 0);
        assert_eq!(
            (2287, 5470),
            (keys, values)
        );
    }

    #[test]
    fn test_read_base_block() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let mut filter = Filter {
            find_path: Some(FindPath::new("Control Panel/Accessibility/HighContrast", Some(String::from("Flags")))),
            is_complete: false
        };
        let ret = Registry::from_bytes(&f[0..], &mut filter);
    }

    #[test]
    fn test_parse_base_block() {
        let mut unk2: Vec<u8> = [188, 136, 104, 1, 111, 108, 222, 17, 141, 29, 0, 30, 11, 205, 227, 236, 188, 136, 104, 1, 111, 108, 222, 17, 141, 29, 0, 30, 11, 205, 227, 236, 0, 0, 0, 0, 189, 136, 104, 1, 111, 108, 222, 17, 141, 29, 0, 30, 11, 205, 227, 236, 114, 109, 116, 109].to_vec();
        unk2.extend([0; 340].iter().copied());

        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let ret = FileBaseBlock::from_bytes(&f[0..4096]);
        let expected_header = FileBaseBlock {
            primary_sequence_number: 10407,
            secondary_sequence_number: 10407,
            last_modification_date_and_time: util::get_date_time_from_filetime(129782121007374460).unwrap(),
            major_version: 1,
            minor_version: 3,
            file_type: FileType::Normal,
            format: FileFormat::DirectMemoryLoad,
            root_cell_offset: 32,
            hive_bins_data_size: 1060864,
            clustering_factor: 1,
            filename: "\\??\\C:\\Users\\nfury\\ntuser.dat".to_string(),
            unk2,
            checksum: 738555936,
            reserved: FileBaseBlockReserved::from_bytes(&[0; 3576]).finish().unwrap().1,
            boot_type: 0,
            boot_recover: 0,
            parse_warnings: Warnings::new()
        };
        let remaining: [u8; 0] = [0; 0];
        let expected = Ok((&remaining[..], expected_header));
        assert_eq!(
            expected,
            ret
        );

        let ret = FileBaseBlock::from_bytes(&f[0..10]);
        let remaining = &f[8..10];
        let expected_error = Err(nom::Err::Error(nom::error::Error {input: remaining, code: ErrorKind::Eof}));
        assert_eq!(
            expected_error,
            ret
        );
    }

    #[test]
    fn dump_registry() {
        let f = std::fs::read("test_data/FuseHive").unwrap();
        let mut filter = Filter {
            ..Default::default()
        };
        let ret = Registry::from_bytes(&f[..], &mut filter);

        let write_file = File::create("out.txt").unwrap();
        let mut writer = BufWriter::new(&write_file);
        write!(&mut writer, "{}", serde_json::to_string_pretty(&ret.unwrap()).unwrap());
    }
}
