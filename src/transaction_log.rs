use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u32, le_u64}
};
use serde::Serialize;
use crate::state::State;
use crate::base_block::FileBaseBlockBase;
use crate::util;
use crate::warn::Warnings;
use crate::marvin_hash;

// Structures based off https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-transaction-log-files

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DirtyPageRef {
    /// Offset of a page in a primary file (in bytes), relative from the start of the hive bins data
    pub offset: u32,
    //Size of a page in bytes
    pub size: u32
}

impl DirtyPageRef {
    fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        |input: &[u8]| {
            let (input, offset) = le_u32(input)?;
            let (input, size) = le_u32(input)?;
            Ok((input,
                Self {
                    offset,
                    size,
                }
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DirtyPage {
    pub dirty_page_ref: DirtyPageRef,
    pub page_bytes: Vec<u8>
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct LogEntry {
    /// The absolute offset of the hive bin, calculated at parse time
    pub file_offset_absolute: usize,
    /// Size of the log entry
    pub size: u32,
    /// Partial copy of the Flags field of the base block at the time of creation of a current log entry
    pub flags: u32,
    /// This number constitutes a possible value of the Primary sequence number and Secondary sequence number fields of the base block in memory after a current log entry is applied (these fields are not modified before the write operation on the recovered hive)
    pub sequence_number: u32,
    /// Copy of the Hive bins data size field of the base block at the time of creation of a current log entry
    pub hive_bin_data_size: u32,
    /// Number of dirty pages attached to a current log entry
    pub dirty_pages_count: u32,
    pub hash1: u64,
    pub hash2: u64,
    pub dirty_pages: Vec<DirtyPage>
}

impl LogEntry {
    pub fn from_bytes(file_start_pos: usize) -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        move |input: &[u8]| {
            LogEntry::from_bytes_internal(file_start_pos, input)
        }
    }

    fn from_bytes_internal(file_start_pos: usize, input: &[u8]) -> IResult<&[u8], Self> {
        let start = input;
        let file_offset_absolute = input.as_ptr() as usize - file_start_pos;
        let (input, _signature) = tag("HvLE")(input)?;
        let (input, size) = le_u32(input)?;
        let (input, flags) = le_u32(input)?;
        let (input, sequence_number) = le_u32(input)?;
        let (input, hive_bin_data_size) = le_u32(input)?;
        let (input, dirty_pages_count) = le_u32(input)?;
        let (input, hash1) = le_u64(input)?;
        let (input, hash2) = le_u64(input)?;
        let (mut input, dirty_page_refs) = nom::multi::count(DirtyPageRef::from_bytes(), dirty_pages_count as usize)(input)?;

        let mut dirty_pages = Vec::new();
        for dirty_page_ref in dirty_page_refs {
            let res = nom::bytes::complete::take(dirty_page_ref.size)(input)?;
            input = res.0;
            dirty_pages.push(
                DirtyPage {
                    dirty_page_ref,
                    page_bytes: res.1.to_vec()
                }
            );
        }
        let (input, _) = util::parser_eat_remaining(input, size, input.as_ptr() as usize - file_start_pos - file_offset_absolute)?;
        //let hash2 = Self::calc_hash2(start);
        //let hash1 = Self::calc_hash1(start, size as usize);

        let hbh = Self {
            file_offset_absolute,
            size,
            flags,
            sequence_number,
            hive_bin_data_size,
            dirty_pages_count,
            hash1,
            hash2,
            dirty_pages
        };

        Ok((
            input,
            hbh
        ))
    }

    //pub fn has_valid_hashes(&self, raw_bytes: &[u8]) -> bool {
    //    self.hash1 == LogEntry::calc_hash1(raw_bytes) && self.hash2 == LogEntry::calc_hash2(raw_bytes)
    //}

    pub fn calc_hash1(raw_bytes: &[u8], len: usize) -> u64 {
       // var b = new byte[_rawBytes.Length - 40];
        let mut b = vec![0; len - 40];//Vec::with_capacity(len - 40);
        let dst = &mut b[0..len-40];
        let src = &raw_bytes[40..len];
        dst.copy_from_slice(src);
        let aaa =  marvin_hash::compute_hash(dst, (len - 40) as u32, marvin_hash::DEFAULT_SEED);
        aaa
    }

    pub fn calc_hash2(raw_bytes: &[u8]) -> u64 {
        let len = 32;
        let mut b = vec![0; len];//Vec::with_capacity(len);
        let dst = &mut b[0..len];
        let src = &raw_bytes[0..len];
        dst.copy_from_slice(src);
        let aaa =  marvin_hash::compute_hash(dst, len as u32, marvin_hash::DEFAULT_SEED);

        aaa
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct TransactionLog {
    pub base_block: FileBaseBlockBase,
    log_entries: Vec<LogEntry>
}

impl TransactionLog {
    pub fn from_bytes(file_start_pos: usize, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, base_block) = FileBaseBlockBase::from_bytes(input)?;
        let (input, log_entries) = nom::multi::many0(LogEntry::from_bytes(file_start_pos))(input)?;

        Ok((
            input,
            Self {
                base_block,
                log_entries
            }
        ))
    }

    /// Updates the primary registry with the dirty pages. Returns the last sequence number applied
    pub fn update_bytes(&self, primary_file: &mut[u8]) -> u32 {
        let baseOffset = 4096;
        let mut new_sequence_number = 0;
        for log_entry in &self.log_entries {
            //if transactionLogEntry.HasValidHashes() == false {
                //Logger.Debug($"Skipping transaction log entry with sequence # 0x{transactionLogEntry.SequenceNumber:X}. Hash verification failed");
                //continue;
            //}

            new_sequence_number = log_entry.sequence_number;

            for dirty_page in &log_entry.dirty_pages {
                let dst_offset = dirty_page.dirty_page_ref.offset + baseOffset;
                let dst = &mut primary_file[dst_offset as usize..(dst_offset + dirty_page.dirty_page_ref.size) as usize];
                let src = &dirty_page.page_bytes[..dirty_page.dirty_page_ref.size as usize];
                dst.copy_from_slice(src);
            }
        }
        new_sequence_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_block::{FileFormat, FileType};

    #[test]
    fn test_parse_transaction_log() {
        let state = State::from_path("test_data/SYSTEM.LOG1", 4096).unwrap();
        let (_, log) = TransactionLog::from_bytes(state.file_start_pos, &state.file_buffer[0..]).unwrap();

        let mut unk2: Vec<u8> = [0, 157, 174, 134, 126, 174, 227, 17, 128, 186, 0, 38, 185, 86, 201, 104, 0, 157, 174, 134, 126, 174, 227, 17, 128, 186, 0, 38, 185, 86, 201, 104, 0, 0, 0, 0, 1, 157, 174, 134, 126, 174, 227, 17, 128, 186, 0, 38, 185, 86, 201, 104, 114, 109, 116, 109, 249, 73, 219, 43, 26, 227, 208, 1].to_vec();
        unk2.extend([0; 332].iter().copied());
        let expected_header = FileBaseBlockBase {
            primary_sequence_number: 178,
            secondary_sequence_number: 178,
            last_modification_date_and_time: util::get_date_time_from_filetime(130216567421081762),
            major_version: 1,
            minor_version: 5,
            file_type: FileType::TransactionLogNewFormat,
            format: FileFormat::DirectMemoryLoad,
            root_cell_offset_relative: 32,
            hive_bins_data_size: 7155712,
            clustering_factor: 1,
            filename: "SYSTEM".to_string(),
            unk2,
            checksum: 3430861351,
            parse_warnings: Warnings::default()
        };
        assert_eq!(expected_header, log.base_block);
        assert_eq!(8, log.log_entries.len());
        assert_eq!(2306048, log.log_entries[7].file_offset_absolute);
        assert_eq!(12288, log.log_entries[7].size);
        assert_eq!(107, log.log_entries[7].dirty_pages[1].page_bytes[4037]);
    }

    #[test]
    fn test_parse_log_entry() {
        let state = State::from_path("test_data/SYSTEM.LOG1", 4096).unwrap();
        let (_, log_entry) = LogEntry::from_bytes_internal(state.file_start_pos, &state.file_buffer[512..]).unwrap();
        assert_eq!(512, log_entry.file_offset_absolute);
        assert_eq!(515584, log_entry.size);
        assert_eq!(0, log_entry.flags);
        assert_eq!(178, log_entry.sequence_number);
        assert_eq!(7155712, log_entry.hive_bin_data_size);
        assert_eq!(69, log_entry.dirty_pages_count);
        assert_eq!(9787668550818779155, log_entry.hash1);
        assert_eq!(7274014407108881154, log_entry.hash2);
        assert_eq!(69, log_entry.dirty_pages.len());
        assert_eq!(DirtyPageRef {offset:0, size:4096}, log_entry.dirty_pages[0].dirty_page_ref);
        assert_eq!(116, log_entry.dirty_pages[0].page_bytes[1880]);
        assert_eq!(DirtyPageRef {offset:1708032, size:24576}, log_entry.dirty_pages[32].dirty_page_ref);
        assert_eq!(2, log_entry.dirty_pages[32].page_bytes[3904]);
        assert_eq!(DirtyPageRef {offset:7151616, size:4096}, log_entry.dirty_pages[68].dirty_page_ref);
        assert_eq!(0, log_entry.dirty_pages[68].page_bytes[1880]);
    }
}
