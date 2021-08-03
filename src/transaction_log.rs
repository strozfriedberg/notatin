use std::collections::HashMap;
use nom::{
    IResult,
    bytes::complete::tag,
    number::complete::{le_u32, le_u64}
};
use serde::Serialize;
use crate::base_block::BaseBlockBase;
use crate::file_info::{FileInfo, ReadSeek};
use crate::state::State;
use crate::err::Error;
use crate::util;
use crate::log::{LogCode, Logs};
use crate::marvin_hash;
use crate::cell_key_node::{CellKeyNode, CellKeyNodeReadOptions};
use crate::cell_key_value::CellKeyValue;
use crate::parser::{Parser, RegItems};

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
    pub dirty_page_ref_offset: u32,
    pub page_bytes: Vec<u8>
}

enum ModifiedListType {
    Updated,
    Deleted
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
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
    pub hive_bins_data_size: u32,
    /// Number of dirty pages attached to a current log entry
    pub dirty_pages_count: u32,
    pub hash1: u64,
    pub hash2: u64,
    pub dirty_pages: Vec<DirtyPage>,
    pub has_valid_hashes: bool
}

impl LogEntry {
    fn from_bytes(start_pos: usize) -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        move |input: &[u8]| {
            LogEntry::from_bytes_internal(start_pos, input)
        }
    }

    fn from_bytes_internal(start_pos: usize, input: &[u8]) -> IResult<&[u8], Self> {
        let start = input;
        let file_offset_absolute = input.as_ptr() as usize - start_pos;
        let (input, _signature) = tag("HvLE")(input)?;
        let (input, size) = le_u32(input)?;
        let (input, flags) = le_u32(input)?;
        let (input, sequence_number) = le_u32(input)?;
        let (input, hive_bins_data_size) = le_u32(input)?;
        let (input, dirty_pages_count) = le_u32(input)?;
        let (input, hash1) = le_u64(input)?;
        let (input, hash2) = le_u64(input)?;
        let (mut input, dirty_page_refs) = nom::multi::count(DirtyPageRef::from_bytes(), dirty_pages_count as usize)(input)?;

        let mut dirty_pages = Vec::new();
        for dirty_page_ref in dirty_page_refs {
            let (local_input, page_bytes) = nom::bytes::complete::take(dirty_page_ref.size)(input)?;
            input = local_input;
            dirty_pages.push(
                DirtyPage {
                    dirty_page_ref_offset: dirty_page_ref.offset,
                    page_bytes: page_bytes.to_vec()
                }
            );
        }
        let (input, _) = util::parser_eat_remaining(input, size, input.as_ptr() as usize - start_pos - file_offset_absolute)?;
        let has_valid_hashes = hash1 == Self::calc_hash1(start, size as usize) && hash2 == Self::calc_hash2(start);

        let hbh = Self {
            file_offset_absolute,
            size,
            flags,
            sequence_number,
            hive_bins_data_size,
            dirty_pages_count,
            hash1,
            hash2,
            dirty_pages,
            has_valid_hashes
        };

        Ok((
            input,
            hbh
        ))
    }

    fn is_valid_hive_bin_data_size(&self) -> bool {
        self.hive_bins_data_size % 4096 == 0
    }

    fn calc_hash1(raw_bytes: &[u8], len: usize) -> u64 {
        const OFFSET: usize = 40;
        let mut b = vec![0; len - OFFSET];
        let dst = &mut b[0..len - OFFSET];
        let src = &raw_bytes[OFFSET..len];
        dst.copy_from_slice(src);
        marvin_hash::compute_hash(dst, (len - OFFSET) as u32, marvin_hash::DEFAULT_SEED)
    }

    fn calc_hash2(raw_bytes: &[u8]) -> u64 {
        const LENGTH: usize = 32;
        let mut b = vec![0; LENGTH];
        let dst = &mut b[0..LENGTH];
        let src = &raw_bytes[0..LENGTH];
        dst.copy_from_slice(src);
        marvin_hash::compute_hash(dst, LENGTH as u32, marvin_hash::DEFAULT_SEED)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct TransactionLog {
    pub(crate) base_block: BaseBlockBase,
    pub(crate) base_block_bytes: Vec<u8>,
    log_entries: Vec<LogEntry>
}

impl TransactionLog {
    pub(crate) fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let start = input;
        let start_pos = input.as_ptr() as usize;
        let (input, base_block) = BaseBlockBase::from_bytes(input)?;
        let (input, log_entries) = nom::multi::many0(LogEntry::from_bytes(start_pos))(input)?;
        Ok((
            input,
            Self {
                base_block,
                base_block_bytes: start[..512].to_vec(),
                log_entries
            }
        ))
    }

    pub(crate) fn parse<T: ReadSeek>(log_files: Option<Vec<T>>) -> Result<Option<Vec<Self>>, Error> {
        if let Some(log_files) = log_files {
            let mut transaction_logs = Vec::new();
            for mut log_file in log_files {
                let mut file_buffer_log = Vec::new();
                log_file.read_to_end(&mut file_buffer_log)?;
                let slice_log = &file_buffer_log[0..];
                let (_, log) = Self::from_bytes(slice_log)?;
                transaction_logs.push(log);
            }
            Ok(Some(transaction_logs))
        }
        else {
            Ok(None)
        }
    }

    /// Updates the primary registry with the dirty pages. Returns the last sequence number applied and the updated list of RegItems
    pub(crate) fn update_bytes(
        &self,
        parser: &mut Parser,
        base_block_base: &BaseBlockBase,
        mut prior_items: RegItems
    ) -> (u32, RegItems) {
        let mut new_sequence_number = 0;
        for log_entry in &self.log_entries {
            println!("log_entry sequence_number: {}", log_entry.sequence_number);
            if log_entry.has_valid_hashes {
                if log_entry.sequence_number < base_block_base.secondary_sequence_number {
                    parser.state.info.add(
                        LogCode::WarningTransactionLog,
                        &format!("Skipping log entry; the log entry sequence number ({}) is less than to the primary file's secondary sequence number ({})", log_entry.sequence_number, base_block_base.secondary_sequence_number)
                    );
                }
                else if !log_entry.is_valid_hive_bin_data_size() {
                    parser.state.info.add(
                        LogCode::WarningTransactionLog,
                        &format!("Stopping log entry processing; the hive_bin_data_size ({}) is not a multiple of 4096)", log_entry.hive_bins_data_size)
                    );
                    break;
                }
                else if new_sequence_number != 0 && log_entry.sequence_number != new_sequence_number + 1 {
                    parser.state.info.add(
                        LogCode::WarningTransactionLog,
                        &format!("Stopping log entry processing; the sequence number ({}) does not follow the previous log entry's sequence number ({})", log_entry.sequence_number, new_sequence_number)
                    );
                    break;
                }
                else {
                    if base_block_base.hive_bins_data_size < log_entry.hive_bins_data_size {
                        parser.file_info.buffer.resize(parser.file_info.buffer.len() + (log_entry.hive_bins_data_size - base_block_base.hive_bins_data_size) as usize, 0);
                    }
                    new_sequence_number = log_entry.sequence_number;

                    // save the prior buffer for use
                    let prior_file_info;
                    if parser.state.recover_deleted {
                        prior_file_info = Some(parser.file_info.clone());
                    }
                    else {
                        prior_file_info = None;
                    }

                    // apply the updated bytes to the main file buffer for each dirty page
                    for dirty_page in &log_entry.dirty_pages {
                        let dst_offset     = dirty_page.dirty_page_ref_offset as usize + parser.file_info.hbin_offset_absolute;
                        let dst_offset_end = dst_offset + dirty_page.page_bytes.len();
                        let dst            = &mut parser.file_info.buffer[dst_offset..dst_offset_end];
                        let src            = &dirty_page.page_bytes;
                        dst.copy_from_slice(src);
                    }

                    if parser.state.recover_deleted {
                        let mut logs = Logs::default();
                        let transaction_analyzer = TransactionAnalyzer{ prior_file_info: &prior_file_info.unwrap(), new_sequence_number };
                        match transaction_analyzer.update_cell_key_tree(parser, &mut prior_items, &mut logs) {
                            Ok(updated_items_ret) => {
                                prior_items = updated_items_ret;
                            },
                            Err(e) => parser.state.info.add(
                                LogCode::WarningTransactionLog,
                                &format!("Unable to read cell tree for new sequence number {}, {:?}", new_sequence_number, e)
                            )
                        }
                        parser.state.info.extend(logs);
                    }
                }
            }
            else {
                parser.state.info.add(
                    LogCode::WarningTransactionLog,
                    &format!("Stopping log entry processing; hash mismatch at log entry with sequence number {}", log_entry.sequence_number)
                );
                break;
            }
        }
        (new_sequence_number, prior_items)
    }

    pub(crate) fn get_reg_items(
        parser: &mut Parser,
        sequence_num: u32,
    ) -> Result<RegItems, Error> {
        let mut reg_items: RegItems = HashMap::new();
        if parser.state.recover_deleted {
            parser.init_root()?;
            for key in parser.iter_postorder_include_ancestors() {
                reg_items.insert((key.path.clone(), None), (key.hash.expect("Must have a hash here"), key.detail.file_offset_absolute, sequence_num));
                for value in key.sub_values {
                    reg_items.insert((key.path.clone(), Some(value.value_name)), (value.hash.expect("Must have a hash here"), value.detail.file_offset_absolute, sequence_num));
                }
            }
        }
        Ok(reg_items)
    }
}

#[derive(Clone, Debug)]
struct TransactionAnalyzer<'a> {
    prior_file_info: &'a FileInfo,
    new_sequence_number: u32,
}

impl TransactionAnalyzer<'_> {
    pub(crate) fn update_cell_key_tree(
        &self,
        updated_parser: &mut Parser,
        prior_reg_items: &mut RegItems,
        logs: &mut Logs
    ) -> Result<RegItems, Error> {
        let mut prior_key_needed = Vec::new();
        let mut prior_value_needed = Vec::new();
        let mut updated_reg_items = HashMap::with_capacity(prior_reg_items.len());

        updated_parser.init_root()?;

        for mut updated_key in updated_parser.iter_skip_modified() {
            // Is the key in our prior list?
            let sequence_num;
            if let Some(prior_key) = prior_reg_items.remove(&(updated_key.path.clone(), None)) {
                // Existing item; if the hash differs we have a modified item
                if updated_key.hash == Some(prior_key.0) {
                    sequence_num = prior_key.2;
                }
                else {
                    sequence_num = self.new_sequence_number;
                    prior_key_needed.push((updated_key.path.clone(), prior_key.1, prior_key.2));
                }
            }
            else {
                sequence_num = self.new_sequence_number;
            }
            updated_reg_items.insert((updated_key.path.clone(), None), (updated_key.hash.expect("Must have a hash here"), updated_key.detail.file_offset_absolute, sequence_num));

            updated_key.logs.prepend_all(&format!("Sequence number {} - ", self.new_sequence_number));
            logs.extend(updated_key.logs);

            for updated_value in updated_key.sub_values {
                // Is the value in our prior list?
                let sequence_num;
                if let Some(prior_value) = prior_reg_items.remove(&(updated_key.path.clone(), Some(updated_value.value_name.clone()))) {
                    // Existing item; if the hash differs we have a modified item
                    if updated_value.hash == Some(prior_value.0) {
                        sequence_num = prior_value.2;
                    }
                    else {
                        sequence_num = self.new_sequence_number;
                        prior_value_needed.push((updated_key.path.clone(), prior_value.1, prior_value.2));
                    }
                }
                else {
                    sequence_num = self.new_sequence_number;
                }
                updated_reg_items.insert((updated_key.path.clone(), Some(updated_value.value_name)), (updated_value.hash.expect("Must have a hash here"), updated_value.detail.file_offset_absolute, sequence_num));
            }
        }

        // go read the full keys for prior keys needed and add them to the list in state
        for key in prior_key_needed.iter() {
            if let Err(e) = self.add_full_key_to_list(&mut updated_parser.state, &key.0, key.1, key.2, ModifiedListType::Updated) {
                logs.add(LogCode::WarningTransactionLog, &format!("Error adding {} to updated list for sequence num: {} ({})", key.0, key.2, &e.to_string()));
            }
        }
        // go read the full values for prior values needed and add them to the list in state
        for key in prior_value_needed.iter() {
            if let Err(e) = self.add_full_value_to_list(&mut updated_parser.state, &key.0, key.1, key.2, ModifiedListType::Updated) {
                logs.add(LogCode::WarningTransactionLog, &format!("Error adding {} to updated list for sequence num: {} ({})", key.0, key.2, &e.to_string()));
            }
        }

        // if we have any items that are left in reg_items, then we didn't see them in the newly parsed buffer and therefore they're deleted
        for prior_item in prior_reg_items {
            match &prior_item.0.1 {
                Some(_) => {
                    if let Err(e) = self.add_full_value_to_list(&mut updated_parser.state, &prior_item.0.0, prior_item.1.1, prior_item.1.2, ModifiedListType::Deleted) {
                        logs.add(LogCode::WarningTransactionLog, &format!("Error adding {:?} to updated list for sequence num: {} ({})", prior_item.0, prior_item.1.2, &e.to_string()));
                    }
                },
                None => {
                    if let Err(e) = self.add_full_key_to_list(&mut updated_parser.state, &prior_item.0.0, prior_item.1.1, prior_item.1.2, ModifiedListType::Deleted) {
                        logs.add(LogCode::WarningTransactionLog, &format!("Error adding {} to deleted list for sequence num: {} ({})", prior_item.0.0, prior_item.1.2, &e.to_string()));
                    }
                }
            }
        }

        // Check all new items against the deleted list. If it's in the deleted list, remove it.
        // This is a mitigation against ending up with a bunch of spurious deleted items from unparsable buffers.
        for item in &updated_reg_items {
            match &item.0.1 {
                Some(value_name) => updated_parser.state.deleted_values.remove(&item.0.0, &value_name, &item.1.0),
                None => updated_parser.state.deleted_keys.remove(&item.0.0, &item.1.0)
            }
        }

        Ok(updated_reg_items)
    }

    fn add_full_key_to_list(
        &self,
        state: &mut State,
        path: &str,
        file_offset_absolute: usize,
        old_sequence_number: u32,
        modified_list_type: ModifiedListType
    ) -> Result<(), Error> {
        let parent_path = &path[0..path.rfind('\\').unwrap_or_default()];
        let full_key =
            CellKeyNode::read(
                self.prior_file_info,
                state,
                CellKeyNodeReadOptions {
                    offset: file_offset_absolute,
                    cur_path: &parent_path,
                    filter: None,
                    self_is_filter_match_or_descendent: false,
                    sequence_num: Some(old_sequence_number),
                    update_modified_lists: false
                }
            )?;
        if let Some(mut full_key) = full_key {
            full_key.updated_by_sequence_num = Some(self.new_sequence_number);
            match modified_list_type {
                ModifiedListType::Updated => state.updated_keys.add(&path, full_key),
                ModifiedListType::Deleted => state.deleted_keys.add(&parent_path, full_key)
            }
        }
        Ok(())
    }

    fn add_full_value_to_list(
        &self,
        state: &mut State,
        path: &str,
        file_offset_absolute: usize,
        old_sequence_number: u32,
        modified_list_type: ModifiedListType
    ) -> Result<(), Error> {
        let (_, mut full_value) =
            CellKeyValue::from_bytes(
                self.prior_file_info,
                &self.prior_file_info.buffer[file_offset_absolute..],
                Some(old_sequence_number)
            )?;
        full_value.read_value_bytes(self.prior_file_info, state);
        full_value.updated_by_sequence_num = Some(self.new_sequence_number);
        let name = full_value.value_name.clone();
        match modified_list_type {
            ModifiedListType::Updated => state.updated_values.add(&path, &name, full_value),
            ModifiedListType::Deleted => state.deleted_values.add(&path, &name, full_value)
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_info::FileInfo;
    use crate::base_block::{FileFormat, FileType};
    use crate::log::Logs;

    #[test]
    fn test_parse_transaction_log() {
        let mut file_info = FileInfo::from_path("test_data/SYSTEM.LOG1").unwrap();
        file_info.hbin_offset_absolute = 4096;
        let (_, log) = TransactionLog::from_bytes(&file_info.buffer[0..]).unwrap();

        let mut unk2: Vec<u8> = [0, 157, 174, 134, 126, 174, 227, 17, 128, 186, 0, 38, 185, 86, 201, 104, 0, 157, 174, 134, 126, 174, 227, 17, 128, 186, 0, 38, 185, 86, 201, 104, 0, 0, 0, 0, 1, 157, 174, 134, 126, 174, 227, 17, 128, 186, 0, 38, 185, 86, 201, 104, 114, 109, 116, 109, 249, 73, 219, 43, 26, 227, 208, 1].to_vec();
        unk2.extend([0; 332].iter().copied());
        let expected_header = BaseBlockBase {
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
            logs: Logs::default()
        };
        assert_eq!(expected_header, log.base_block);
        assert_eq!(8, log.log_entries.len());
        assert_eq!(2306048, log.log_entries[7].file_offset_absolute);
        assert_eq!(12288, log.log_entries[7].size);
        assert_eq!(107, log.log_entries[7].dirty_pages[1].page_bytes[4037]);
    }

    #[test]
    fn test_parse_log_entry() {
       /* let parser = Parser::from_path(primary_path: T, transaction_log_paths: Option<Vec<T>>, filter: Option<Filter>, recover_deleted: bool)
        let mut log_entry = LogEntry::default();
        let mut state = State::default();
        log_entry.hive_bins_data_size = 8192;
        assert_eq!(true, log_entry.is_valid_hive_bin_data_size());
        log_entry.hive_bins_data_size = 1;
        assert_eq!(false, log_entry.is_valid_hive_bin_data_size());

        let mut file_info = FileInfo::from_path("test_data/SYSTEM.LOG1").unwrap();
        file_info.hbin_offset_absolute = 4096;
        let (_, base_block_base) = BaseBlockBase::from_bytes(&file_info.buffer[..]).unwrap();
        let (_, mut log) = TransactionLog::from_bytes(&file_info.buffer[0..]).unwrap();
        log.log_entries[0].dirty_pages = Vec::new();
        log.log_entries[0].sequence_number = 179;
        log.log_entries[1].dirty_pages = Vec::new();
        log.log_entries[1].sequence_number = 181;

        let (last_sequence_num, _) = log.update_bytes(&mut file_info, &mut state, MinCellKeyNode::default(), &base_block_base);
        assert_eq!(179, last_sequence_num);
        let mut expected_warning_logs = Logs::default();
        expected_warning_logs.add(LogCode::WarningTransactionLog, &"Stopping log entry processing; the sequence number (181) does not follow the previous log entry's sequence number (179)");
        assert_eq!(expected_warning_logs, state.info);

        log.log_entries[0].has_valid_hashes = false;
        let (last_sequence_num, _) = log.update_bytes(&mut file_info, &mut state, MinCellKeyNode::default(), &base_block_base);
        assert_eq!(0, last_sequence_num);
        expected_warning_logs.add(LogCode::WarningTransactionLog, &"Stopping log entry processing; hash mismatch at log entry with sequence number 179");
        assert_eq!(expected_warning_logs, state.info);*/
    }

    #[test]
    fn test_update_bytes() {
        /*let mut file_info = FileInfo::from_path("test_data/SYSTEM.LOG1").unwrap();
        file_info.hbin_offset_absolute = 4096;
        let (_, log_entry) = LogEntry::from_bytes_internal(&file_info.buffer[512..]).unwrap();
        assert_eq!(512, log_entry.file_offset_absolute);
        assert_eq!(515584, log_entry.size);
        assert_eq!(0, log_entry.flags);
        assert_eq!(178, log_entry.sequence_number);
        assert_eq!(7155712, log_entry.hive_bins_data_size);
        assert_eq!(69, log_entry.dirty_pages_count);
        assert_eq!(9787668550818779155, log_entry.hash1);
        assert_eq!(7274014407108881154, log_entry.hash2);
        assert_eq!(69, log_entry.dirty_pages.len());*/


       /* assert_eq!(DirtyPageRef {offset:0, size:4096}, log_entry.dirty_pages[0].dirty_page_ref);
        assert_eq!(116, log_entry.dirty_pages[0].page_bytes[1880]);
        assert_eq!(DirtyPageRef {offset:1708032, size:24576}, log_entry.dirty_pages[32].dirty_page_ref);
        assert_eq!(2, log_entry.dirty_pages[32].page_bytes[3904]);
        assert_eq!(DirtyPageRef {offset:7151616, size:4096}, log_entry.dirty_pages[68].dirty_page_ref);
        assert_eq!(0, log_entry.dirty_pages[68].page_bytes[1880]);*/
    }
}