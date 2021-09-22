/*
 * Copyright 2021 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::base_block::BaseBlockBase;
use crate::cell::{Cell, CellState};
use crate::cell_key_node::{CellKeyNode, CellKeyNodeReadOptions};
use crate::cell_key_value::CellKeyValue;
use crate::err::Error;
use crate::file_info::{FileInfo, ReadSeek};
use crate::log::{LogCode, Logs};
use crate::marvin_hash;
use crate::parser::{Parser, ParserIterator};
use crate::reg_item_map::{RegItemMap, RegItemMapKey, RegItemMapValue};
use crate::state::State;
use crate::util;
use nom::{
    bytes::complete::tag,
    number::complete::{le_u32, le_u64},
    IResult,
};
use serde::Serialize;
use std::collections::HashMap;

// Transaction log structures based off https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-transaction-log-files

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DirtyPageRef {
    pub offset: u32,
    //Size of a page in bytes
    pub size: u32,
}

impl DirtyPageRef {
    fn from_bytes() -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        |input: &[u8]| {
            let (input, offset) = le_u32(input)?;
            let (input, size) = le_u32(input)?;
            Ok((input, Self { offset, size }))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DirtyPage {
    pub dirty_page_ref_offset: u32,
    pub page_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
enum ModifiedListType {
    Updated,
    Deleted,
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
    pub has_valid_hashes: bool,
}

impl LogEntry {
    fn from_bytes(start_pos: usize) -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        move |input: &[u8]| LogEntry::from_bytes_internal(start_pos, input)
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
        let (mut input, dirty_page_refs) =
            nom::multi::count(DirtyPageRef::from_bytes(), dirty_pages_count as usize)(input)?;

        let mut dirty_pages = Vec::new();
        for dirty_page_ref in dirty_page_refs {
            let (local_input, page_bytes) = nom::bytes::complete::take(dirty_page_ref.size)(input)?;
            input = local_input;
            dirty_pages.push(DirtyPage {
                dirty_page_ref_offset: dirty_page_ref.offset,
                page_bytes: page_bytes.to_vec(),
            });
        }
        let (input, _) = util::parser_eat_remaining(
            input,
            size,
            input.as_ptr() as usize - start_pos - file_offset_absolute,
        )?;
        let has_valid_hashes =
            hash1 == Self::calc_hash1(start, size as usize) && hash2 == Self::calc_hash2(start);

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
            has_valid_hashes,
        };

        Ok((input, hbh))
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
    log_entries: Vec<LogEntry>,
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
                log_entries,
            },
        ))
    }

    pub(crate) fn parse<T: ReadSeek>(
        log_files: Vec<T>,
    ) -> Result<(Vec<Self>, Option<Logs>), Error> {
        let mut transaction_logs = Vec::new();
        let mut error_logs = Logs::default();
        for mut log_file in log_files {
            let mut file_buffer_log = Vec::new();
            log_file.read_to_end(&mut file_buffer_log)?;
            if file_buffer_log.is_empty() {
                error_logs.add(LogCode::WarningParse, &"Skipping log file; 0 bytes");
            } else {
                match Self::from_bytes(&file_buffer_log[0..]) {
                    Ok((_, log)) => transaction_logs.push(log),
                    Err(e) => {
                        error_logs.add(
                            LogCode::WarningParse,
                            &format!("Skipping log file; {}", Error::from(e).to_string()),
                        );
                    }
                }
            }
        }
        // sort oldest to newest
        transaction_logs.sort_by(|a, b| {
            a.base_block
                .primary_sequence_number
                .cmp(&b.base_block.primary_sequence_number)
        });
        Ok((transaction_logs, error_logs.get_option()))
    }

    /// Updates the primary registry with the dirty pages in the passed-in log. Returns the last sequence number applied and the updated RegItemMap
    pub(crate) fn update_parser(
        &self,
        parser: &mut Parser,
        mut prior_items: RegItemMap,
    ) -> (u32, RegItemMap) {
        let mut new_sequence_number = 0;
        let (primary_secondary_seq_num, primary_hive_bins_data_size) = parser.get_base_block_info();
        for log_entry in &self.log_entries {
            if log_entry.has_valid_hashes {
                if log_entry.sequence_number < primary_secondary_seq_num {
                    parser.state.info.add(
                        LogCode::WarningTransactionLog,
                        &format!("Skipping log entry; the log entry sequence number ({}) is less than to the primary file's secondary sequence number ({})", log_entry.sequence_number, primary_secondary_seq_num)
                    );
                } else if !log_entry.is_valid_hive_bin_data_size() {
                    parser.state.info.add(
                        LogCode::WarningTransactionLog,
                        &format!("Stopping log entry processing; the hive_bin_data_size ({}) is not a multiple of 4096)", log_entry.hive_bins_data_size)
                    );
                    break;
                } else if new_sequence_number != 0
                    && log_entry.sequence_number != new_sequence_number + 1
                {
                    parser.state.info.add(
                        LogCode::WarningTransactionLog,
                        &format!("Stopping log entry processing; the sequence number ({}) does not follow the previous log entry's sequence number ({})", log_entry.sequence_number, new_sequence_number)
                    );
                    break;
                } else {
                    if primary_hive_bins_data_size < log_entry.hive_bins_data_size {
                        parser.file_info.buffer.resize(
                            parser.file_info.buffer.len()
                                + (log_entry.hive_bins_data_size - primary_hive_bins_data_size)
                                    as usize,
                            0,
                        );
                    }
                    new_sequence_number = log_entry.sequence_number;

                    // save the prior buffer for use
                    let prior_file_info;
                    if parser.recover_deleted {
                        prior_file_info = Some(parser.file_info.clone());
                    } else {
                        prior_file_info = None;
                    }

                    // apply the updated bytes to the main file buffer for each dirty page
                    for dirty_page in &log_entry.dirty_pages {
                        let dst_offset = dirty_page.dirty_page_ref_offset as usize
                            + parser.file_info.hbin_offset_absolute;
                        let dst_offset_end = dst_offset + dirty_page.page_bytes.len();
                        let dst = &mut parser.file_info.buffer[dst_offset..dst_offset_end];
                        let src = &dirty_page.page_bytes;
                        dst.copy_from_slice(src);
                    }

                    if parser.recover_deleted {
                        let mut logs = Logs::default();
                        let transaction_analyzer = TransactionAnalyzer {
                            prior_file_info: &prior_file_info.unwrap(),
                            new_sequence_number,
                        };
                        match transaction_analyzer.get_latest_reg_items(
                            parser,
                            &mut prior_items,
                            &mut logs,
                        ) {
                            Ok(updated_items_ret) => {
                                prior_items = updated_items_ret;
                            }
                            Err(e) => parser.state.info.add(
                                LogCode::WarningTransactionLog,
                                &format!(
                                    "Unable to read cell tree for new sequence number {}, {:?}",
                                    new_sequence_number, e
                                ),
                            ),
                        }
                        parser.state.info.extend(logs);
                    }
                }
            } else {
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
    ) -> Result<RegItemMap, Error> {
        let mut reg_items: RegItemMap = HashMap::new();
        if parser.recover_deleted {
            parser.init_root()?;
            for key in ParserIterator::new(parser).iter() {
                reg_items.insert(
                    RegItemMapKey::new(key.path.clone(), None),
                    RegItemMapValue::new(
                        key.hash.expect("Must have a hash here"),
                        key.detail.file_offset_absolute,
                        sequence_num,
                    ),
                );
                for value in key.sub_values {
                    reg_items.insert(
                        RegItemMapKey::new(key.path.clone(), Some(value.value_name)),
                        RegItemMapValue::new(
                            value.hash.expect("Must have a hash here"),
                            value.detail.file_offset_absolute,
                            sequence_num,
                        ),
                    );
                }
            }
        }
        Ok(reg_items)
    }
}

struct RegItemNeeded {
    key_path: String,
    file_offset_absolute: usize,
    sequence_num: u32,
}

impl RegItemNeeded {
    fn new(key_path: String, file_offset_absolute: usize, sequence_num: u32) -> Self {
        Self {
            key_path,
            file_offset_absolute,
            sequence_num,
        }
    }
}

struct NewItemInfo<'a> {
    key_path: &'a str,
    value_path: Option<String>,
    updated_item: &'a dyn Cell,
}

#[derive(Clone, Debug)]
pub(crate) struct TransactionAnalyzer<'a> {
    prior_file_info: &'a FileInfo,
    new_sequence_number: u32,
}

impl TransactionAnalyzer<'_> {
    pub(crate) fn get_latest_reg_items(
        &self,
        updated_parser: &mut Parser,
        prior_reg_items: &mut RegItemMap,
        logs: &mut Logs,
    ) -> Result<RegItemMap, Error> {
        let mut prior_keys_needed = Vec::new(); // vec of keys that are missing or different in the latest version
        let mut prior_values_needed = Vec::new(); // vec of values that are missing or different in the latest version
        let mut latest_reg_items = HashMap::with_capacity(prior_reg_items.len());

        updated_parser.init_root()?;

        for updated_key in ParserIterator::new(updated_parser)
            .get_modified_items(false)
            .iter()
        {
            self.handle_new_item(
                prior_reg_items,
                &mut latest_reg_items,
                &mut prior_keys_needed,
                logs,
                NewItemInfo {
                    key_path: &updated_key.path,
                    value_path: None,
                    updated_item: &updated_key,
                },
            );
            for updated_value in updated_key.sub_values {
                self.handle_new_item(
                    prior_reg_items,
                    &mut latest_reg_items,
                    &mut prior_values_needed,
                    logs,
                    NewItemInfo {
                        key_path: &updated_key.path,
                        value_path: Some(updated_value.value_name.clone()),
                        updated_item: &updated_value,
                    },
                );
            }
        }

        // Now read the full keys for prior_keys_needed and add them to the list in state
        for key_needed in prior_keys_needed.iter() {
            if let Err(e) = self.add_full_key_to_list(
                &mut updated_parser.state,
                &key_needed.key_path,
                key_needed.file_offset_absolute,
                key_needed.sequence_num,
                ModifiedListType::Updated,
            ) {
                logs.add(
                    LogCode::WarningTransactionLog,
                    &format!(
                        "Error adding {} to updated list for sequence num: {} ({})",
                        key_needed.key_path,
                        key_needed.sequence_num,
                        &e.to_string()
                    ),
                );
            }
        }
        // Now read the full values for prior_values_needed and add them to the list in state
        for value_needed in prior_values_needed.iter() {
            if let Err(e) = self.add_full_value_to_list(
                &mut updated_parser.state,
                &value_needed.key_path,
                value_needed.file_offset_absolute,
                value_needed.sequence_num,
                ModifiedListType::Updated,
            ) {
                logs.add(
                    LogCode::WarningTransactionLog,
                    &format!(
                        "Error adding {} to updated list for sequence num: {} ({})",
                        &value_needed.key_path,
                        value_needed.sequence_num,
                        &e.to_string()
                    ),
                );
            }
        }

        // If we have any items that are left in prior_reg_items, then we didn't see them in the newly parsed buffer and therefore they're deleted.
        // Move them to the relevant lists in state
        for (prior_item_map_key, prior_item_map_value) in prior_reg_items {
            match &prior_item_map_key.value_name {
                Some(_) => {
                    if let Err(e) = self.add_full_value_to_list(
                        &mut updated_parser.state,
                        &prior_item_map_key.key_path,
                        prior_item_map_value.file_offset_absolute,
                        prior_item_map_value.sequence_num,
                        ModifiedListType::Deleted,
                    ) {
                        logs.add(
                            LogCode::WarningTransactionLog,
                            &format!(
                                "Error adding {:?} to updated list for sequence num: {} ({})",
                                prior_item_map_key,
                                prior_item_map_value.sequence_num,
                                &e.to_string()
                            ),
                        );
                    }
                }
                None => {
                    if let Err(e) = self.add_full_key_to_list(
                        &mut updated_parser.state,
                        &prior_item_map_key.key_path,
                        prior_item_map_value.file_offset_absolute,
                        prior_item_map_value.sequence_num,
                        ModifiedListType::Deleted,
                    ) {
                        logs.add(
                            LogCode::WarningTransactionLog,
                            &format!(
                                "Error adding {} to deleted list for sequence num: {} ({})",
                                prior_item_map_key.key_path,
                                prior_item_map_value.sequence_num,
                                &e.to_string()
                            ),
                        );
                    }
                }
            }
        }

        // Check all new items against the deleted list. If it's in the deleted list, remove it.
        // This is a mitigation against ending up with a bunch of spurious deleted items from unparsable buffers.
        for (reg_item_map_key, reg_item_map_value) in &latest_reg_items {
            match &reg_item_map_key.value_name {
                Some(value_name) => updated_parser.state.deleted_values.remove(
                    &reg_item_map_key.key_path,
                    value_name,
                    &reg_item_map_value.hash,
                ),
                None => updated_parser
                    .state
                    .deleted_keys
                    .remove(&reg_item_map_key.key_path, &reg_item_map_value.hash),
            }
        }

        Ok(latest_reg_items)
    }

    fn handle_new_item(
        &self,
        prior_reg_items: &mut RegItemMap,
        latest_reg_items: &mut RegItemMap,
        reg_items_needed: &mut Vec<RegItemNeeded>,
        logs: &mut Logs,
        new_item_info: NewItemInfo,
    ) {
        let sequence_num;
        let updated_item_hash = new_item_info
            .updated_item
            .get_hash()
            .expect("must have hash if here");
        if let Some(prior_item) = prior_reg_items.remove(&RegItemMapKey::new(
            new_item_info.key_path.to_string(),
            new_item_info.value_path.clone(),
        )) {
            // We found our item in prior_reg_items. Now we will check the hash.
            // If the hash is the same then we will just return the sequence number from the original item.
            // If the hash differs, we have a modified item and we'll add it to the reg_items_needed map
            if updated_item_hash == prior_item.hash {
                sequence_num = prior_item.sequence_num
            } else {
                sequence_num = self.new_sequence_number;
                reg_items_needed.push(RegItemNeeded::new(
                    new_item_info.key_path.to_string(),
                    prior_item.file_offset_absolute,
                    prior_item.sequence_num,
                ));
            }
        } else {
            sequence_num = self.new_sequence_number;
        }

        latest_reg_items.insert(
            RegItemMapKey::new(new_item_info.key_path.to_string(), new_item_info.value_path),
            RegItemMapValue::new(
                updated_item_hash,
                new_item_info.updated_item.get_file_offset_absolute(),
                sequence_num,
            ),
        );

        let mut item_logs = new_item_info.updated_item.get_logs().clone();
        item_logs.prepend_all(&format!("Sequence number {} - ", self.new_sequence_number));
        logs.extend(item_logs);
    }

    fn add_full_key_to_list(
        &self,
        state: &mut State,
        path: &str,
        file_offset_absolute: usize,
        old_sequence_number: u32,
        modified_list_type: ModifiedListType,
    ) -> Result<(), Error> {
        let parent_path = &path[0..path.rfind('\\').unwrap_or_default()];
        let full_key = CellKeyNode::read(
            self.prior_file_info,
            state,
            CellKeyNodeReadOptions {
                offset: file_offset_absolute,
                cur_path: parent_path,
                filter: None,
                self_is_filter_match_or_descendent: false,
                sequence_num: Some(old_sequence_number),
                get_deleted_and_modified: false,
            },
        )?;
        if let Some(mut full_key) = full_key {
            full_key.updated_by_sequence_num = Some(self.new_sequence_number);
            // remove values; they'll be captured elsewhere
            full_key.sub_values = vec![];
            match modified_list_type {
                ModifiedListType::Updated => {
                    full_key.cell_state = CellState::ModifiedTransactionLog;
                    state.updated_keys.add(path, full_key)
                }
                ModifiedListType::Deleted => {
                    full_key.cell_state = CellState::DeletedTransactionLog;
                    state.deleted_keys.add(parent_path, full_key)
                }
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
        modified_list_type: ModifiedListType,
    ) -> Result<(), Error> {
        let (_, mut full_value) = CellKeyValue::from_bytes(
            &self.prior_file_info.buffer[file_offset_absolute..],
            file_offset_absolute,
            Some(old_sequence_number),
        )?;
        full_value.read_value_bytes(self.prior_file_info, state);
        full_value.updated_by_sequence_num = Some(self.new_sequence_number);
        let name = full_value.value_name.clone();
        match modified_list_type {
            ModifiedListType::Updated => {
                full_value.cell_state = CellState::ModifiedTransactionLog;
                state.updated_values.add(path, &name, full_value)
            }
            ModifiedListType::Deleted => {
                full_value.cell_state = CellState::DeletedTransactionLog;
                state.deleted_values.add(path, full_value)
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_block::{FileFormat, FileType};
    use crate::file_info::FileInfo;
    use crate::log::Logs;

    #[test]
    fn test_parse_transaction_log() {
        let mut file_info = FileInfo::from_path("test_data/system.log1").unwrap();
        file_info.hbin_offset_absolute = 4096;
        let (_, log) = TransactionLog::from_bytes(&file_info.buffer[0..]).unwrap();

        let mut unk2: Vec<u8> = [
            248, 63, 180, 93, 211, 13, 235, 17, 130, 154, 128, 110, 111, 110, 105, 99, 248, 63,
            180, 93, 211, 13, 235, 17, 130, 154, 128, 110, 111, 110, 105, 99, 1, 0, 0, 0, 249, 63,
            180, 93, 211, 13, 235, 17, 130, 154, 128, 110, 111, 110, 105, 99, 114, 109, 116, 109,
            234, 29, 73, 188, 218, 138, 215, 1, 79, 102, 82, 103, 1,
        ]
        .to_vec();
        unk2.extend([0; 327].iter().copied());
        let expected_header = BaseBlockBase {
            primary_sequence_number: 4064,
            secondary_sequence_number: 4064,
            last_modification_date_and_time: util::get_date_time_from_filetime(0),
            major_version: 1,
            minor_version: 5,
            file_type: FileType::TransactionLogNewFormat,
            format: FileFormat::DirectMemoryLoad,
            root_cell_offset_relative: 32,
            hive_bins_data_size: 16445440,
            clustering_factor: 1,
            filename: "SYSTEM".to_string(),
            unk2,
            checksum: 2429800415,
            logs: Logs::default(),
        };
        assert_eq!(expected_header, log.base_block);
        assert_eq!(3, log.log_entries.len());
        assert_eq!(32768, log.log_entries[2].file_offset_absolute);
        assert_eq!(16384, log.log_entries[2].size);
        assert_eq!(114, log.log_entries[2].dirty_pages[1].page_bytes[1000]);
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
