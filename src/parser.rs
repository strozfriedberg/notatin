/*
 * Copyright 2023 Aon Cyber Solutions
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

use crate::base_block::{BaseBlock, BaseBlockBase, FileType};
use crate::cell_key_node::{CellKeyNode, CellKeyNodeReadOptions, FilterMatchState};
use crate::err::Error;
use crate::file_info::FileInfo;
use crate::filter::{Filter, FilterBuilder};
use crate::hive_bin_header::HiveBinHeader;
use crate::log::{LogCode, Logs};
use crate::parser_recover_deleted::ParserRecoverDeleted;
use crate::progress;
use crate::state::State;
use crate::transaction_log::TransactionLog;
use std::collections::BTreeSet;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/

/// `Parser` should be constructed using `ParserBuilder`
/// ```
/// use notatin::parser_builder::ParserBuilder;
///
/// ParserBuilder::from_path("system")
///     .with_transaction_log("system.log1") // optional
///     .with_transaction_log("system.log2") // optional
///     .recover_deleted(true) // optional
///     .build();
/// ```
#[derive(Debug)]
pub struct Parser {
    pub(crate) file_info: FileInfo,
    pub(crate) state: State,
    pub(crate) base_block: Option<BaseBlock>,
    pub(crate) hive_bin_header: Option<HiveBinHeader>,
    pub(crate) cell_key_node_root: Option<CellKeyNode>,
    pub(crate) recover_deleted: bool,
    pub(crate) update_console: bool,
}

impl Parser {
    pub(crate) fn init(
        &mut self,
        recover_deleted: bool,
        parsed_transaction_logs: Vec<TransactionLog>,
    ) -> Result<(), Error> {
        let (is_supported_format, has_bad_checksum) = self.init_base_block()?;
        if is_supported_format {
            if recover_deleted {
                self.init_recover_deleted()?;
            }
            self.apply_transaction_logs(has_bad_checksum, parsed_transaction_logs)?;
            self.init_root()?;
        }
        Ok(())
    }

    pub(crate) fn init_root(&mut self) -> Result<(), Error> {
        let input = &self
            .file_info
            .buffer
            .get(self.file_info.hbin_offset_absolute..)
            .ok_or_else(|| Error::buffer("init_root"))?;
        let (input, hive_bin_header) = HiveBinHeader::from_bytes(&self.file_info, input)?;
        self.hive_bin_header = Some(hive_bin_header);
        let root = CellKeyNode::read(
            &self.file_info,
            &mut self.state,
            CellKeyNodeReadOptions {
                offset: self.file_info.get_file_offset(input),
                cur_path: "",
                filter: None, // root will always match, so no need for a filter here
                self_is_filter_match_or_descendent: true,
                sequence_num: None,
                get_deleted_and_modified: true,
            },
        )?;
        self.cell_key_node_root = root;
        Ok(())
    }

    /// Returns a tuple of (is_supported_format, has_bad_checksum)
    fn init_base_block(&mut self) -> Result<(bool, bool), Error> {
        let (input, base_block) = BaseBlock::from_bytes(&self.file_info.buffer)?;
        self.file_info.hbin_offset_absolute =
            input.as_ptr() as usize - self.file_info.buffer.as_ptr() as usize;
        self.base_block = Some(base_block);
        self.check_base_block()
    }

    /// Checks if the base block is a supported format. Returns a tuple of (is_supported_format, has_bad_checksum)
    fn check_base_block(&mut self) -> Result<(bool, bool), Error> {
        if self.is_supported_file_type() {
            let mut has_bad_checksum = false;
            let base_block = &self
                .base_block
                .as_ref()
                .expect("Shouldn't be here unless we've parsed the base block")
                .base;
            if base_block.primary_sequence_number != base_block.secondary_sequence_number {
                self.state.info.add(
                    LogCode::WarningBaseBlock,
                    &format!("Hive requires recovery: primary and secondary sequence numbers do not match. {}, {}",
                        base_block.primary_sequence_number,
                        base_block.secondary_sequence_number
                    )
                );
            }
            let checksum = BaseBlockBase::calculate_checksum(&self.file_info.buffer[..0x200])?;
            if checksum != base_block.checksum {
                self.state.info.add(
                    LogCode::WarningBaseBlock,
                    &"Hive requires recovery: base block checksum is wrong.",
                );
                has_bad_checksum = true;
            }
            return Ok((true, has_bad_checksum));
        } else {
            self.state.info.add(
                LogCode::WarningBaseBlock,
                &"Unsupported registry file type.",
            );
        }
        Ok((false, false))
    }

    fn is_supported_file_type(&self) -> bool {
        self.base_block
            .as_ref()
            .expect("Shouldn't be here unless we've parsed the base block")
            .base
            .file_type
            != FileType::Unknown
    }

    fn init_recover_deleted(&mut self) -> Result<(), Error> {
        self.find_free_keys_and_values()?;
        Ok(())
    }

    fn find_free_keys_and_values(&mut self) -> Result<bool, Error> {
        let base_block_base = &self.base_block.as_ref().expect("we just parsed this").base;
        let hive_bins_size = base_block_base.hive_bins_data_size;

        let mut file_offset_absolute = self.file_info.hbin_offset_absolute;
        let mut parser_recover_deleted = ParserRecoverDeleted {
            file_info: &self.file_info,
            state: &mut self.state,
        };
        while file_offset_absolute < hive_bins_size as usize {
            let file_offset_absolute_ret =
                parser_recover_deleted.find_free_keys_and_values(file_offset_absolute)?;
            file_offset_absolute = file_offset_absolute_ret;
        }
        Ok(true)
    }

    fn prepare_transaction_logs(
        &mut self,
        has_bad_checksum: bool,
        parsed_transaction_logs: &mut Vec<TransactionLog>,
    ) -> Result<bool, Error> {
        if has_bad_checksum {
            self.handle_bad_checksum(parsed_transaction_logs)?;
        }
        let primary_base_block = &self
            .base_block
            .as_ref()
            .expect("Shouldn't be here unless we have a base block")
            .base;
        if primary_base_block.primary_sequence_number
            == primary_base_block.secondary_sequence_number
        {
            self.state.info.add(LogCode::WarningTransactionLog, &"Skipping transaction logs because the primary file's primary_sequence_number matches the secondary_sequence_number");
            return Ok(false);
        }
        Ok(true)
    }

    fn handle_bad_checksum(
        &mut self,
        parsed_transaction_logs: &mut Vec<TransactionLog>,
    ) -> Result<(), Error> {
        self.state
            .info
            .add(LogCode::WarningBaseBlock, &"Applying recovered base block");

        // logs come in here sorted oldest to newest
        let newest_log = parsed_transaction_logs
            .last()
            .expect("shouldn't be here unless we have logs");
        let slice = self
            .file_info
            .buffer
            .get_mut(..BaseBlockBase::BASE_BLOCK_LEN)
            .ok_or_else(|| Error::buffer("handle_bad_checksum"))?;
        slice.copy_from_slice(&newest_log.base_block_bytes);

        // Per https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#new-format-1:
        //  "If a primary file contains an invalid base block, only the transaction log file with latest log entries is used in the recovery."
        debug_assert!(parsed_transaction_logs.len() <= 2); // Per Microsoft there will max two logs at this point.
                                                           // if there are two logs, remove the first (older) one
        if parsed_transaction_logs.len() > 1 {
            parsed_transaction_logs.remove(0);
        }

        self.init_base_block()?;
        Ok(())
    }

    fn update_header_after_transaction_logs(
        &mut self,
        new_sequence_number: u32,
    ) -> Result<(), Error> {
        // Update primary file header
        const PRIMARY_SEQUENCE_NUMBER_OFFSET: usize = 4;
        const SECONDARY_SEQUENCE_NUMBER_OFFSET: usize = 8;

        // Update sequence numbers with latest available
        let new_sequence_number_bytes = new_sequence_number.to_le_bytes();
        self.file_info.buffer[PRIMARY_SEQUENCE_NUMBER_OFFSET
            ..PRIMARY_SEQUENCE_NUMBER_OFFSET + new_sequence_number_bytes.len()]
            .copy_from_slice(&new_sequence_number_bytes);
        self.file_info.buffer[SECONDARY_SEQUENCE_NUMBER_OFFSET
            ..SECONDARY_SEQUENCE_NUMBER_OFFSET + new_sequence_number_bytes.len()]
            .copy_from_slice(&new_sequence_number_bytes);

        // Update the checksum
        let new_checksum = BaseBlockBase::calculate_checksum(&self.file_info.buffer[..0x200])?;
        self.file_info.buffer[BaseBlockBase::CHECKSUM_OFFSET
            ..BaseBlockBase::CHECKSUM_OFFSET + std::mem::size_of_val(&new_checksum)]
            .copy_from_slice(&new_checksum.to_le_bytes());

        // read the header again
        self.init_base_block()?;
        self.state.info.add(
            LogCode::Info,
            &format!("Applied transaction log(s). Sequence numbers have been updated to {}. New Checksum: 0x{:08X}", new_sequence_number, new_checksum)
        );
        Ok(())
    }

    fn apply_transaction_logs(
        &mut self,
        has_bad_checksum: bool,
        mut parsed_transaction_logs: Vec<TransactionLog>,
    ) -> Result<(), Error> {
        if !parsed_transaction_logs.is_empty()
            && self.prepare_transaction_logs(has_bad_checksum, &mut parsed_transaction_logs)?
        {
            let mut new_sequence_number = 0;
            let mut original_items = TransactionLog::get_reg_items(self, 0)?;

            let (primary_file_secondary_seq_num, _) = self.get_base_block_info();

            let mut console = progress::new(self.update_console);
            /* https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#new-format-1:
            If a primary file contains a valid base block, both transaction log files are used to recover the dirty hive,
            i.e. log entries from both transaction log files are applied.
            The transaction log file with earlier log entries is used first.
            (If recovery stops when applying log entries from this transaction log file, then recovery is resumed with the next
            transaction log file; the first log entry of the next transaction log file is expected to have a sequence number
            equal to N + 1, where N is a sequence number of the last log entry applied) */
            for (index, log) in &mut parsed_transaction_logs.iter().enumerate() {
                if log.base_block.primary_sequence_number >= primary_file_secondary_seq_num {
                    if new_sequence_number == 0
                        || (log.base_block.primary_sequence_number == new_sequence_number + 1)
                    {
                        console.write(&format!(
                            "Applying transaction log {} of {}\n",
                            index + 1,
                            parsed_transaction_logs.len()
                        ))?;
                        let (new_seq_num_ret, prior_reg_items) =
                            log.update_parser(self, original_items)?;
                        original_items = prior_reg_items;
                        new_sequence_number = new_seq_num_ret;
                    } else {
                        self.state.info.add(
                            LogCode::WarningTransactionLog,
                            &format!("Skipping log file; the log's primary sequence number ({}) does not follow the previous log's last sequence number ({})", log.base_block.primary_sequence_number, new_sequence_number)
                        );
                    }
                } else {
                    self.state.info.add(
                        LogCode::WarningTransactionLog,
                        &format!("Skipping log file; the log's primary sequence number ({}) is less than the primary file's secondary sequence number ({})", log.base_block.primary_sequence_number, primary_file_secondary_seq_num)
                    );
                }
            }
            self.update_header_after_transaction_logs(new_sequence_number)?;
        }
        Ok(())
    }

    pub(crate) fn get_base_block_info(&self) -> (u32, u32) {
        let base_block = &self
            .base_block
            .as_ref()
            .expect("Shouldn't be here unless we have a base block")
            .base;
        (
            base_block.secondary_sequence_number,
            base_block.hive_bins_data_size,
        )
    }

    /// Counts all subkeys and values
    pub fn count_all_keys_and_values(&self, filter: Option<&Filter>) -> (usize, usize) {
        let mut keys = 0;
        let mut values = 0;
        let mut iter = ParserIterator::new(self);
        if let Some(filter) = filter {
            iter.with_filter(filter.clone());
        }
        for key in iter.iter() {
            keys += 1;
            values += key.sub_values.len();
        }
        (keys, values)
    }

    /// Counts all subkeys and values
    pub(crate) fn _count_all_keys_and_values_with_modified(
        &mut self,
        filter: Option<Filter>,
    ) -> (usize, usize, usize, usize, usize, usize) {
        let mut keys = 0;
        let mut keys_versions = 0;
        let mut keys_deleted = 0;
        let mut values = 0;
        let mut values_versions = 0;
        let mut values_deleted = 0;

        let mut iter = ParserIterator::new(self);
        if let Some(filter) = filter {
            iter.with_filter(filter);
        }
        for key in iter.iter() {
            if key.cell_state.is_deleted() {
                keys_deleted += 1;
            } else {
                keys += 1;
            }
            keys_versions += key.versions.len();

            for value in key.value_iter() {
                if value.cell_state.is_deleted() {
                    values_deleted += 1;
                } else {
                    values += 1;
                }
                values_versions += value.versions.len();
            }
        }
        (
            keys,
            keys_versions,
            keys_deleted,
            values,
            values_versions,
            values_deleted,
        )
    }

    pub(crate) fn get_file_info(&self) -> &FileInfo {
        &self.file_info
    }

    pub fn get_parse_logs(&self) -> &Logs {
        &self.state.info
    }

    pub fn next_key_postorder(
        &self,
        iter_context: &mut ParserIteratorContext,
    ) -> Option<CellKeyNode> {
        // not using 'while let' here because we don't want to pop stack_to_traverse in the event that we return something from stack_to_return
        while !iter_context.stack_to_traverse.is_empty() {
            // first check to see if we are done with anything on stack_to_return;
            // if so, we can pop, return it, and carry on (without this check we'd push every node onto the stack before returning anything)
            if let Some(last) = iter_context.stack_to_return.last() {
                if last.iteration_state.track_returned == last.iteration_state.to_return {
                    return Some(
                        iter_context
                            .stack_to_return
                            .pop()
                            .expect("Just checked that stack_to_return wasn't empty"),
                    );
                }
            }

            if let Some(mut node) = iter_context.pop_stack_to_traverse() {
                if node.detail.number_of_sub_keys() > 0 {
                    let (children, _) = node.read_sub_keys_internal(
                        &self.file_info,
                        &mut iter_context.state,
                        &iter_context.filter,
                        None,
                        iter_context.get_modified_items,
                    );
                    node.iteration_state.to_return = children.len() as u32;
                    for c in children.into_iter().rev() {
                        let _ = iter_context.push_check_stack_to_traverse(c); // Come back to this. We should log if we get an error, but we need to rework things so self is mut, or pass in the logs directly.
                    }
                }
                for d in node.deleted_keys.iter_mut() {
                    d.iteration_state.filter_state = node.iteration_state.filter_state;
                    iter_context.stack_to_traverse.push(d.clone()); // just push directly; don't call push_check_stack_to_traverse because we don't follow deleted keys. (Also, log errors todo ^^.)
                }
                if !iter_context.stack_to_return.is_empty() {
                    let last = iter_context
                        .stack_to_return
                        .last_mut()
                        .expect("Just checked that stack_to_return wasn't empty");
                    last.iteration_state.track_returned += 1;
                }
                iter_context.stack_to_return.push(node);
            }
        }

        // Handle any remaining elements
        if !iter_context.stack_to_return.is_empty() {
            let to_return = iter_context
                .stack_to_return
                .pop()
                .expect("Just checked that stack_to_return wasn't empty");
            if iter_context.filter_include_ancestors
                || to_return.iteration_state.filter_state != Some(FilterMatchState::None)
            {
                return Some(to_return);
            }
        }
        None
    }

    pub fn next_key_preorder(
        &self,
        iter_context: &mut ParserIteratorContext,
    ) -> Option<CellKeyNode> {
        while let Some(mut node) = iter_context.pop_stack_to_traverse() {
            if node.detail.number_of_sub_keys() > 0 {
                let (children, _) = node.read_sub_keys_internal(
                    &self.file_info,
                    &mut iter_context.state,
                    &iter_context.filter,
                    None,
                    iter_context.get_modified_items,
                );
                node.iteration_state.to_return = children.len() as u32;
                for c in children.into_iter().rev() {
                    let _ = iter_context.push_check_stack_to_traverse(c);
                }
            }
            for d in node.deleted_keys.iter_mut() {
                d.iteration_state.filter_state = node.iteration_state.filter_state;
                iter_context.stack_to_traverse.push(d.clone()); // just push directly; don't call push_check_stack_to_traverse because we don't follow deleted keys
            }
            if iter_context.filter_include_ancestors
                || !iter_context.filter.is_valid()
                || node.is_filter_match_or_descendent()
            {
                return Some(node);
            }
        }
        None
    }
}

// Direct key accessor methods - used by PyNotatin
impl Parser {
    pub fn get_root_key(&mut self) -> Result<Option<CellKeyNode>, Error> {
        match &self.base_block {
            Some(bb) => {
                let root = CellKeyNode::read(
                    &self.file_info,
                    &mut self.state,
                    CellKeyNodeReadOptions {
                        offset: bb.base.root_cell_offset_relative as usize
                            + self.file_info.hbin_offset_absolute,
                        cur_path: "",
                        filter: None,
                        self_is_filter_match_or_descendent: true,
                        sequence_num: None,
                        get_deleted_and_modified: true,
                    },
                )?;
                Ok(root)
            }
            _ => Ok(None),
        }
    }

    pub fn get_sub_key(
        &mut self,
        cell_key_node: &mut CellKeyNode,
        name: &str,
    ) -> Result<Option<CellKeyNode>, Error> {
        let key_path_sans_root =
            &cell_key_node.path[self.state.get_root_path_offset(&cell_key_node.path)..];
        let filter = FilterBuilder::new()
            .add_key_path(&(key_path_sans_root.to_string() + "\\" + name))
            .build()?;
        cell_key_node
            .read_sub_keys_internal(&self.file_info, &mut self.state, &filter, None, false)
            .0
            .get(0)
            .map_or_else(|| Ok(None), |k| Ok(Some(k.clone())))
    }

    pub fn get_key(
        &mut self,
        mut key_path: &str,
        key_path_has_root: bool,
    ) -> Result<Option<CellKeyNode>, Error> {
        match self.get_root_key() {
            Ok(root) => {
                if let Some(mut root) = root {
                    // if key_path starts with '\\', strip it
                    key_path = key_path.trim_start_matches('\\');
                    // if key_path_has_root, strip that before searching
                    if key_path_has_root {
                        if let Some(slash_offset) = key_path.find('\\') {
                            key_path = &key_path[slash_offset + 1..];
                        } else {
                            key_path = ""; // key_path _is_ root
                        }
                    }
                    let key = root.get_sub_key_by_path(self, key_path);
                    Ok(key)
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    pub fn get_parent_key(
        &mut self,
        cell_key_node: &mut CellKeyNode,
    ) -> Result<Option<CellKeyNode>, Error> {
        let mut parent_path = cell_key_node.path.clone();
        if let Some(last_slash_offset) = parent_path.rfind('\\') {
            parent_path.truncate(last_slash_offset);
        }
        if let Some(last_slash_offset) = parent_path.rfind('\\') {
            parent_path.truncate(last_slash_offset);
        }
        let parent = CellKeyNode::read(
            &self.file_info,
            &mut self.state,
            CellKeyNodeReadOptions {
                offset: cell_key_node.detail.parent_key_offset_relative() as usize
                    + self.file_info.hbin_offset_absolute,
                cur_path: &parent_path,
                filter: None,
                self_is_filter_match_or_descendent: true,
                sequence_num: None,
                get_deleted_and_modified: true,
            },
        )?;
        Ok(parent)
    }
}

#[derive(Clone)]
pub struct ParserIteratorContext {
    pub(crate) state: State,
    pub(crate) filter: Filter,
    stack_to_traverse: Vec<CellKeyNode>,
    stack_file_offsets: BTreeSet<usize>,
    stack_to_return: Vec<CellKeyNode>,
    get_modified_items: bool,
    filter_include_ancestors: bool,
}

impl ParserIteratorContext {
    pub fn from_parser(
        parser: &Parser,
        get_modified_items: bool,
        filter_and_ancestors: Option<(Filter, bool)>,
    ) -> Self {
        let (filter, filter_include_ancestors) = filter_and_ancestors.unwrap_or_default();

        let root = parser.cell_key_node_root.clone().unwrap_or_default();
        let mut stack_file_offsets = BTreeSet::new();
        stack_file_offsets.insert(root.file_offset_absolute);
        ParserIteratorContext {
            state: parser.state.clone(),
            filter,
            stack_to_traverse: vec![root],
            stack_file_offsets,
            stack_to_return: vec![],
            get_modified_items,
            filter_include_ancestors,
        }
    }

    fn push_check_stack_to_traverse(&mut self, node_to_add: CellKeyNode) -> Result<(), Error> {
        // Make sure the offset of what we're about to add is not the same as the offset of the current node, or of another node we are going to process.
        // Otherwise we could have a circular reference (this should only happen in recovery mode)
        if self
            .stack_file_offsets
            .insert(node_to_add.file_offset_absolute)
        {
            self.stack_to_traverse.push(node_to_add);
            Ok(())
        } else {
            Err(Error::Any {
                detail: format!("Attempting to add node with same file offset as another node we have processed (potential circular reference): {}", node_to_add.file_offset_absolute),
            })
        }
    }

    fn pop_stack_to_traverse(&mut self) -> Option<CellKeyNode> {
        self.stack_to_traverse.pop()
    }
}

#[derive(Clone)]
pub struct ParserIterator<'a> {
    parser: &'a Parser,
    postorder_iteration: bool,
    context: ParserIteratorContext,
}

impl Iterator for ParserIterator<'_> {
    type Item = CellKeyNode;

    fn next(&mut self) -> Option<Self::Item> {
        if self.postorder_iteration {
            self.parser.next_key_postorder(&mut self.context)
        } else {
            self.parser.next_key_preorder(&mut self.context)
        }
    }
}

impl<'a> ParserIterator<'a> {
    pub fn new(parser: &'a Parser) -> Self {
        let context = ParserIteratorContext::from_parser(parser, true, None);
        ParserIterator {
            parser,
            postorder_iteration: false,
            context,
        }
    }

    pub fn with_filter(&mut self, filter: Filter) -> &mut Self {
        self.context.filter = filter;
        self
    }

    pub fn filter_include_ancestors(&mut self, value: bool) -> &mut Self {
        self.context.filter_include_ancestors = value;
        self
    }

    pub fn postorder_iteration(&mut self, value: bool) -> &mut Self {
        self.postorder_iteration = value;
        self
    }

    pub fn get_modified_items(&mut self, value: bool) -> &mut Self {
        self.context.get_modified_items = value;
        self
    }

    pub fn iter(&mut self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::err::Error;
    use crate::filter::FilterBuilder;
    use crate::parser_builder::ParserBuilder;
    use md5;

    #[test]
    fn test_parser_iter_postorder() {
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .build()
            .unwrap();
        let (keys, values) = parser.count_all_keys_and_values(None);
        assert_eq!((2853, 5523), (keys, values));

        let mut md5_context = md5::Context::new();

        for key in ParserIterator::new(&parser)
            .filter_include_ancestors(true)
            .postorder_iteration(true)
            .iter()
        {
            md5_context.consume(key.path);
        }
        assert_eq!(
            "7e0d357766857c0524cc78d622709da9",
            format!("{:x}", md5_context.compute()),
            "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn test_parser_next_key_postorder() {
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .build()
            .unwrap();
        let mut keys = 0;
        let mut values = 0;
        let mut iter_context = ParserIteratorContext::from_parser(&parser, true, None);
        while let Some(key) = parser.next_key_postorder(&mut iter_context) {
            keys += 1;
            values += key.value_iter().count();
        }
        assert_eq!((2853, 5523), (keys, values));
    }

    #[test]
    fn test_parser_iterator_preorder_next() {
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .build()
            .unwrap();
        let mut keys = 0;
        let mut values = 0;
        let mut iter_context = ParserIteratorContext::from_parser(&parser, true, None);
        while let Some(key) = parser.next_key_preorder(&mut iter_context) {
            keys += 1;
            values += key.value_iter().count();
        }
        assert_eq!((2853, 5523), (keys, values));
    }

    #[test]
    fn test_parser_iterator_postorder_next() {
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .build()
            .unwrap();
        let mut keys = 0;
        let mut values = 0;
        let mut iter_context = ParserIteratorContext::from_parser(&parser, true, None);
        while let Some(key) = parser.next_key_postorder(&mut iter_context) {
            keys += 1;
            values += key.value_iter().count();
        }
        assert_eq!((2853, 5523), (keys, values));
    }

    #[test]
    // this test is slow because log analysis is slow. Ideally we will speed up analysis, but would be good to find smaller sample data as well.
    fn test_reg_logs_no_filter() {
        let mut parser = ParserBuilder::from_path("test_data/system")
            .with_transaction_log("test_data/system.log2")
            .with_transaction_log("test_data/system.log1")
            .recover_deleted(true)
            .build()
            .unwrap();

        let (keys, keys_versions, keys_deleted, values, values_versions, values_deleted) =
            parser._count_all_keys_and_values_with_modified(None);
        assert_eq!(
            (45587, 289, 31, 108178, 139, 244),
            (
                keys,
                keys_versions,
                keys_deleted,
                values,
                values_versions,
                values_deleted
            )
        );
    }

    #[test]
    #[ignore]
    fn test_reg_logs_with_filter() -> Result<(), Error> {
        let filter = FilterBuilder::new()
            .add_key_path(r"RegistryTest")
            .return_child_keys(true)
            .build()?;

        let mut parser = ParserBuilder::from_path("test_data/system")
            .with_transaction_log("test_data/system.log1")
            .with_transaction_log("test_data/system.log2")
            .recover_deleted(true)
            .build()?;

        let (keys, keys_versions, keys_deleted, values, values_versions, values_deleted) =
            parser._count_all_keys_and_values_with_modified(Some(filter));
        assert_eq!(
            (1, 4, 1, 3, 1, 3),
            (
                keys,
                keys_versions,
                keys_deleted,
                values,
                values_versions,
                values_deleted
            )
        );

        let filter = FilterBuilder::new()
            .add_key_path(r"RegistryTest")
            .return_child_keys(true)
            .build()?;
        let mut parser = ParserBuilder::from_path("test_data/system")
            .with_transaction_log("test_data/system.log1")
            .with_transaction_log("test_data/system.log2")
            .build()?;

        let (keys, keys_versions, keys_deleted, values, values_versions, values_deleted) =
            parser._count_all_keys_and_values_with_modified(Some(filter));
        assert_eq!(
            (1, 0, 0, 3, 0, 0),
            (
                keys,
                keys_versions,
                keys_deleted,
                values,
                values_versions,
                values_deleted
            )
        );
        Ok(())
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_key_filter() -> Result<(), Error> {
        let filter = FilterBuilder::new()
            .add_key_path(r"Software\Microsoft")
            .return_child_keys(true)
            .build()?;
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;
        let (keys, values) = parser.count_all_keys_and_values(Some(&filter));
        assert_eq!(
            (2390, 4791),
            (keys, values),
            "key and/or value count doesn't match expected"
        );

        let mut md5_context = md5::Context::new();
        for key in ParserIterator::new(&parser)
            .with_filter(filter.clone())
            .filter_include_ancestors(true)
            .postorder_iteration(true)
            .iter()
        {
            md5_context.consume(key.path);
        }
        assert_eq!(
            "c04d7a8f64b35f46bc93490701afbaf0",
            format!("{:x}", md5_context.compute()),
            "Expected hash of paths doesn't match"
        );

        let mut keys = 0;
        let mut values = 0;
        for key in ParserIterator::new(&parser)
            .with_filter(filter)
            .filter_include_ancestors(true)
            .iter()
        {
            keys += 1;
            values += key.sub_values.len();
        }
        assert_eq!(
            (2392, 4791),
            (keys, values),
            "key and/or value count doesn't match expected"
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_parser_primary_deleted() {
        let mut parser = ParserBuilder::from_path("test_data/system")
            .recover_deleted(true)
            .build()
            .unwrap();
        let (keys, keys_versions, keys_deleted, values, values_versions, values_deleted) =
            parser._count_all_keys_and_values_with_modified(None);
        assert_eq!(
            (45527, 0, 192, 108055, 0, 225),
            (
                keys,
                keys_versions,
                keys_deleted,
                values,
                values_versions,
                values_deleted
            )
        );
    }

    #[test]
    fn test_parser_get_key() {
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .build()
            .unwrap();

        let sub_key = parser
            .get_key("Control Panel\\Accessibility\\Keyboard Response", false)
            .unwrap()
            .unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let sub_key = parser
            .get_key("\\Control Panel\\Accessibility\\Keyboard Response", false)
            .unwrap()
            .unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let sub_key = parser
            .get_key("Control Panel\\Accessibility", false)
            .unwrap()
            .unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility", sub_key.path);
        assert_eq!(2, sub_key.sub_values.len());

        let sub_key = parser.get_key("Control Panel\\Accessibility\\XYZ", false);
        assert_eq!(Ok(None), sub_key);

        let sub_key = parser.get_key("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", true).unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let sub_key = parser.get_key("CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", true).unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let mut key = parser.get_key("Control Panel", false).unwrap().unwrap();
        assert_eq!(
            "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel",
            key.path
        );
        let sub_key = key
            .get_sub_key_by_path(&mut parser, "Accessibility\\Keyboard Response")
            .unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());
    }

    #[test]
    fn test_parser_get_sub_key() -> Result<(), Error> {
        let filter = FilterBuilder::new()
            .add_key_path("Control Panel\\Accessibility")
            .build()?;
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;
        let mut key = ParserIterator::new(&parser)
            .with_filter(filter)
            .filter_include_ancestors(true)
            .postorder_iteration(true)
            .iter()
            .next()
            .unwrap();
        let sub_key = parser.get_sub_key(&mut key, "Keyboard Response")?.unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let sub_key = parser.get_sub_key(&mut key, "Nope").unwrap();
        assert_eq!(None, sub_key);

        let filter = FilterBuilder::new().add_key_path("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility").key_path_has_root(true).build()?;

        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;
        let mut key = ParserIterator::new(&parser)
            .with_filter(filter)
            .filter_include_ancestors(true)
            .postorder_iteration(true)
            .iter()
            .next()
            .unwrap();
        let sub_key = parser.get_sub_key(&mut key, "Keyboard Response")?.unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let sub_key = parser.get_sub_key(&mut key, "Nope").unwrap();
        assert_eq!(None, sub_key);
        Ok(())
    }

    #[test]
    fn test_get_parent_key() -> Result<(), Error> {
        let filter = FilterBuilder::new()
            .add_key_path("Control Panel\\Accessibility\\On")
            .build()?;
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;

        let mut key = ParserIterator::new(&parser)
            .with_filter(filter)
            .filter_include_ancestors(true)
            .postorder_iteration(true)
            .iter()
            .next()
            .unwrap();
        let parent_key = parser.get_parent_key(&mut key)?.unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility", parent_key.path);
        assert_eq!(2, parent_key.sub_values.len());
        Ok(())
    }

    #[test]
    fn test_get_root_key() {
        let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
            .build()
            .unwrap();
        let root_key = parser.get_root_key().unwrap().unwrap();
        assert_eq!(
            "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}",
            root_key.path
        );
        assert_eq!(0, root_key.sub_values.len());
    }

    #[test]
    fn test_reg_query() -> Result<(), Error> {
        let filter = FilterBuilder::new()
            .add_literal_segment("\\control Panel")
            .add_regex_segment("access.*")
            .add_regex_segment("keyboard.+")
            .return_child_keys(false)
            .build()?;
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;

        let mut parser_iter = ParserIterator::new(&parser)
            .with_filter(filter.clone())
            .filter_include_ancestors(true)
            .postorder_iteration(true)
            .iter();
        let key = parser_iter.next().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Preference", key.path);
        let key = parser_iter.next().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", key.path);
        let kv = parser.count_all_keys_and_values(Some(&filter));
        assert_eq!((2, 10), kv, "if we get 12 values back then we are incorrectly returning values for the Control Panel\\Accessibility key");

        let filter = FilterBuilder::new()
            .add_key_path(r"appevents\schemes\apps\Explorer")
            .add_regex_segment(".*a.*")
            .add_literal_segment(".current")
            .return_child_keys(false)
            .build()?;
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;

        let mut parser_iter = ParserIterator::new(&parser)
            .with_filter(filter.clone())
            .filter_include_ancestors(true)
            .postorder_iteration(true)
            .iter();
        let key = parser_iter.next().unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\AppEvents\Schemes\Apps\Explorer\ActivatingDocument\.Current",
            key.path
        );
        let key = parser_iter.next().unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\AppEvents\Schemes\Apps\Explorer\ActivatingDocument",
            key.path
        );
        let key = parser_iter.next().unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\AppEvents\Schemes\Apps\Explorer\Navigating\.Current",
            key.path
        );
        let key = parser_iter.next().unwrap();
        assert_eq!(
            r"\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\AppEvents\Schemes\Apps\Explorer\Navigating",
            key.path
        );
        let kv = parser.count_all_keys_and_values(Some(&filter));
        assert_eq!((4, 4), kv);
        Ok(())
    }

    #[test]
    fn test_push_stack_to_traverse() -> Result<(), Error> {
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;

        let mut iter_context = ParserIteratorContext::from_parser(&parser, true, None);
        let node10 = CellKeyNode {
            file_offset_absolute: 10,
            ..Default::default()
        };
        assert_eq!(1, iter_context.stack_to_traverse.len()); // initially it has the root node to traverse
        assert_eq!(Ok(()), iter_context.push_check_stack_to_traverse(node10));
        assert_eq!(2, iter_context.stack_to_traverse.len());
        let ret = iter_context.stack_file_offsets.get(&10);
        assert_eq!(&10, ret.unwrap());

        let node10_2 = CellKeyNode {
            file_offset_absolute: 10,
            ..Default::default()
        };
        let ret = iter_context.push_check_stack_to_traverse(node10_2.clone());
        assert_eq!(Err(Error::Any {
            detail: format!("Attempting to add node with same file offset as another node we have processed (potential circular reference): {}", node10_2.file_offset_absolute),
        })
        , ret);
        Ok(())
    }

    #[test]
    fn test_pop_stack_to_traverse() -> Result<(), Error> {
        let parser = ParserBuilder::from_path("test_data/NTUSER.DAT").build()?;

        let mut iter_context = ParserIteratorContext::from_parser(&parser, true, None);
        let node10 = CellKeyNode {
            file_offset_absolute: 10,
            ..Default::default()
        };
        assert_eq!(Ok(()), iter_context.push_check_stack_to_traverse(node10));
        let ret = iter_context.pop_stack_to_traverse();
        assert_eq!(10, ret.unwrap().file_offset_absolute);

        Ok(())
    }
}
