use std::collections::HashMap;
use std::path::Path;
use crate::base_block::{BaseBlock, BaseBlockBase, FileType};
use crate::err::Error;
use crate::cell_key_node::CellKeyNode;
use crate::hive_bin_header::HiveBinHeader;
use crate::file_info::{FileInfo, ReadSeek};
use crate::state::State;
use crate::log::{LogCode, Logs};
use crate::transaction_log::TransactionLog;
use crate::filter::{Filter, FindPath};

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/
#[derive(Debug)]
pub struct Parser {
    pub(crate) file_info: FileInfo,
    pub(crate) state: State,
    filter: Filter,
    base_block: Option<BaseBlock>,
    hive_bin_header: Option<HiveBinHeader>,
    cell_key_node_root: Option<CellKeyNode>,

    // members to support iteration
    stack_to_traverse: Vec<CellKeyNode>,
    stack_to_return: Vec<CellKeyNode>,
    get_modified: bool
}

impl Parser {
    pub fn from_path<T: AsRef<Path>>(primary_path: T, transaction_log_paths: Option<Vec<T>>, filter: Option<Filter>, recover_deleted: bool) -> Result<Self, Error> {
        match transaction_log_paths {
            Some(log_paths) => {
                let mut fh_logs = Vec::new();
                for log_path in log_paths {
                    fh_logs.push(std::fs::File::open(log_path)?);
                }
                Self::from_file_info_with_logs(FileInfo::from_path(primary_path)?, fh_logs, filter, recover_deleted)
            },
            None => Self::from_file_info(FileInfo::from_path(primary_path)?, filter, recover_deleted)
        }
    }

    pub fn from_read_seek<T: ReadSeek>(primary_file: T, transaction_logs: Option<Vec<T>>, filter: Option<Filter>, recover_deleted: bool) -> Result<Self, Error> {
        match transaction_logs {
            Some(transaction_logs) => Self::from_file_info_with_logs(FileInfo::from_read_seek(primary_file)?, transaction_logs, filter, recover_deleted),
            None => Self::from_file_info(FileInfo::from_read_seek(primary_file)?, filter, recover_deleted),
        }
    }

    pub fn from_read_seek_with_filter<T: ReadSeek>(primary_file: T, filter: Filter) -> Result<Self, Error> {
        Self::from_file_info(FileInfo::from_read_seek(primary_file)?, Some(filter), false)
    }

    fn from_file_info(file_info: FileInfo, filter: Option<Filter>, recover_deleted: bool) -> Result<Self, Error> {
        let mut parser = Parser {
            file_info,
            state: State::from_transaction_logs(None, recover_deleted),
            filter: filter.unwrap_or_default(),
            base_block: None,
            hive_bin_header: None,
            cell_key_node_root: None,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            get_modified: false
        };
        parser.init(recover_deleted)?;
        Ok(parser)
    }

    fn from_file_info_with_logs<T: ReadSeek>(file_info: FileInfo, transaction_logs: Vec<T>, filter: Option<Filter>, recover_deleted: bool) -> Result<Self, Error> {
        let mut parser = Parser {
            file_info,
            state: State::from_transaction_logs(TransactionLog::parse(Some(transaction_logs))?, recover_deleted),
            filter: filter.unwrap_or_default(),
            base_block: None,
            hive_bin_header: None,
            cell_key_node_root: None,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            get_modified: false
        };
        parser.init(recover_deleted)?;
        Ok(parser)
    }

    pub fn init(&mut self, recover_deleted: bool) -> Result<(), Error> {
        let (is_supported_format, has_bad_checksum) = self.init_base_block()?;
        if is_supported_format {
            if recover_deleted {
             //   self.init_recover_deleted()?;
            }
            self.apply_transaction_logs(has_bad_checksum)?;
            self.init_root()?;
            self.init_key_iter();
        }
        Ok(())
    }

    pub(crate) fn init_root(&mut self) -> Result<(), Error> {
        self.state.key_complete = false;
        self.state.value_complete = false;

        let input = &self.file_info.buffer[self.file_info.hbin_offset_absolute..];
        let (input, hive_bin_header) = HiveBinHeader::from_bytes(&self.file_info, input)?;
        self.hive_bin_header = Some(hive_bin_header);
        let (kn, _) =
            CellKeyNode::read(
                &self.file_info,
                &mut self.state,
                self.file_info.get_file_offset(input),
                &String::new(),
                &self.filter,
                None,
                true
            )?;
        self.cell_key_node_root = kn;
        Ok(())
    }

    /// Returns a tuple of (is_supported_format, has_bad_checksum)
    fn init_base_block(&mut self) -> Result<(bool, bool), Error> {
        let (input, base_block) = BaseBlock::from_bytes(&self.file_info.buffer)?;
        self.file_info.hbin_offset_absolute = input.as_ptr() as usize - self.file_info.buffer.as_ptr() as usize;
        self.base_block = Some(base_block);
        Ok(self.check_base_block())
    }

    /// Checks if the base block is a supported format. Returns a tuple of (is_supported_format, has_bad_checksum)
    fn check_base_block(&mut self) -> (bool, bool) {
        if self.is_supported_file_type() {
            let mut has_bad_checksum = false;
            let base_block = &self.base_block.as_ref().expect("Shouldn't be here unless we've parsed the base block").base;
            if base_block.primary_sequence_number != base_block.secondary_sequence_number {
                self.state.info.add(
                    LogCode::WarningBaseBlock,
                    &format!("Hive requires recovery: primary and secondary sequence numbers do not match. {}, {}",
                        base_block.primary_sequence_number,
                        base_block.secondary_sequence_number
                    )
                );
            }
            let checksum = BaseBlockBase::calculate_checksum(&self.file_info.buffer[..0x200]);
            if checksum != base_block.checksum {
                self.state.info.add(LogCode::WarningBaseBlock, &"Hive requires recovery: base block checksum is wrong.");
                has_bad_checksum = true;
            }
            return (true, has_bad_checksum);
        }
        else {
            self.state.info.add(LogCode::WarningBaseBlock, &"Unsupported registry file type.");
        }
        (false, false)
    }

    fn is_supported_file_type(&self) -> bool {
        self.base_block.as_ref().expect("Shouldn't be here unless we've parsed the base block").base.file_type != FileType::Unknown
    }

    fn prepare_transaction_logs(&mut self, primary_base_block: &BaseBlockBase, transaction_logs: &mut Vec<TransactionLog>, has_bad_checksum: bool) -> Result<bool, Error> {
        if has_bad_checksum {
            transaction_logs.sort_by(|a, b| b.base_block.primary_sequence_number.cmp(&a.base_block.primary_sequence_number));
            self.state.info.add(LogCode::WarningBaseBlock, &"Applying recovered base block");
            let newest_log = transaction_logs.first().expect("shouldn't be here unless we have logs");
            self.file_info.buffer[..512].copy_from_slice(&newest_log.base_block_bytes);

            // Per https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#new-format-1:
            //  "If a primary file contains an invalid base block, only the transaction log file with latest log entries is used in the recovery."
            transaction_logs.truncate(1);

            self.init_base_block()?;
        }
        if primary_base_block.primary_sequence_number == primary_base_block.secondary_sequence_number {
            self.state.info.add(LogCode::WarningTransactionLog, &"Skipping transaction logs because the primary file's primary_sequence_number matches the secondary_sequence_number");
            return Ok(false);
        }

        // put the logs in order of oldest (lowest sequence number) first
        transaction_logs.sort_by(|a, b| a.base_block.primary_sequence_number.cmp(&b.base_block.primary_sequence_number));
        Ok(true)
    }

    fn update_header_after_transaction_logs(&mut self, new_sequence_number: u32) -> Result<(), Error> {
        // Update primary file header
        const PRIMARY_SEQUENCE_NUMBER_OFFSET: usize = 4;
        const SECONDARY_SEQUENCE_NUMBER_OFFSET: usize = 8;
        // Update sequence numbers with latest available
        let new_sequence_number_bytes = new_sequence_number.to_le_bytes();
        self.file_info.buffer[PRIMARY_SEQUENCE_NUMBER_OFFSET..PRIMARY_SEQUENCE_NUMBER_OFFSET + new_sequence_number_bytes.len()].copy_from_slice(&new_sequence_number_bytes);
        self.file_info.buffer[SECONDARY_SEQUENCE_NUMBER_OFFSET..SECONDARY_SEQUENCE_NUMBER_OFFSET + new_sequence_number_bytes.len()].copy_from_slice(&new_sequence_number_bytes);
        // Update the checksum
        let new_checksum = BaseBlockBase::calculate_checksum(&self.file_info.buffer[..0x200]);
        self.file_info.buffer[508..512].copy_from_slice(&new_checksum.to_le_bytes());

        // read the header again
        self.init_base_block()?;
        self.state.info.add(
            LogCode::Info,
            &format!("Applied transaction log(s). Sequence numbers have been updated to {}. New Checksum: 0x{:08X}", new_sequence_number, new_checksum)
        );
        Ok(())
    }

    fn apply_transaction_logs(&mut self, has_bad_checksum: bool) -> Result<(), Error> {
        if self.state.transaction_logs.is_some() {
            let mut transaction_logs = self.state.transaction_logs.as_ref().unwrap().clone();
            let primary_base_block = self.base_block.as_ref().expect("Shouldn't be here unless we have a base block").base.clone();
            if self.prepare_transaction_logs(&primary_base_block, &mut transaction_logs, has_bad_checksum)? {
                let mut new_sequence_number: u32 = 0;
                let mut original_items = TransactionLog::get_reg_items(self, 0)?;

                for log in transaction_logs {
                    if log.base_block.primary_sequence_number >= primary_base_block.secondary_sequence_number {
                        if new_sequence_number == 0 || (log.base_block.primary_sequence_number == new_sequence_number + 1) {
                            let (new_sequence_number_ret, prior_reg_items) =
                                log.update_bytes(
                                    self,
                                    &primary_base_block,
                                    original_items
                                );
                            original_items = prior_reg_items;
                            new_sequence_number = new_sequence_number_ret;
                        }
                        else {
                            self.state.info.add(
                                LogCode::WarningTransactionLog,
                                &format!("Skipping log file; the log's primary sequence number ({}) does not follow the previous log's last sequence number ({})", log.base_block.primary_sequence_number, new_sequence_number)
                            );
                        }
                    }
                    else {
                        self.state.info.add(
                            LogCode::WarningTransactionLog,
                            &format!("Skipping log file; the log's primary sequence number ({}) is less than the primary file's secondary sequence number ({})", log.base_block.primary_sequence_number, primary_base_block.secondary_sequence_number)
                        );
                    }
                }
                self.update_header_after_transaction_logs(new_sequence_number)?;
            }
        }
        Ok(())
    }

    /// Counts all subkeys and values
    pub fn count_all_keys_and_values(
        &mut self
    ) -> (usize, usize) {
        let mut keys = 0;
        let mut values = 0;
        for key in self.iter() {
            keys += 1;
            values += key.sub_values.len();
        }
        (keys, values)
    }

    /// Counts all subkeys and values
    pub(crate) fn _count_all_keys_and_values_with_modified(
        &mut self
    ) -> (usize, usize, usize, usize, usize, usize) {
        let mut keys = 0;
        let mut keys_versions = 0;
        let mut keys_deleted = 0;
        let mut values = 0;
        let mut values_versions = 0;
        let mut values_deleted = 0;

        for mut key in self.iter() {
            keys += 1;
            keys_versions += key.versions.len();
            keys_deleted += key.deleted_keys.len();
            values_deleted += key.deleted_values.len();
            values += key.sub_values.len();
            for value in key.value_iter() {
                values_versions += value.versions.len();
            }
        }
        (keys, keys_versions, keys_deleted, values, values_versions, values_deleted)
    }

    pub(crate) fn get_file_info(&self) -> &FileInfo {
        &self.file_info
    }

    pub fn get_parse_logs(&self) -> &Logs {
        &self.state.info
    }

    // the methods below are here to support the python interface
    pub fn get_root_key(&mut self) -> Result<Option<CellKeyNode>, Error> {
        match &self.base_block {
            Some(bb) => {
                let (root, _) = CellKeyNode::read(
                    &self.file_info,
                    &mut self.state,
                    bb.base.root_cell_offset_relative as usize + self.file_info.hbin_offset_absolute,
                    &String::new(),
                    &Filter::new(),
                    None,
                    true
                )?;
                Ok(root)
            },
            _ => Ok(None)
        }
    }

    pub fn get_sub_key(
        &mut self,
        cell_key_node: &mut CellKeyNode,
        name: &str,
    ) -> Result<Option<CellKeyNode>, Error> {
        let key_path_sans_root = &cell_key_node.path[self.state.get_root_path_offset(&cell_key_node.path)..];
        let filter = Filter::from_path(FindPath::from_key(&(key_path_sans_root.to_string() + "\\" + name), false, false));
        cell_key_node
            .read_sub_keys_internal(&self.file_info, &mut self.state, &filter, true, None, false)
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
                    // if key_path_has_root, strip that before searching
                    if key_path_has_root {
                        if let Some(first_char) = key_path.chars().next() {
                            if first_char == '\\' {
                                key_path = &key_path[1.. ];
                            }
                        }
                        if let Some(slash_offset) = key_path.find('\\') {
                            key_path = &key_path[slash_offset + 1 .. ];
                        }
                    }
                    let key = root.get_sub_key_by_path(self, &key_path);
                    Ok(key)
                }
                else {
                    Ok(None)
                }
            },
            _ => Ok(None)
        }
    }

    pub fn get_parent_key(
        &mut self,
        cell_key_node: &mut CellKeyNode
    ) -> Result<Option<CellKeyNode>, Error> {
        let mut parent_path = cell_key_node.path.clone();
        let last_slash_offset = parent_path.rfind('\\');
        parent_path.truncate(last_slash_offset.unwrap()); // todo: handle unwrap
        let last_slash_offset = parent_path.rfind('\\');
        parent_path.truncate(last_slash_offset.unwrap());

        let (parent, _) = CellKeyNode::read(
            &self.file_info,
            &mut self.state,
            cell_key_node.parent_key_offset_relative as usize + self.file_info.hbin_offset_absolute,
            &parent_path,
            &Filter::new(),
            None,
            true
        )?;
        Ok(parent)
    }

    pub fn iter(&mut self) -> ParserIterator<'_> {
        self.init_iter_inner(true);
        ParserIterator {
            inner: self
        }
    }

    pub(crate) fn iter_skip_modified(&mut self) -> ParserIterator<'_> {
        self.init_iter_inner(false);
        ParserIterator {
            inner: self
        }
    }

    pub fn init_key_iter(&mut self) {
        self.init_iter_inner(true)
    }

    fn init_iter_inner(&mut self, get_modified: bool) {
        self.state.reset_filter_state();
        self.stack_to_traverse = Vec::new();
        self.stack_to_return = Vec::new();
        self.get_modified = get_modified;
        if let Some(cell_key_node_root) = &self.cell_key_node_root {
            self.stack_to_traverse.push(cell_key_node_root.clone());
        }
    }

    // Iterative post-order traversal
    pub fn next_key(&mut self) -> Option<CellKeyNode> {
        while !self.stack_to_traverse.is_empty() {
            // first check to see if we are done with anything on stack_to_return;
            // if so, we can pop, return it, and carry on (without this check we'd push every node onto the stack before returning anything)
            if !self.stack_to_return.is_empty() {
                let last = self.stack_to_return.last().expect("We checked that stack_to_return wasn't empty");
                if last.track_returned == last.number_of_sub_keys {
                    return Some(self.stack_to_return.pop().expect("We checked that stack_to_return wasn't empty"));
                }
            }

            let mut node = self.stack_to_traverse.pop().expect("We checked that stack_to_traverse wasn't empty");
            if node.number_of_sub_keys > 0 {
                let (children, _) = node.read_sub_keys_internal(&self.file_info, &mut self.state, &self.filter, false, None, self.get_modified);
                //debug_assert_eq!(node.number_of_sub_keys as usize, children.len());
                self.stack_to_traverse.extend(children);
            }
            if !self.stack_to_return.is_empty() {
                let last = self.stack_to_return.last_mut().expect("We checked that stack_to_return wasn't empty");
                last.track_returned += 1;
            }
            self.stack_to_return.push(node);
        }

        // Handle any remaining elements
        if !self.stack_to_return.is_empty() {
            return Some(self.stack_to_return.pop().expect("We just checked that stack_to_return wasn't empty"));
        }
        None
    }
}

// key: (key_path, value_name)  value: (hash, file_offset_absolute, sequence_num)
pub type RegItems = HashMap<(String, Option<String>), (blake3::Hash, usize, u32)>;

pub struct ParserIterator<'a> {
    inner: &'a mut Parser
}

impl Iterator for ParserIterator<'_> {
    type Item = CellKeyNode;

    // Iterative post-order traversal
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5;
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use blake3::Hash;
    use crate::filter::{Filter, FindPath};
    use crate::util;

    #[test]
    fn test_parser_iterator() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, None, true).unwrap();
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (2853, 5523),
            (keys, values)
        );

        let mut md5_context =  md5::Context::new();
        for key in parser.iter() {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "fdc7e9feb8b1d8c6f196d11d8bbfd028",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn test_parser_iterator_next() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, None, true).unwrap();
        let mut keys = 0;
        let mut values = 0;
        parser.init_key_iter();
        loop {
            match parser.next_key() {
                Some(mut key) => {
                    keys += 1;
                    key.init_value_iter();
                    loop {
                        match key.next_value() {
                            Some(_) => values += 1,
                            None => break
                        }
                    }
                },
                None => break
            };
        }
        assert_eq!(
            (2853, 5523),
            (keys, values)
        );
    }

    #[test]
    fn test_reg_logs() {
        let mut parser = Parser::from_path(
            "/home/kstone/code/rust_parser_2/test_data/SYSTEM",
            Some(vec!["/home/kstone/code/rust_parser_2/test_data/SYSTEM.LOG1", "/home/kstone/code/rust_parser_2/test_data/SYSTEM.LOG2"]),
            None,
            true
        ).unwrap();

        let (keys, keys_versions, keys_deleted, values, values_versions, values_deleted) = parser.count_all_keys_and_values_with_modified();
        assert_eq!(
            (19908, 423, 0, 49616, 196, 0),
            (keys, keys_versions, keys_deleted, values, values_versions, values_deleted)
        );
    }

    #[test]
    fn test_reg_logs_with_filter() {
        let mut parser = Parser::from_path(
            "/home/kstone/code/rust_parser_2/test_data/SoftwareKim",
            Some(vec!["/home/kstone/code/rust_parser_2/test_data/SoftwareKim.LOG1", "/home/kstone/code/rust_parser_2/test_data/SoftwareKim.LOG2"]),
            Some(Filter::from_path(FindPath::from_key("WOW6432Node\\TortoiseOverlays", false, true))),
            true
        ).unwrap();

        let (keys, keys_versions, keys_deleted, values, values_versions, values_deleted) = parser.count_all_keys_and_values_with_modified();
        assert_eq!(
            (19908, 423, 0, 49616, 196, 0),
            (keys, keys_versions, keys_deleted, values, values_versions, values_deleted)
        );
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_kv_filter() {
        let filter = Filter::from_path(FindPath::from_key_value("Control Panel\\Accessibility\\HighContrast", "Flags", false));
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, Some(filter), false).unwrap();
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (4, 1),
            (keys, values)
        );

        let mut md5_context =  md5::Context::new();
        for key in parser.iter() {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "75639d0ba098a3f4ab15a5e906dadcc1",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_kv_filter2() {
        let filter = Filter::from_path(FindPath::from_key_value(r"ControlSet001\Control\DeviceContainers\{48ae4b41-eeac-57b9-8d0c-6752dfa94bf5}\Properties\{78c34fc8-104a-4aca-9ea4-524d52996e57}\0050", "", false));
        let mut parser = Parser::from_path("test_data/asdf_test_data/SYSTEM", None, Some(filter), false).unwrap();
        let mut key = parser.next_key().unwrap();
        let value = key.next_value();
        let t=3;

    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_key_filter() {
        let filter = Filter::from_path(FindPath::from_key(&r"Software\Microsoft".to_string(), false, true));
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, Some(filter), false).unwrap();
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (2392, 4791),
            (keys, values),
            "key and/or value count doesn't match expected"
        );

        let mut md5_context =  md5::Context::new();
        for key in parser.iter() {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "a9ea6a62091b803fe501d5c1c6f6d23d",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn test_parser_get_key() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, None, false).unwrap();
        let sub_key = parser.get_key("Control Panel\\Accessibility\\Keyboard Response", false).unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let sub_key = parser.get_key("Control Panel\\Accessibility", false).unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility", sub_key.path);
        assert_eq!(2, sub_key.sub_values.len());

        let sub_key = parser.get_key("Control Panel\\Accessibility\\XYZ", false);
        assert_eq!(Ok(None), sub_key);

        let sub_key = parser.get_key("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", true).unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let mut key = parser.get_key("Control Panel", false).unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel", key.path);
        let sub_key = key.get_sub_key_by_path(&mut parser, &"Accessibility\\Keyboard Response").unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());
    }

    #[test]
    fn test_parser_get_sub_key() {
        let filter = Filter::from_path(FindPath::from_key("Control Panel\\Accessibility", false, false));
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, Some(filter), false).unwrap();
        let mut key = parser.iter().next().unwrap();
        let sub_key = parser.get_sub_key(&mut key, "Keyboard Response").unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let sub_key = parser.get_sub_key(&mut key, "Nope").unwrap();
        assert_eq!(None, sub_key);

        let filter = Filter::from_path(FindPath::from_key("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility", true, false));
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, Some(filter), false).unwrap();
        let mut key = parser.iter().next().unwrap();
        let sub_key = parser.get_sub_key(&mut key, "Keyboard Response").unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response", sub_key.path);
        assert_eq!(9, sub_key.sub_values.len());

        let sub_key = parser.get_sub_key(&mut key, "Nope").unwrap();
        assert_eq!(None, sub_key);
    }

    #[test]
    fn test_get_parent_key() {
        let filter = Filter::from_path(FindPath::from_key("Control Panel\\Accessibility\\Keyboard Response", false, false));
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, Some(filter), false).unwrap();
        let mut key = parser.iter().next().unwrap();
        let parent_key = parser.get_parent_key(&mut key).unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility", parent_key.path);
        assert_eq!(2, parent_key.sub_values.len());
    }

    #[test]
    fn test_get_root_key() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, None, false).unwrap();
        let root_key = parser.get_root_key().unwrap().unwrap();
        assert_eq!("\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}", root_key.path);
        assert_eq!(0, root_key.sub_values.len());
    }

    #[test]
    fn dump_registry() {
        let filter = Filter::from_path(FindPath::from_key("Software\\7-Zip\\FM", false, false));
        let write_file = File::create("office_NTUSER.DAT.jsonl").unwrap();
        let mut writer = BufWriter::new(&write_file);

        let mut parser = Parser::from_path("test_data/asdf_test_data/office_NTUSER.DAT", None, Some(filter), true).unwrap();
        for key in parser.iter() {
            writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap()).expect("panic upon failure");
        }
    }

    #[test]
    fn common_export_format() {
        //let mut parser = Parser::from_path_with_logs("test_data/SYSTEM", vec!["test_data/SYSTEM.LOG1", "test_data/SYSTEM.LOG2"]).unwrap();
        let mut parser = Parser::from_path("test_data/asdf_test_data/office_NTUSER.DAT", None, None, true).unwrap();
        let write_file = File::create("office_NTUSER.DAT_common_export_format.txt").unwrap();
        util::write_common_export_format(&mut parser, write_file).unwrap();
    }
}