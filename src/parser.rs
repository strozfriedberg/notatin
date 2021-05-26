use std::path::Path;
use nom::{
    number::complete::le_i32
};
use crate::reg_header::{RegHeader, RegHeaderBase};
use crate::filter::Filter;
use crate::err::Error;
use crate::cell_key_node::CellKeyNode;
use crate::hive_bin_header::HiveBinHeader;
use crate::file_info::{FileInfo, ReadSeek};
use crate::state::State;
use crate::track_cell::TrackCell;
use crate::log::LogCode;
use crate::transaction_log;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/
#[derive(Debug)]
pub struct Parser {
    file_info: FileInfo,
    state: State,
    filter: Filter,
    stack_to_traverse: Vec<CellKeyNode>,
    stack_to_return: Vec<CellKeyNode>,
    reg_header: Option<RegHeader>,
    hive_bin_header: Option<HiveBinHeader>
}

impl Parser {
    pub fn from_path<T: AsRef<Path>>(primary_path: T, transaction_log_paths: Option<Vec<T>>, recover_deleted: bool) -> Result<Self, Error> {
        let transaction_logs;
        let mut fh_logs = Vec::new();
        if let Some(log_paths) = transaction_log_paths {
            for log_path in log_paths {
                fh_logs.push(std::fs::File::open(log_path)?);
            }
            transaction_logs = Some(fh_logs);
        }
        else{
            transaction_logs = None;
        }
        Self::from_file_info(FileInfo::from_path(primary_path)?, transaction_logs, None, recover_deleted)
    }

    pub fn from_path_with_filter<T: AsRef<Path>>(primary_path: T, transaction_log_paths: Option<Vec<T>>, filter: Option<Filter>) -> Result<Self, Error> {
        let log_option;
        let mut fh_logs = Vec::new();
        match transaction_log_paths {
            Some(transaction_log_paths) => {
                for log_path in transaction_log_paths {
                    fh_logs.push(std::fs::File::open(log_path)?);
                }
                log_option = Some(fh_logs)
            },
            _ => log_option = None
        }
        Self::from_file_info(FileInfo::from_path(primary_path)?, log_option, filter, false)
    }

    pub fn from_read_seek<T: ReadSeek>(primary_file: T, transaction_logs: Option<Vec<T>>, recover_deleted: bool) -> Result<Self, Error> {
        Self::from_file_info(FileInfo::from_read_seek(primary_file)?, transaction_logs, None, recover_deleted)
    }

    pub fn from_read_seek_with_filter<T: ReadSeek>(primary_file: T, transaction_logs: Option<Vec<T>>, filter: Option<Filter>) -> Result<Self, Error> {
        Self::from_file_info(FileInfo::from_read_seek(primary_file)?, transaction_logs, filter, false)
    }

    fn from_file_info<T: ReadSeek>(file_info: FileInfo, transaction_logs: Option<Vec<T>>, filter: Option<Filter>, recover_deleted: bool) -> Result<Self, Error> {
        let mut parser = Parser {
            file_info,
            state: State::from_transaction_logs(transaction_log::parse(transaction_logs)?, recover_deleted),
            filter: filter.unwrap_or_default(),
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            reg_header: None,
            hive_bin_header: None
        };
        parser.init(recover_deleted)?;
        Ok(parser)
    }

    fn init(&mut self, recover_deleted: bool) -> Result<(), Error> {
        self.init_base_block()?;
        if recover_deleted {
            self.init_recover_deleted()?;
        }
        self.apply_transaction_logs()?;
        self.init_root()?;
        Ok(())
    }

    /// Sets up the parser for iteration
    fn init_root(&mut self) -> Result<(), Error> {
        let input = &self.file_info.buffer[self.file_info.hbin_offset_absolute..];
        let (input, hive_bin_header) = HiveBinHeader::from_bytes(&self.file_info, input)?;
        self.hive_bin_header = Some(hive_bin_header);
        let (kn, _) =
            CellKeyNode::read(
                &self.file_info,
                &mut self.state,
                self.file_info.get_file_offset(input),
                &String::new(),
                &Filter::new() // even if we have a filter, we pass in a null filter for the root since matches by definition
            )?;
        if let Some(cell_key_node_root) = kn {
            self.stack_to_traverse.push(cell_key_node_root);
        }
        Ok(())
    }

    fn init_recover_deleted(&mut self) -> Result<(), Error> {
        self.walk_cells(self.reg_header.as_ref().expect("we just parsed this").base.hive_bins_data_size)?;
        self.state.track_cells.sort_by(|a, b| a.file_offset_absolute.cmp(&b.file_offset_absolute));
        Ok(())
    }

    fn init_base_block(&mut self) -> Result<(), Error> {
        let (input, reg_header) = RegHeader::from_bytes(&self.file_info.buffer)?;
        self.file_info.hbin_offset_absolute = input.as_ptr() as usize - self.file_info.buffer.as_ptr() as usize;
        self.reg_header = Some(reg_header);
        self.state.key_complete = false;
        self.state.value_complete = false;
        Ok(())
    }

    pub(crate) fn apply_transaction_logs(&mut self) -> Result<(), Error> {
        if let Some(logs) = &mut self.state.transaction_logs {
            let primary_reg_header = &self.reg_header.as_ref().expect("Shouldn't be here unless we have a base block").base;
            if primary_reg_header.primary_sequence_number == primary_reg_header.secondary_sequence_number {
                self.state.info.add(LogCode::WarningTransactionLog, &"Skipping transaction logs because the primary file's primary_sequence_number matches the secondary_sequence_number");
            }
            else {
                // put the logs in order of oldest (lowest sequence number) first
                logs.sort_by(|a, b| a.reg_header.primary_sequence_number.cmp(&b.reg_header.primary_sequence_number));

                let primary_file_secondary_sequence_number = primary_reg_header.secondary_sequence_number;
                let mut new_sequence_number = 0;
                for log in logs {
                    if log.reg_header.primary_sequence_number >= primary_file_secondary_sequence_number {
                        if new_sequence_number == 0 || (log.reg_header.primary_sequence_number == new_sequence_number + 1) {
                            new_sequence_number = log.update_bytes(&mut self.file_info, &mut self.state.info);
                        }
                        else {
                            self.state.info.add(
                                LogCode::WarningTransactionLog,
                                &format!("Skipping log file; the log's primary sequence number ({}) does not follow the previous log's last sequence number ({})", log.reg_header.primary_sequence_number, new_sequence_number)
                            );
                        }
                    }
                    else {
                        self.state.info.add(
                            LogCode::WarningTransactionLog,
                            &format!("Skipping log file; the log's primary sequence number ({}) is less than the primary file's secondary sequence number ({})", log.reg_header.primary_sequence_number, primary_file_secondary_sequence_number)
                        );
                    }
                }

                // Update primary file header
                // Update sequence numbers with latest available
                let new_sequence_number_bytes = new_sequence_number.to_le_bytes();
                self.file_info.buffer[4..8].copy_from_slice(&new_sequence_number_bytes);
                self.file_info.buffer[8..12].copy_from_slice(&new_sequence_number_bytes);
                // Update the checksum
                let new_checksum = RegHeaderBase::calculate_checksum(&self.file_info.buffer[..0x200]);
                self.file_info.buffer[508..512].copy_from_slice(&new_checksum.to_le_bytes());

                // read the header again
                self.init_base_block()?;
                self.state.info.add(
                    LogCode::Info,
                    &format!("Applied transaction log(s). Sequence numbers have been updated to 0x{:08X}. New Checksum: 0x{:08X}", new_sequence_number, new_checksum)
                );
            }
        }
        Ok(())
    }

    fn walk_cells(&mut self, hive_bins_size: u32) -> Result<bool, Error> {
        // read hbin then cells
        let mut input = &self.file_info.buffer[self.file_info.hbin_offset_absolute..];
        let mut file_offset_absolute = self.file_info.get_file_offset(input);
        while file_offset_absolute < hive_bins_size as usize {
            let res = HiveBinHeader::from_bytes(&self.file_info, input)?;
            input = res.0;
            let hbin_size = res.1.size as usize;
            let hbin_max = file_offset_absolute + hbin_size;
            file_offset_absolute = self.file_info.get_file_offset(input);
            while file_offset_absolute < hbin_max {
                let (input2, size) = le_i32(input)?;
                let cell_type = TrackCell::read_cell_type(input2);
                let size_abs = size.abs() as u32;
                input = &self.file_info.buffer[file_offset_absolute + size_abs as usize..];
                self.state.track_cells.push(
                    TrackCell {
                        file_offset_absolute,
                        cell_type,
                        is_allocated: size < 0,
                        is_used: false,
                        sequence_num: 999
                    }
                );
                file_offset_absolute = self.file_info.get_file_offset(input);
            }
        }
        Ok(true)
    }

    /// Counts all subkeys and values
    pub fn count_all_keys_and_values(
        &mut self
    ) -> (usize, usize) {
        let mut keys = 0;
        let mut values = 0;
        for key in self {
            keys += 1;
            values += key.sub_values.len();
        }
        (keys, values)
    }

    pub(crate) fn get_file_info(&self) -> &FileInfo {
        &self.file_info
    }
}

impl Iterator for Parser {
    type Item = CellKeyNode;

    // Iterative post-order traversal
    fn next(&mut self) -> Option<Self::Item> {
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
                match node.read_sub_keys(&self.file_info, &mut self.state, &self.filter) {
                    Ok(children) => self.stack_to_traverse.extend(children),
                    Err(e) => self.state.info.add(LogCode::WarningIterator, &format!("Error reading sub keys for {}: {}", node.path, e))
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use md5;
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use crate::filter::{Filter, FindPath};
    use crate::util;

    #[test]
    fn test_parser_iterator() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, true).unwrap();
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (2288, 5470),
            (keys, values)
        );

        let parser = Parser::from_path("test_data/NTUSER.DAT", None, true).unwrap();
        let mut md5_context =  md5::Context::new();
        for key in parser {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "25c1c64894d5107d43d9edd3b17b1a9e",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn test_read_big_reg() {
        let mut parser = Parser::from_path("test_data/SOFTWARE_1_nfury", None, true).unwrap();
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (177877, 293276),
            (keys, values)
        );
    }

    #[test]
    fn test_read_small_reg() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, true).unwrap();
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (2288, 5470),
            (keys, values)
        );

        parser.state.untouched_cells();
    }

    #[test]
    fn test_read_reg_with_logs() {
        {
            let write_file = File::create("SYSTEM_with_logs.jsonl").unwrap();
            let mut writer = BufWriter::new(&write_file);
            let parser = Parser::from_path("test_data/SYSTEM", Some(vec!["test_data/SYSTEM.LOG1", "test_data/SYSTEM.LOG2"]), true).unwrap();
            for key in parser {
                writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap()).expect("panic upon failure");
            }
        }
        {
            let write_file = File::create("SYSTEM.jsonl").unwrap();
            let mut writer = BufWriter::new(&write_file);
            let parser = Parser::from_path("test_data/SYSTEM", None, true).unwrap();
            for key in parser {
                writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap()).expect("panic upon failure");
            }
        }
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_kv_filter() {
        let filter = Filter::from_path(FindPath::from_key_value("Control Panel\\Accessibility\\HighContrast", "Flags"));
        let mut parser = Parser::from_path_with_filter("test_data/NTUSER.DAT", None, Some(filter)).unwrap();
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (4, 1),
            (keys, values)
        );

        let filter = Filter::from_path(FindPath::from_key_value("Control Panel\\Accessibility\\HighContrast", "Flags"));
        let parser = Parser::from_path_with_filter("test_data/NTUSER.DAT", None, Some(filter)).unwrap();
        let mut md5_context =  md5::Context::new();
        for key in parser {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "2f0c1e14b72a26f61bdaf7128895b976",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_key_filter() {
        let filter = Filter::from_path(FindPath::from_key(&r"Software\Microsoft\Office\14.0\Common".to_string()));
        let mut parser = Parser::from_path_with_filter("test_data/NTUSER.DAT", None, Some(filter)).unwrap();
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (45, 304),
            (keys, values),
            "key and/or value count doesn't match expected"
        );

        let filter = Filter::from_path(FindPath::from_key(&r"Software\Microsoft\Office\14.0\Common".to_string()));
        let parser = Parser::from_path_with_filter("test_data/NTUSER.DAT", None, Some(filter)).unwrap();
        let mut md5_context =  md5::Context::new();
        for key in parser {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "6ced711ecdfe62f4ae7f219f3e8341ef",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn dump_registry() {
        let write_file = File::create("FuseHive.jsonl").unwrap();
        let mut writer = BufWriter::new(&write_file);

        let parser = Parser::from_path("test_data/FuseHive", None, true).unwrap();
        for key in parser {
            writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap()).expect("panic upon failure");
        }
    }

    #[test]
    fn common_export_format() {
        //let mut parser = Parser::from_path_with_logs("test_data/SYSTEM", vec!["test_data/SYSTEM.LOG1", "test_data/SYSTEM.LOG2"]).unwrap();
        let mut parser = Parser::from_path("test_data/SYSTEM", None, true).unwrap();
        let write_file = File::create("SYSTEM_common_2").unwrap();
        util::write_common_export_format(&mut parser, write_file).unwrap();
    }
}