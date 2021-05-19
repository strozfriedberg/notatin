use std::path::Path;
use crate::base_block::{FileBaseBlock, FileBaseBlockBase};
use crate::filter::Filter;
use crate::err::Error;
use crate::cell_key_node::CellKeyNode;
use crate::hive_bin_header::HiveBinHeader;
use crate::state::{State, ReadSeek};
use crate::warn::WarningCode;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/
#[derive(Clone, Debug)]
pub struct Parser {
    state: State,
    pub filter: Filter,
    pub stack_to_traverse: Vec<CellKeyNode>,
    pub stack_to_return: Vec<CellKeyNode>,
    pub base_block: Option<FileBaseBlock>,
    pub hive_bin_header: Option<HiveBinHeader>,

    is_init: bool
}

impl Parser {
    pub fn from_path(filename: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_path_filtered(filename, Filter::new())
    }

    pub fn from_path_filtered(filename: impl AsRef<Path>, filter: Filter) -> Result<Self, Error> {
        Ok(Parser {
            state: State::from_path(filename, 0)?,
            filter,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            base_block: None,
            hive_bin_header: None,
            is_init: false
        })
    }

    pub fn from_path_with_logs(filename: impl AsRef<Path>, logs: Vec<impl AsRef<Path>>) -> Result<Self, Error> {
        Self::from_path_filtered_with_logs(filename, logs, Filter::new())
    }

    pub fn from_path_filtered_with_logs(filename: impl AsRef<Path>, logs: Vec<impl AsRef<Path>>, filter: Filter) -> Result<Self, Error> {
        Ok(Parser {
            state: State::from_path_with_logs(filename, logs, 0)?,
            filter,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            base_block: None,
            hive_bin_header: None,
            is_init: false
        })
    }

    pub fn from_read_seek<T: ReadSeek>(data: T) -> Result<Self, Error> {
        Self::from_read_seek_filtered(data, Filter::new())
    }

    pub fn from_read_seek_filtered<T: ReadSeek>(data: T, filter: Filter) -> Result<Self, Error> {
        Ok(Parser {
            state: State::from_read_seek(data, 0)?,
            filter,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            base_block: None,
            hive_bin_header: None,
            is_init: false
        })
    }

    fn init_base_block(&mut self) -> Result<(), Error> {
        let (input, base_block) = FileBaseBlock::from_bytes(&self.state.file_buffer)?;
        self.state.hbin_offset_absolute = input.as_ptr() as usize - self.state.file_buffer.as_ptr() as usize;
        self.base_block = Some(base_block);
        self.state.key_complete = false;
        self.state.value_complete = false;
        Ok(())
    }

    pub fn handle_transaction_logs(&mut self) -> Result<(), Error> {
        if self.state.transaction_logs.is_some() {
            let base_block_base = &self.base_block.as_ref().expect("Shouldn't be here unless we have a base block").base;
            if base_block_base.primary_sequence_number == base_block_base.secondary_sequence_number {
                self.state.info.add(WarningCode::WarningTransactionLog, &"Skipping transaction logs because the primary file primary_sequence_number == the secondary_sequence_number");
            }
            else {
                let logs = self.state.transaction_logs.as_mut().expect("just checked");
                // put the logs in order of oldest (lowest sequence number) first
                logs.sort_by(|a, b| a.base_block.primary_sequence_number.cmp(&b.base_block.primary_sequence_number));
                let primary_file_secondary_sequence_number = self.base_block.as_ref().expect("we must have parsed a base_block if we are here").base.secondary_sequence_number;
                let mut new_sequence_number = 0;
                for log in logs {
                    //if log.has_valid_hashes {
                        if log.base_block.primary_sequence_number >= primary_file_secondary_sequence_number {
                            if new_sequence_number == 0 || (log.base_block.primary_sequence_number == new_sequence_number + 1) {
                                new_sequence_number = log.update_bytes(&mut self.state.file_buffer, &mut self.state.info, self.state.hbin_offset_absolute); // Why are we passing multiple members of self.state into this method rather than just passing in self.state? Because we already have a mutable borrow of self.state above (self.state.transaction_logs.as_mut())
                            }
                            else {
                                self.state.info.add(
                                    WarningCode::WarningTransactionLog,
                                    &format!("Skipping log file; the log's primary sequence number ({}) does not follow the previous log's last sequence number ({})", log.base_block.primary_sequence_number, new_sequence_number)
                                );
                            }
                        }
                        else {
                            self.state.info.add(
                                WarningCode::WarningTransactionLog,
                                &format!("Skipping log file; the log's primary sequence number ({}) is less than the primary file's secondary sequence number ({})", log.base_block.primary_sequence_number, primary_file_secondary_sequence_number)
                            );
                        }
                    //}
                /* else {
                        self.state.warnings.add(
                            WarningCode::WarningTransactionLog,
                            format!("Skipping log file; primary file's checksum doesn't match", log.base_block.primary_sequence_number, new_sequence_number)
                        );
                    }*/
                }

                // Update primary file header
                // Update sequence numbers with latest available
                let new_sequence_number_bytes = new_sequence_number.to_le_bytes();
                self.state.file_buffer[4..8].copy_from_slice(&new_sequence_number_bytes);
                self.state.file_buffer[8..12].copy_from_slice(&new_sequence_number_bytes);
                // Update the checksum
                let new_checksum = FileBaseBlockBase::calculate_checksum(&self.state.file_buffer[..0x200]);
                self.state.file_buffer[508..512].copy_from_slice(&new_checksum.to_le_bytes());

                self.init_base_block()?;
                self.state.info.add(
                    WarningCode::Info,
                    &format!("Applied transaction log(s). Sequence numbers have been updated to 0x{:08X}. New Checksum: 0x{:08X}", new_sequence_number, new_checksum)
                );
            }
        }
        Ok(())
    }

    pub fn init(&mut self) -> Result<bool, Error> {
        self.is_init = true;
        self.init_base_block()?;
        self.handle_transaction_logs()?;

        let input = &self.state.file_buffer[self.state.hbin_offset_absolute..];
        let (input, hive_bin_header) = HiveBinHeader::from_bytes(&self.state, input)?;
        self.hive_bin_header = Some(hive_bin_header);
        let offset = self.state.get_file_offset(input);
        let (kn, _) = CellKeyNode::read(&mut self.state, offset, &String::new(), &Filter::new())?; // we pass in a null filter for the root since matches by definition
        match kn {
            Some(cell_key_node_root) => {
                self.stack_to_traverse.push(cell_key_node_root);
                Ok(true)
            },
            None => Ok(false)
        }
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
}

impl Iterator for Parser {
    type Item = CellKeyNode;

    // iterative post-order traversal
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
                let children = node.read_sub_keys(&mut self.state, &self.filter).unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use crate::filter::{Filter, FindPath};
    use crate::util;
    use md5;

    #[test]
    fn test_parser_iterator() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT").unwrap();
        let res = parser.init();
        assert_eq!(Ok(true), res);

        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (2288, 5470),
            (keys, values)
        );

        let res = parser.init();
        assert_eq!(Ok(true), res);
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
        let mut parser = Parser::from_path("test_data/SOFTWARE_1_nfury").unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );

        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (177877, 293276),
            (keys, values)
        );
    }

    #[test]
    fn test_read_small_reg() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT").unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );

        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (2288, 5470),
            (keys, values)
        );
    }

    #[test]
    fn test_read_reg_with_logs() {
        {
            let write_file = File::create("SYSTEM_with_logs.jsonl").unwrap();
            let mut writer = BufWriter::new(&write_file);
            let mut parser = Parser::from_path_with_logs("test_data/SYSTEM", vec!["test_data/SYSTEM.LOG1", "test_data/SYSTEM.LOG2"]).unwrap();
            let res = parser.init();
            assert_eq!(
                Ok(true),
                res
            );
            for key in parser {
                writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap()).expect("panic upon failure");
            }
        }
        {
            let write_file = File::create("SYSTEM.jsonl").unwrap();
            let mut writer = BufWriter::new(&write_file);
            let mut parser = Parser::from_path("test_data/SYSTEM").unwrap();
            let res = parser.init();
            assert_eq!(
                Ok(true),
                res
            );
            for key in parser {
                writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap()).expect("panic upon failure");
            }
        }
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_kv_filter() {
        let filter = Filter::from_path(FindPath::from_key_value("Control Panel\\Accessibility\\HighContrast", "Flags"));
        let mut parser = Parser::from_path_filtered("test_data/NTUSER.DAT", filter).unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );

        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (4, 1),
            (keys, values)
        );

        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );
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
        let mut parser = Parser::from_path_filtered("test_data/NTUSER.DAT", filter).unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (45, 304),
            (keys, values),
            "key and/or value count doesn't match expected"
        );

        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );
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
        let write_file = File::create("NTUSER.DAT_iterative.jsonl").unwrap();
        let mut writer = BufWriter::new(&write_file);

        let mut parser = Parser::from_path("test_data/NTUSER.DAT").unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );
        for key in parser {
            writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap()).expect("panic upon failure");
        }
    }

    #[test]
    fn wip_common_export_format() {
        /*
        ## Registry common export format
        ## Key format
        ## key,Is Free (A for in use, U for unused),Absolute offset in decimal,KeyPath,,,,LastWriteTime in UTC
        ## Value format
        ## value,Is Free (A for in use, U for unused),Absolute offset in decimal,KeyPath,Value name,Data type (as decimal integer),Value data as bytes separated by a singe space,
        ##
        ## Comparison of deleted keys/values is done to compare recovery of vk and nk records, not the algorithm used to associate deleted keys to other keys and their values.
        ## When including deleted keys, only the recovered key name should be included, not the full path to the deleted key.
        ## When including deleted values, do not include the parent key information.
        ##
        ## The following totals should also be included
        ##
        ## total_keys: total in use key count
        ## total_values: total in use value count
        ## total_deleted_keys: total recovered free key count
        ## total_deleted_values: total recovered free value count
        ##
        ## Before comparison with other common export implementations, the files should be sorted
        ##*/

        let mut parser = Parser::from_path_with_logs("test_data/SYSTEM", vec!["test_data/SYSTEM.LOG1", "test_data/SYSTEM.LOG2"]).unwrap();
        //let mut parser = Parser::from_path("test_data/SYSTEM").unwrap();
        let _ = parser.init();

        let write_file = File::create("SYSTEM_with_logs_common").unwrap();
        let mut writer = BufWriter::new(&write_file);
        let mut keys = 0;
        let mut values = 0;
        for key in parser {
            keys += 1;
            writeln!(&mut writer, "key,A,{},{},,,,{}", key.detail.file_offset_absolute, key.path, key.last_key_written_date_and_time.format("%+")).unwrap();
            for value in key.sub_values {
                values += 1;
                writeln!(&mut writer, "value,A,{},{},{},{:?},{}", value.detail.file_offset_absolute, key.key_name, value.value_name, value.data_type as u32, util::to_hex_string(&value.detail.value_bytes.unwrap()[..])).unwrap();
            }
        }
        writeln!(&mut writer, "## total_keys: {}", keys).unwrap();
        writeln!(&mut writer, "## total_values: {}", values).unwrap();
        writeln!(&mut writer, "## total_deleted_keys").unwrap();
        writeln!(&mut writer, "## total_deleted_values").unwrap();
    }
}