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

use notatin::{
    cell::CellState,
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    err::Error,
    filter::Filter,
    parser::{Parser, ParserIterator},
    progress, util,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::*;

pub(crate) struct WriteCommon {
    writer: BufWriter<File>,
}

impl WriteCommon {
    pub(crate) fn new<P: AsRef<Path>>(output: &P) -> Result<Self, Error> {
        let write_file = File::create(output)?;
        let writer = BufWriter::new(write_file);
        Ok(WriteCommon { writer })
    }

    pub(crate) fn write(&mut self, parser: &Parser, filter: Option<Filter>) -> Result<(), Error> {
        writeln!(
            &mut self.writer,
            "## Registry common export format\n\
            ## Key format\n\
            ## key,Is Free,Absolute offset in decimal,KeyPath,,,,LastWriteTime in UTC\n\
            ## Value format\n\
            ## value,Is Free,Absolute offset in decimal,KeyPath,Value name,Data type (as decimal integer),Value data as bytes separated by a singe space,\n\
            ## \"Is Free\" interpretation: A for in use, U for unused from the primary file, D for deleted from the transaction log, M for modified from the transaction log\n\
            ##\n\
            ## Comparison of unused keys/values is done to compare recovery of vk and nk records, not the algorithm used to associate unused keys to other keys and their values.\n\
            ## When including unused keys, only the recovered key name should be included, not the full path to the unused key.\n\
            ## When including unused values, do not include the parent key information.\n\
            ##\n\
            ## The following totals should also be included\n\
            ##\n\
            ## total_keys: total in use key count\n\
            ## total_values: total in use value count\n\
            ## total_unused_keys: total free key count (recovered from primary file)\n\
            ## total_unused_values: total free value count (recovered from primary file)\n\
            ## total_deleted_from_transaction_log_keys: total deleted key count (recovered from transaction logs)\n\
            ## total_deleted_from_transaction_log_values: total deleted value count (recovered from transaction logs)\n\
            ## total_modified_from_transaction_log_keys: total modified key count (recovered from transaction logs)\n\
            ## total_modified_from_transaction_log_values: total modified value count (recovered from transaction logs)\n\
            ##\n\
            ## Before comparison with other common export implementations, the files should be sorted\n\
            ##"
        )?;
        let mut keys = 0;
        let mut values = 0;
        let mut unused_keys = 0;
        let mut unused_values = 0;
        let mut tx_log_deleted_keys = 0;
        let mut tx_log_deleted_values = 0;
        let mut tx_log_modified_keys = 0;
        let mut tx_log_modified_values = 0;

        let mut iter = ParserIterator::new(parser);
        if let Some(filter) = filter {
            iter.with_filter(filter);
        }

        let mut console = progress::new(true);
        for (index, key) in iter.iter().enumerate() {
            console.update_progress(index)?;
            self.write_key(
                &key,
                &mut unused_keys,
                &mut keys,
                &mut tx_log_deleted_keys,
                &mut tx_log_modified_keys,
            )?;
            for mk in &key.versions {
                self.write_key(
                    mk,
                    &mut unused_keys,
                    &mut keys,
                    &mut tx_log_deleted_keys,
                    &mut tx_log_modified_keys,
                )?;
            }

            for value in key.value_iter() {
                self.write_value(
                    &key,
                    &value,
                    &mut unused_values,
                    &mut values,
                    &mut tx_log_deleted_values,
                    &mut tx_log_modified_values,
                )?;

                for mv in value.versions {
                    self.write_value(
                        &key,
                        &mv,
                        &mut unused_values,
                        &mut values,
                        &mut tx_log_deleted_values,
                        &mut tx_log_modified_values,
                    )?;
                }
            }
        }
        writeln!(&mut self.writer, "## total_keys: {}", keys)?;
        writeln!(&mut self.writer, "## total_values: {}", values)?;
        writeln!(&mut self.writer, "## total_unused_keys: {}", unused_keys)?;
        writeln!(
            &mut self.writer,
            "## total_unused_values: {}",
            unused_values
        )?;
        writeln!(
            &mut self.writer,
            "## total_deleted_from_transaction_log_keys: {}",
            tx_log_deleted_keys
        )?;
        writeln!(
            &mut self.writer,
            "## total_deleted_from_transaction_log_values: {}",
            tx_log_deleted_values
        )?;
        writeln!(
            &mut self.writer,
            "## total_modified_from_transaction_log_keys: {}",
            tx_log_modified_keys
        )?;
        writeln!(
            &mut self.writer,
            "## total_modified_from_transaction_log_values: {}",
            tx_log_modified_values
        )?;
        Ok(())
    }

    fn get_alloc_char(state: &CellState) -> &str {
        match state {
            CellState::DeletedPrimaryFile | CellState::DeletedPrimaryFileSlack => "U",
            CellState::DeletedTransactionLog => "D",
            CellState::ModifiedTransactionLog => "M",
            CellState::Allocated => "A",
        }
    }

    fn write_key(
        &mut self,
        key: &CellKeyNode,
        unused_keys: &mut u32,
        keys: &mut u32,
        tx_log_deleted_keys: &mut u32,
        tx_log_modified_keys: &mut u32,
    ) -> Result<(), Error> {
        let key_path = match key.cell_state {
            CellState::DeletedPrimaryFile | CellState::DeletedPrimaryFileSlack => {
                *unused_keys += 1;
                &key.key_name
            } // ## When including unused keys, only the recovered key name should be included, not the full path to the deleted key.
            CellState::Allocated => {
                *keys += 1;
                &key.path[1..]
            } // drop the first slash to match EZ's formatting
            CellState::DeletedTransactionLog => {
                *tx_log_deleted_keys += 1;
                &key.path[1..]
            } // drop the first slash to match EZ's formatting
            CellState::ModifiedTransactionLog => {
                *tx_log_modified_keys += 1;
                &key.path[1..]
            } // drop the first slash to match EZ's formatting
        };
        writeln!(
            self.writer,
            "key,{},{},{},,,,{}",
            Self::get_alloc_char(&key.cell_state),
            key.file_offset_absolute,
            util::escape_string(key_path),
            util::format_date_time(key.last_key_written_date_and_time())
        )?;
        Ok(())
    }

    fn write_value(
        &mut self,
        key: &CellKeyNode,
        value: &CellKeyValue,
        unused_values: &mut u32,
        values: &mut u32,
        tx_log_deleted_values: &mut u32,
        tx_log_modified_values: &mut u32,
    ) -> Result<(), Error> {
        let key_name = match value.cell_state {
            CellState::DeletedPrimaryFile | CellState::DeletedPrimaryFileSlack => {
                *unused_values += 1;
                ""
            } // ## When including unused values, do not include the parent key information
            CellState::Allocated => {
                *values += 1;
                &key.key_name[..]
            }
            CellState::DeletedTransactionLog => {
                *tx_log_deleted_values += 1;
                &key.key_name[..]
            }
            CellState::ModifiedTransactionLog => {
                *tx_log_modified_values += 1;
                &key.key_name[..]
            }
        };
        writeln!(
            self.writer,
            "value,{},{},{},{},{:?},{},",
            Self::get_alloc_char(&value.cell_state),
            value.file_offset_absolute,
            util::escape_string(key_name),
            util::escape_string(&value.get_pretty_name()),
            value.data_type as u32,
            util::to_hex_string(&value.detail.value_bytes().unwrap_or_default()[..])
        )?;
        Ok(())
    }
}
