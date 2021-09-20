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

use crate::err::Error;
use crate::file_info::{FileInfo, ReadSeek};
use crate::filter::Filter;
use crate::parser::Parser;
use crate::state::State;
use crate::transaction_log::TransactionLog;
use std::path::Path;

#[derive(Clone)]
pub struct ParserBuilderBase {
    filter: Option<Filter>,
    recover_deleted: bool,
}

pub struct ParserBuilderFromPath {
    primary: Box<dyn AsRef<Path>>,
    transaction_logs: Vec<Box<dyn AsRef<Path>>>,
    base: ParserBuilderBase,
}

impl ParserBuilderFromPath {
    pub fn recover_deleted(&mut self, recover: bool) -> &mut Self {
        self.base.recover_deleted = recover;
        self
    }

    pub fn with_transaction_log<T: AsRef<Path> + 'static>(&mut self, log: T) -> &mut Self {
        self.transaction_logs.push(Box::new(log));
        self
    }

    pub fn build(&self) -> Result<Parser, Error> {
        let mut transaction_logs = vec![];
        for transaction_log in &self.transaction_logs {
            transaction_logs.push(Box::new(std::fs::File::open(transaction_log.as_ref())?))
        }
        ParserBuilder::build(
            FileInfo::from_path(self.primary.as_ref())?,
            self.base.clone(),
            transaction_logs,
        )
    }
}

pub struct ParserBuilderFromFile {
    primary: Box<dyn ReadSeek>,
    transaction_logs: Vec<Box<dyn ReadSeek>>,
    base: ParserBuilderBase,
}

impl ParserBuilderFromFile {
    // These methods have consuming and reference versions of each because the consuming versions allow for chaining and are cleaner to use,
    // but the python bindings require the reference versions. (Why not a mut ref that returns a reference? Becuase `build()` consumes members of ParserBuilder.)
    pub fn with_filter(mut self, filter: Filter) -> Self {
        self.base.filter = Some(filter);
        self
    }

    pub fn recover_deleted(mut self, recover: bool) -> Self {
        self.recover_deleted_ref(recover);
        self
    }

    pub fn recover_deleted_ref(&mut self, recover: bool) {
        self.base.recover_deleted = recover;
    }

    pub fn with_transaction_log<T: ReadSeek + 'static>(mut self, log: T) -> Self {
        self.with_transaction_log_ref(log);
        self
    }

    pub fn with_transaction_log_ref<T: ReadSeek + 'static>(&mut self, log: T) {
        self.transaction_logs.push(Box::new(log));
    }

    pub fn build(self) -> Result<Parser, Error> {
        let mut transaction_logs = vec![];
        for transaction_log in self.transaction_logs {
            transaction_logs.push(Box::new(transaction_log));
        }
        ParserBuilder::build(
            FileInfo::from_read_seek(self.primary)?,
            self.base,
            transaction_logs,
        )
    }
}

pub struct ParserBuilder {}

impl ParserBuilder {
    pub fn from_path<P: AsRef<Path> + 'static>(primary: P) -> ParserBuilderFromPath {
        ParserBuilderFromPath {
            primary: Box::new(primary),
            transaction_logs: vec![],
            base: ParserBuilderBase {
                filter: None,
                recover_deleted: false,
            },
        }
    }

    pub fn from_file<R: ReadSeek + 'static>(primary: R) -> ParserBuilderFromFile {
        ParserBuilderFromFile {
            primary: Box::new(primary),
            transaction_logs: vec![],
            base: ParserBuilderBase {
                filter: None,
                recover_deleted: false,
            },
        }
    }

    fn build<T: ReadSeek + 'static>(
        file_info: FileInfo,
        base: ParserBuilderBase,
        transaction_logs: Vec<Box<T>>,
    ) -> Result<Parser, Error> {
        let (parsed_transaction_logs, warning_logs) = TransactionLog::parse(transaction_logs)?;

        let mut parser = Parser {
            file_info,
            state: State::default(),
            base_block: None,
            hive_bin_header: None,
            cell_key_node_root: None,
            recover_deleted: base.recover_deleted,
        };
        parser.init(base.recover_deleted, parsed_transaction_logs)?;

        if let Some(warning_logs) = warning_logs {
            parser.state.info.extend(warning_logs);
        }
        Ok(parser)
    }
}
