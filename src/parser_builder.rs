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

pub trait ParserBuilderTrait {
    fn with_filter(self, filter: Filter) -> Self;
    fn recover_deleted(self, recover: bool) -> Self;
}

pub struct ParserBuilderBase {
    filter: Option<Filter>,
    recover_deleted: bool,
}

pub struct ParserBuilderFromPath {
    primary: Box<dyn AsRef<Path>>,
    transaction_logs: Vec<Box<dyn AsRef<Path>>>,
    base: ParserBuilderBase,
}

impl ParserBuilderTrait for ParserBuilderFromPath {
    fn with_filter(mut self, filter: Filter) -> Self {
        self.base.filter = Some(filter);
        self
    }

    fn recover_deleted(mut self, recover: bool) -> Self {
        self.base.recover_deleted = recover;
        self
    }
}

impl ParserBuilderFromPath {
    pub fn with_transaction_log<T: AsRef<Path> + 'static>(mut self, log: T) -> Self {
        self.transaction_logs.push(Box::new(log));
        self
    }

    pub fn build(self) -> Result<Parser, Error> {
        let mut transaction_logs = vec![];
        for transaction_log in self.transaction_logs {
            transaction_logs.push(Box::new(std::fs::File::open(transaction_log.as_ref())?))
        }
        ParserBuilder::build(
            FileInfo::from_path(self.primary.as_ref())?,
            self.base,
            transaction_logs,
        )
    }
}

pub struct ParserBuilderFromFile {
    primary: Box<dyn ReadSeek>,
    transaction_logs: Vec<Box<dyn ReadSeek>>,
    base: ParserBuilderBase,
}

impl ParserBuilderTrait for ParserBuilderFromFile {
    fn with_filter(mut self, filter: Filter) -> Self {
        self.base.filter = Some(filter);
        self
    }

    fn recover_deleted(mut self, recover: bool) -> Self {
        self.base.recover_deleted = recover;
        self
    }
}

impl ParserBuilderFromFile {
    pub fn with_transaction_log<T: ReadSeek + 'static>(mut self, log: T) -> Self {
        self.transaction_logs.push(Box::new(log));
        self
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
        let parsed_transaction_logs;
        let warning_logs;
        if transaction_logs.is_empty() {
            parsed_transaction_logs = None;
            warning_logs = None;
        } else {
            let ret = TransactionLog::parse(Some(transaction_logs))?;
            parsed_transaction_logs = ret.0;
            warning_logs = ret.1;
        }

        let mut parser = Parser {
            file_info,
            state: State::from_transaction_logs(parsed_transaction_logs, base.recover_deleted),
            filter: base.filter.unwrap_or_default(),
            base_block: None,
            hive_bin_header: None,
            cell_key_node_root: None,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            get_modified: false,
        };
        parser.init(base.recover_deleted)?;

        if let Some(warning_logs) = warning_logs {
            parser.state.info.extend(warning_logs);
        }
        Ok(parser)
    }
}
