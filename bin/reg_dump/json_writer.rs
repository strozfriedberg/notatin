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
    err::Error,
    filter::Filter,
    parser::{Parser, ParserIterator},
    progress,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::*;

pub(crate) struct WriteJson {}

impl WriteJson {
    pub(crate) fn write<P: AsRef<Path>>(
        out_path: &P,
        parser: &Parser,
        filter: Option<Filter>,
        console: &mut Box<dyn progress::UpdateProgressTrait>,
    ) -> Result<(), Error> {
        let write_file = File::create(out_path)?;
        let mut iter = ParserIterator::new(parser);
        if let Some(filter) = filter {
            iter.with_filter(filter);
        }
        let mut writer = BufWriter::new(write_file);
        for (index, key) in iter.iter().enumerate() {
            console.update_progress(index)?;
            writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap())?;
        }
        Ok(())
    }
}
