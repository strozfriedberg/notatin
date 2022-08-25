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


pub mod xlsx_writer;

use clap::{arg_enum, value_t, App, Arg};
use notatin::{
    cell::Cell,
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    cli_util::parse_paths,
    err::Error,
    filter::{Filter, FilterBuilder},
    parser::{Parser, ParserIterator},
    parser_builder::ParserBuilder,
    progress, util,
};
use std::{
    fs::File,
    io::{BufWriter, Write},
};
use xlsx_writer::WriteXlsx;

fn main() -> Result<(), Error> {
    let matches = App::new("Notatin Registry Dump")
        .version("0.2")
        .arg(Arg::from_usage(
            "-r --recover 'Recover deleted and versioned keys and values'",
        ))
        .arg(Arg::from_usage(
            "--recovered-only 'Only export recovered items (applicable for tsv and xlsx output only)'",
        ))
        .arg(Arg::from_usage(
            "--full-field-info 'Get the offset and length for each key/value field (applicable for jsonl output only)'",
        ))
        .arg(Arg::from_usage(
            "-f --filter=[STRING] 'Key path for filter (ex: \'ControlSet001\\Services\')'",
        ))
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .value_name("FILE(S)")
                .help("Base registry file with optional transaction log(s) (Comma separated list)")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("Output file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::from_usage("<TYPE> 'output type'")
                .short("t")
                .possible_values(&OutputType::variants())
                .case_insensitive(true)
                .default_value("jsonl"),
        )
        .get_matches();

    let (input, logs) = parse_paths(matches.value_of("input").expect("Required value"));
    let output = matches.value_of("output").expect("Required value");
    let recover = matches.is_present("recover");
    let recovered_only = matches.is_present("recovered-only");
    let get_full_field_info = matches.is_present("full-field-info");
    let output_type = value_t!(matches, "TYPE", OutputType).unwrap_or_else(|e| e.exit());

    let mut parser_builder = ParserBuilder::from_path(input);
    parser_builder.update_console(true);
    parser_builder.recover_deleted(recover);
    parser_builder.get_full_field_info(get_full_field_info);
    for log in logs.unwrap_or_default() {
        parser_builder.with_transaction_log(log);
    }
    let parser = parser_builder.build()?;

    let filter = match matches.value_of("filter") {
        Some(f) => Some(
            FilterBuilder::new()
                .add_key_path(f)
                .return_child_keys(true)
                .build()?,
        ),
        None => None,
    };

    let mut console = progress::new(true);
    console.write("Writing file")?;
    if output_type == OutputType::Xlsx {
        WriteXlsx::new(output, recovered_only).write(&parser, filter)?;
    } else if output_type == OutputType::Tsv {
        WriteTsv::new(output, recovered_only)?.write(&parser, filter)?;
    } else {
        let write_file = File::create(output)?;
        if output_type == OutputType::Common {
            util::write_common_export_format(&parser, filter, write_file)?;
        } else {
            let mut iter = ParserIterator::new(&parser);
            if let Some(filter) = filter {
                iter.with_filter(filter);
            }
            let mut writer = BufWriter::new(write_file);
            for (index, key) in iter.iter().enumerate() {
                console.update_progress(index)?;
                writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap())?;
            }
        }
    }
    console.write(&format!("\nFinished writing {}\n", output))?;
    Ok(())
}

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum OutputType {
        Jsonl,
        Common,
        Tsv,
        Xlsx
    }
}

struct WriteTsv {
    index: usize,
    recovered_only: bool,
    writer: BufWriter<File>,
    console: Box<dyn progress::UpdateProgressTrait>,
}

impl WriteTsv {
    fn new(output: &str, recovered_only: bool) -> Result<Self, Error> {
        let write_file = File::create(output)?;
        let writer = BufWriter::new(write_file);
        Ok(WriteTsv {
            index: 0,
            recovered_only,
            writer,
            console: progress::new(true),
        })
    }

    fn write(&mut self, parser: &Parser, filter: Option<Filter>) -> Result<(), Error> {
        let mut iter = ParserIterator::new(parser);
        if let Some(filter) = filter {
            iter.with_filter(filter);
        }

        writeln!(self.writer,"Index\tKey Path\tValue Name\tValue Data\tTimestamp\tStatus\tPrevious Seq Num\tModifying Seq Num\tFlags\tAccess Flags\tValue Type\tLogs")?;
        for (index, key) in iter.iter().enumerate() {
            self.console.update_progress(index)?;
            self.write_key_tsv(&key, false)?;
        }
        writeln!(self.writer, "\nLogs\n-----------")?;
        parser.get_parse_logs().write::<File>(&mut self.writer)?;
        Ok(())
    }

    fn write_value_tsv(
        &mut self,
        cell_key_node: &CellKeyNode,
        value: &CellKeyValue,
    ) -> Result<(), Error> {
        if !self.recovered_only || value.has_or_is_recovered() {
            self.index += 1;
            writeln!(
                self.writer,
                "{index}\t{key_path}\t{value_name}\t{value_data}\t\t{status:?}\t{prev_seq_num}\t{mod_seq_num}\t\t\t{value_type}\t{logs}",
                index = self.index,
                key_path = util::escape_string(&cell_key_node.path),
                value_name = util::escape_string(&value.get_pretty_name()),
                value_data = util::escape_string(&value.get_content().0.to_string()),
                status = value.cell_state,
                prev_seq_num = Self::get_sequence_num_string(value.sequence_num),
                mod_seq_num = Self::get_sequence_num_string(value.updated_by_sequence_num),
                value_type = value.get_content().0.get_type(),
                logs = util::escape_string(&value.logs.to_string())
            )?;
        }
        Ok(())
    }

    fn write_key_tsv(
        &mut self,
        cell_key_node: &CellKeyNode,
        key_modified: bool,
    ) -> Result<(), Error> {
        if !self.recovered_only || cell_key_node.has_or_is_recovered() {
            let mut logs = cell_key_node.logs.clone();
            self.index += 1;
            writeln!(
                self.writer,
                "{index}\t{key_path}\t\t\t{timestamp}\t{status:?}\t{prev_seq_num}\t{mod_seq_num}\t{flags:?}\t{access_flags:?}\t\t{logs}",
                index = self.index,
                key_path = util::escape_string(&cell_key_node.path),
                timestamp = util::format_date_time(cell_key_node.last_key_written_date_and_time()),
                status = cell_key_node.cell_state,
                prev_seq_num = Self::get_sequence_num_string(cell_key_node.sequence_num),
                mod_seq_num = Self::get_sequence_num_string(cell_key_node.updated_by_sequence_num),
                flags = cell_key_node.key_node_flags(&mut logs),
                access_flags = cell_key_node.access_flags(&mut logs),
                logs = util::escape_string(&cell_key_node.logs.to_string())
            )?;

            for sub_key in &cell_key_node.versions {
                self.write_key_tsv(sub_key, true)?;
            }
        }

        if !key_modified {
            // don't output values for modified keys; current/modified/deleted vals will be output via the current version of the key
            for value in cell_key_node.value_iter() {
                self.write_value_tsv(cell_key_node, &value)?;

                for sub_value in &value.versions {
                    self.write_value_tsv(cell_key_node, sub_value)?;
                }
            }
        }
        Ok(())
    }

    fn get_sequence_num_string(seq_num: Option<u32>) -> String {
        match seq_num {
            Some(seq_num) => format!("{}", seq_num),
            _ => String::new(),
        }
    }
}
