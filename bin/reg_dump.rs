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

use clap::{arg_enum, value_t, App, Arg};
use notatin::{
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    cli_util::parse_paths,
    err::Error,
    filter::{Filter, RegQueryBuilder},
    parser_builder::{ParserBuilder, ParserBuilderTrait},
    util::{format_date_time, write_common_export_format},
};
use std::{
    fs::File,
    io::{BufWriter, Write},
};

fn main() -> Result<(), Error> {
    let matches = App::new("Notatin Registry Dump")
        .version("0.1")
        .arg(Arg::from_usage(
            "-r --recover 'Recover deleted and versioned keys and values'",
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
    let output_type = value_t!(matches, "TYPE", OutputType).unwrap_or_else(|e| e.exit());

    let mut parser_builder = ParserBuilder::from_path(input).recover_deleted(recover);
    if let Some(f) = matches.value_of("filter") {
        parser_builder = parser_builder.with_filter(Filter::from_path(
            RegQueryBuilder::from_key(f).return_child_keys(true).build(),
        ));
    }
    for log in logs.unwrap_or_default() {
        parser_builder = parser_builder.with_transaction_log(log);
    }
    let mut parser = parser_builder.build()?;

    let write_file = File::create(output)?;

    match output_type {
        OutputType::Tsv => {
            let mut writer = BufWriter::new(write_file);
            //write!(writer, "{}", std::str::from_utf8(&vec![0xEF, 0xBB, 0xBF]).expect("known good bytes (utf8 BOM)"))?; // need explicit BOM to keep Excel happy with multibyte UTF8 chars
            writeln!(writer,"Key Path\tValue Name\tStatus\tKey Original Sequence Number\tKey Modifying Sequence Number\tValue Original Sequence Number\tValue Modifying Sequence Number\tTimestamp\tFlags\tAccess Flags\tValue\tLogs")?;
            for key in parser.iter() {
                versions_tsv(&key, &mut writer, "Current", false)?;
            }
            writeln!(writer, "\nLogs\n-----------")?;
            parser.get_parse_logs().write(&mut writer)?;
        }
        OutputType::Common => {
            write_common_export_format(&mut parser, write_file)?;
        }
        OutputType::Jsonl => {
            let mut writer = BufWriter::new(write_file);
            for key in parser.iter() {
                writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap())?;
            }
        }
    }

    Ok(())
}

fn get_value_status(value: &CellKeyValue, modified: bool) -> String {
    if value.is_deleted() {
        "Deleted".to_string()
    } else if modified {
        "Modified".to_string()
    } else {
        "Current".to_string()
    }
}

fn write_value_tsv(
    cell_key_node: &CellKeyNode,
    value: &CellKeyValue,
    writer: &mut BufWriter<File>,
    status: &str,
) -> Result<(), Error> {
    let write_status;
    if value.is_deleted() {
        write_status = "Deleted";
    } else {
        write_status = status;
    }
    writeln!(
        writer,
        "{}\t{}\t{}\t{:?}\t{:?}\t{:?}\t{:?}\t\t\t\t{:?}\t{}",
        cell_key_node.path,
        value.get_pretty_name(),
        write_status,
        cell_key_node.sequence_num,
        cell_key_node.updated_by_sequence_num,
        value.sequence_num,
        value.updated_by_sequence_num,
        value.get_content().0,
        value.logs
    )?;
    Ok(())
}

fn versions_tsv(
    cell_key_node: &CellKeyNode,
    writer: &mut BufWriter<File>,
    status: &str,
    key_modified: bool,
) -> Result<(), Error> {
    let write_status;
    if cell_key_node.is_deleted() {
        write_status = "Deleted";
    } else {
        write_status = status;
    }
    writeln!(
        writer,
        "{}\t\t{}\t{:?}\t{:?}\t\t\t{}\t{:?}\t{:?}\t\t{}",
        cell_key_node.path,
        write_status,
        cell_key_node.sequence_num,
        cell_key_node.updated_by_sequence_num,
        format_date_time(cell_key_node.last_key_written_date_and_time),
        cell_key_node.key_node_flags,
        cell_key_node.access_flags,
        cell_key_node.logs
    )?;

    for sub_key in &cell_key_node.versions {
        versions_tsv(sub_key, writer, "Modified", true)?;
    }

    if !key_modified {
        // don't output values for modified keys; current/modified/deleted vals will be output via the current version of the key
        for value in cell_key_node.value_iter() {
            write_value_tsv(
                cell_key_node,
                &value,
                writer,
                &get_value_status(&value, false),
            )?;

            for sub_value in &value.versions {
                write_value_tsv(
                    cell_key_node,
                    sub_value,
                    writer,
                    &get_value_status(&value, true),
                )?;
            }
        }
    }
    Ok(())
}

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum OutputType {
        Jsonl,
        Common,
        Tsv
    }
}
