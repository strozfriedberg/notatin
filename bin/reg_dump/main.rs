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

pub mod common_writer;
pub mod json_writer;
pub mod tsv_writer;
pub mod xlsx_writer;

use clap::{arg, Arg, Command, ValueEnum};
use clap::builder::{EnumValueParser, PossibleValue};
use notatin::{
    cli_util::parse_paths, err::Error, filter::FilterBuilder, parser_builder::ParserBuilder,
    progress,
};

use common_writer::WriteCommon;
use json_writer::WriteJson;
use tsv_writer::WriteTsv;
use xlsx_writer::WriteXlsx;

fn main() -> Result<(), Error> {
    let matches = Command::new("Notatin Registry Dump")
        .version("0.2")
        .arg(arg!(
            -r --recover "Recover deleted and versioned keys and values"
        ))
        .arg(arg!(
            --"recovered-only" "Only export recovered items (applicable for tsv and xlsx output only)"
        ))
        .arg(arg!(
            --"full-field-info" "Get the offset and length for each key/value field (applicable for jsonl output only)"
        ))
        .arg(arg!(
            -f --filter [STRING] "Key path for filter (ex: 'ControlSet001\\Services')"
        ))
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE(S)")
                .help("Base registry file with optional transaction log(s) (Comma separated list)")
                .required(true)
                .number_of_values(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file")
                .required(true)
                .number_of_values(1),
        )
        .arg(
            arg!(<TYPE> "output type")
                .short('t')
                .value_parser(EnumValueParser::<OutputType>::new())
                .ignore_case(true)
                .default_value("jsonl"),
        )
        .get_matches();

    let (input, logs) = parse_paths(
        matches.get_one::<String>("input")
               .expect("Required value")
    );
    let output = matches.get_one::<String>("output").expect("Required value");
    let recover = matches.get_flag("recover");
    let recovered_only = matches.get_flag("recovered-only");
    let get_full_field_info = matches.get_flag("full-field-info");
    let output_type = *matches.get_one::<OutputType>("TYPE").expect("Unrecognized value");

    let mut parser_builder = ParserBuilder::from_path(input);
    parser_builder.update_console(true);
    parser_builder.recover_deleted(recover);
    parser_builder.get_full_field_info(get_full_field_info);
    for log in logs.unwrap_or_default() {
        parser_builder.with_transaction_log(log);
    }
    let parser = parser_builder.build()?;

    let filter = match matches.get_one::<String>("filter") {
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
        WriteXlsx::new(output, recovered_only)?.write(&parser, filter)?;
    } else if output_type == OutputType::Tsv {
        WriteTsv::new(output, recovered_only)?.write(&parser, filter)?;
    } else if output_type == OutputType::Common {
        WriteCommon::new(output)?.write(&parser, filter)?;
    } else {
        WriteJson::write(output, &parser, filter, &mut console)?;
    }
    console.write(&format!("\nFinished writing {}\n", output))?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OutputType {
    Jsonl,
    Common,
    Tsv,
    Xlsx
}

impl ValueEnum for OutputType {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            OutputType::Jsonl,
            OutputType::Common,
            OutputType::Tsv,
            OutputType::Xlsx
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            OutputType::Jsonl => PossibleValue::new("jsonl"),
            OutputType::Common => PossibleValue::new("common"),
            OutputType::Tsv => PossibleValue::new("tsv"),
            OutputType::Xlsx => PossibleValue::new("xlsx")
        })
    }
}
