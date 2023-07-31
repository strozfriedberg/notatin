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

use std::path::*;

use clap::builder::{EnumValueParser, PossibleValue};
use clap::{arg, Arg, Command, ValueEnum};
use notatin::{
    cli_util::*,
    err::Error,
    filter::{Filter, FilterBuilder},
    parser_builder::ParserBuilder,
    progress,
};
use walkdir::WalkDir;

use common_writer::WriteCommon;
use json_writer::WriteJson;
use tsv_writer::WriteTsv;
use xlsx_writer::WriteXlsx;

fn main() -> Result<(), Error> {
    let matches = Command::new("Notatin Registry Dump")
        .version("0.3")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .help("Base registry file, or root folder if recursing")
                .required(true)
                .number_of_values(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file. or folder if recursing")
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
        .arg(arg!(
            --recurse "Recurse through input looking for registry files"
        ))
        .arg(arg!(
            -r --recover "Recover deleted and versioned keys and values"
        ))
        .arg(arg!(
            --"recovered-only" "Only export recovered items (applicable to tsv and xlsx output)"
        ))
        .arg(arg!(
            --"full-field-info" "Get the offset and length for each key/value field (applicable to jsonl output)"
        ))
        .arg(arg!(
            -s --"skip-logs" "Skip transaction log files"
        ))
        .arg(arg!(
            -f --filter [STRING] "Key path for filter (ex: 'ControlSet001\\Services')"
        ))
        .get_matches();

    let input = matches.get_one::<String>("input").expect("Required value");
    let output = matches.get_one::<String>("output").expect("Required value");
    let recurse = matches.get_flag("recurse");
    let recover = matches.get_flag("recoVer");
    let skip_logs = matches.get_flag("skip-logs");
    let recovered_only = matches.get_flag("recovered-only");
    let get_full_field_info = matches.get_flag("full-field-info");
    let output_type = *matches
        .get_one::<OutputType>("TYPE")
        .expect("Unrecognized value");

    let filter = match matches.get_one::<String>("filter") {
        Some(f) => Some(
            FilterBuilder::new()
                .add_key_path(f)
                .return_child_keys(true)
                .build()?,
        ),
        None => None,
    };

    if recurse {
        process_folder(
            &PathBuf::from(output),
            &PathBuf::from(input),
            filter,
            recover,
            recovered_only,
            get_full_field_info,
            skip_logs,
            output_type,
        )
    } else {
        process_file(
            &PathBuf::from(output),
            PathBuf::from(input),
            filter,
            recover,
            recovered_only,
            get_full_field_info,
            skip_logs,
            output_type,
        )
    }
}

fn process_file(
    outpath: &PathBuf,
    input: PathBuf,
    filter: Option<Filter>,
    recover: bool,
    recovered_only: bool,
    get_full_field_info: bool,
    skip_logs: bool,
    output_type: OutputType,
) -> Result<(), Error> {
    let logs = get_log_files(
        skip_logs,
        &input.file_name().unwrap().to_string_lossy(),
        &input,
    );

    reg_dump(
        input,
        &PathBuf::from(outpath),
        logs,
        filter,
        recover,
        recovered_only,
        get_full_field_info,
        output_type,
    )
}

fn process_folder(
    outfolder: &PathBuf,
    base: &PathBuf,
    filter: Option<Filter>,
    recover: bool,
    recovered_only: bool,
    get_full_field_info: bool,
    skip_logs: bool,
    output_type: OutputType,
) -> Result<(), Error> {
    let reg_files = vec![
        "sam",
        "security",
        "software",
        "system",
        "default",
        "amcache",
        "ntuser.dat",
        "usrclass.dat",
    ];

    for entry in WalkDir::new(base)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| !e.file_type().is_dir())
    {
        if let Some(f) = entry.file_name().to_str() {
            let f_lower = f.to_lowercase();
            if reg_files.contains(&f_lower.as_str()) && file_has_size(entry.path()) {
                match entry.path().strip_prefix(base) {
                    Err(e) => println!("{:?}", e),
                    Ok(primary_path_from_base) => {
                        let logs = get_log_files(skip_logs, f, entry.path());
                        let outpath = get_outpath(primary_path_from_base, outfolder, &output_type);
                        let _ = reg_dump(
                            PathBuf::from(entry.path()),
                            &outpath,
                            logs,
                            filter.clone(),
                            recover,
                            recovered_only,
                            get_full_field_info,
                            output_type,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn get_outpath<T>(primary_path_from_base: &Path, outfolder: T, output_type: &OutputType) -> PathBuf
where
    T: AsRef<Path> + std::convert::AsRef<std::ffi::OsStr>,
{
    let path = primary_path_from_base.to_string_lossy();
    let output_filename = str::replace(&path, std::path::MAIN_SEPARATOR, "_");
    let mut output_path = Path::new(&outfolder).join(output_filename);
    match output_type {
        OutputType::Xlsx => output_path.set_extension("xlsx"),
        OutputType::Tsv => output_path.set_extension("tsv"),
        OutputType::Common => output_path.set_extension("txt"),
        _ => output_path.set_extension("jsonl"),
    };
    output_path
}

fn reg_dump(
    input: PathBuf,
    output: &PathBuf,
    logs: Option<Vec<PathBuf>>,
    filter: Option<Filter>,
    recover: bool,
    recovered_only: bool,
    get_full_field_info: bool,
    output_type: OutputType,
) -> Result<(), Error> {
    let mut parser_builder = ParserBuilder::from_path(input);
    parser_builder.update_console(true);
    parser_builder.recover_deleted(recover);
    parser_builder.get_full_field_info(get_full_field_info);
    for log in logs.unwrap_or_default() {
        parser_builder.with_transaction_log(log);
    }
    let parser = parser_builder.build()?;

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
    console.write(&format!("\nFinished writing {:?}\n", output))?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OutputType {
    Jsonl,
    Common,
    Tsv,
    Xlsx,
}

impl ValueEnum for OutputType {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            OutputType::Jsonl,
            OutputType::Xlsx,
            OutputType::Tsv,
            OutputType::Common,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            OutputType::Jsonl => PossibleValue::new("jsonl"),
            OutputType::Xlsx => PossibleValue::new("xlsx"),
            OutputType::Tsv => PossibleValue::new("tsv"),
            OutputType::Common => PossibleValue::new("common"),
        })
    }
}
