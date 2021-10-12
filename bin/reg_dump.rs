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
    cell::CellState,
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    cli_util::parse_paths,
    err::Error,
    filter::{Filter, FilterBuilder},
    parser::{Parser, ParserIterator},
    parser_builder::ParserBuilder,
    util::{format_date_time, write_common_export_format},
};
use std::{
    fs::File,
    io::{BufWriter, Write},
};
use xlsxwriter::{Format, FormatBorder, FormatColor, Workbook, Worksheet, XlsxError};

fn main() -> Result<(), Error> {
    let matches = App::new("Notatin Registry Dump")
        .version("0.1")
        .arg(Arg::from_usage(
            "-r --recover 'Recover deleted and versioned keys and values'",
        ))
        .arg(Arg::from_usage(
            "-h --full-field-info 'Get the offset and length for each key/value field'",
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
    let get_full_field_info = matches.is_present("full-field-info");
    let output_type = value_t!(matches, "TYPE", OutputType).unwrap_or_else(|e| e.exit());

    let mut parser_builder = ParserBuilder::from_path(input);
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

    if output_type == OutputType::Xlsx {
        //write_xlsx(output, &parser, filter)?;
        let mut writer = WriteXlsx::new(output)?;
        writer.write(&parser, filter)?;
    } else {
        let write_file = File::create(output)?;
        if output_type == OutputType::Common {
            write_common_export_format(&parser, filter, write_file)?;
        } else {
            let mut iter = ParserIterator::new(&parser);
            if let Some(filter) = filter {
                iter.with_filter(filter);
            }
            let mut writer = BufWriter::new(write_file);
            match output_type {
                OutputType::Tsv => write_tsv(&mut writer, &parser, &mut iter)?,
                _ => {
                    for key in iter.iter() {
                        writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap())?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn write_tsv(
    writer: &mut BufWriter<File>,
    parser: &Parser,
    iter: &mut ParserIterator,
) -> Result<(), Error> {
    //write!(writer, "{}", std::str::from_utf8(&vec![0xEF, 0xBB, 0xBF]).expect("known good bytes (utf8 BOM)"))?; // need explicit BOM to keep Excel happy with multibyte UTF8 chars
    writeln!(writer,"Key Path\tValue Name\tStatus\tPrevious Sequence Number\tModifying Sequence Number\tTimestamp\tFlags\tAccess Flags\tValue\tLogs")?;
    for key in iter.iter() {
        write_key_tsv(&key, writer, false)?;
    }
    writeln!(writer, "\nLogs\n-----------")?;
    parser.get_parse_logs().write(writer)?;
    Ok(())
}

fn write_value_tsv(
    cell_key_node: &CellKeyNode,
    value: &CellKeyValue,
    writer: &mut BufWriter<File>,
) -> Result<(), Error> {
    writeln!(
        writer,
        "{}\t{}\t{:?}\t{}\t{}\t\t\t\t{:?}\t{}",
        cell_key_node.path,
        value.get_pretty_name(),
        value.cell_state,
        get_sequence_num_string(value.sequence_num),
        get_sequence_num_string(value.updated_by_sequence_num),
        value.get_content().0,
        value.logs
    )?;
    Ok(())
}

fn write_key_tsv(
    cell_key_node: &CellKeyNode,
    writer: &mut BufWriter<File>,
    key_modified: bool,
) -> Result<(), Error> {
    let mut logs = cell_key_node.logs.clone();
    writeln!(
        writer,
        "{}\t\t{:?}\t{}\t{}\t{}\t{:?}\t{:?}\t\t{}",
        cell_key_node.path,
        cell_key_node.cell_state,
        get_sequence_num_string(cell_key_node.sequence_num),
        get_sequence_num_string(cell_key_node.updated_by_sequence_num),
        format_date_time(cell_key_node.last_key_written_date_and_time()),
        cell_key_node.key_node_flags(&mut logs),
        cell_key_node.access_flags(&mut logs),
        cell_key_node.logs
    )?;

    for sub_key in &cell_key_node.versions {
        write_key_tsv(sub_key, writer, true)?;
    }

    if !key_modified {
        // don't output values for modified keys; current/modified/deleted vals will be output via the current version of the key
        for value in cell_key_node.value_iter() {
            write_value_tsv(cell_key_node, &value, writer)?;

            for sub_value in &value.versions {
                write_value_tsv(cell_key_node, sub_value, writer)?;
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

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum OutputType {
        Jsonl,
        Common,
        Tsv,
        Xlsx
    }
}

#[derive(Default)]
struct XlsxState {
    row: u32,
    shaded: bool,
    upper_border: bool,
    key_path: String,
    value_name: Option<String>,
}

impl XlsxState {
    fn set_shading(&mut self, key_path: &str, value_name: Option<&String>, cell_state: CellState) {
        if key_path != self.key_path || value_name != self.value_name.as_ref() {
            self.shaded = !self.shaded;
            self.key_path = key_path.to_string();
            self.value_name = value_name.cloned();
            self.upper_border = true;
        } else if cell_state.is_deleted_primary_file() {
            self.upper_border = true;
            self.shaded = !self.shaded;
        } else {
            self.upper_border = false;
        }
    }
}

struct WriteXlsx {
    workbook: Workbook,
}

impl WriteXlsx {
    const ROW_HEIGHT: f64 = 16.0;
    const COL_WIDTH_WIDE: f64 = 50.0;
    const COL_WIDTH_NARROW: f64 = 23.0;
    const COL_KEY_PATH: u16 = 0;
    const COL_VALUE_NAME: u16 = 1;
    const COL_STATUS: u16 = 2;
    const COL_PREV_SEQ_NUM: u16 = 3;
    const COL_MOD_SEQ_NUM: u16 = 4;
    const COL_TIMESTAMP: u16 = 5;
    const COL_FLAGS: u16 = 6;
    const COL_ACCESS_FLAGS: u16 = 7;
    const COL_VALUE: u16 = 8;
    const COL_LOGS: u16 = 9;
    const MAX_EXCEL_CELL_LEN: usize = 32767;
    const ELLIPSES: &'static str = "...";

    fn new(output: &str) -> Result<Self, Error> {
        Ok(WriteXlsx {
            workbook: Workbook::new(output),
        })
    }

    fn write(&mut self, parser: &Parser, filter: Option<Filter>) -> Result<(), Error> {
        let mut iter = ParserIterator::new(parser);
        if let Some(filter) = filter {
            iter.with_filter(filter);
        }

        let mut reg_items_sheet = self.workbook.add_worksheet(Some("Registry Items"))?;

        reg_items_sheet.set_column(
            Self::COL_KEY_PATH,
            Self::COL_KEY_PATH,
            Self::COL_WIDTH_WIDE,
            None,
        )?;
        reg_items_sheet.set_column(
            Self::COL_VALUE_NAME,
            Self::COL_ACCESS_FLAGS,
            Self::COL_WIDTH_NARROW,
            None,
        )?;
        reg_items_sheet.set_column(Self::COL_VALUE, Self::COL_LOGS, Self::COL_WIDTH_WIDE, None)?;
        reg_items_sheet.set_row(
            0,
            Self::ROW_HEIGHT,
            Some(
                &self
                    .workbook
                    .add_format()
                    .set_bold()
                    .set_border_bottom(FormatBorder::Medium),
            ),
        )?;

        reg_items_sheet.write_string(0, Self::COL_KEY_PATH, "Key Path", None)?;
        reg_items_sheet.write_string(0, Self::COL_VALUE_NAME, "Value Name", None)?;
        reg_items_sheet.write_string(0, Self::COL_STATUS, "Status", None)?;
        reg_items_sheet.write_string(
            0,
            Self::COL_PREV_SEQ_NUM,
            "Previous Sequence Number",
            None,
        )?;
        reg_items_sheet.write_string(
            0,
            Self::COL_MOD_SEQ_NUM,
            "Modifying Sequence Number",
            None,
        )?;
        reg_items_sheet.write_string(0, Self::COL_TIMESTAMP, "Timestamp", None)?;
        reg_items_sheet.write_string(0, Self::COL_FLAGS, "Flags", None)?;
        reg_items_sheet.write_string(0, Self::COL_ACCESS_FLAGS, "Access Flags", None)?;
        reg_items_sheet.write_string(0, Self::COL_VALUE, "Value", None)?;
        reg_items_sheet.write_string(0, Self::COL_LOGS, "Logs", None)?;
        reg_items_sheet.freeze_panes(0, 0);

        let mut state = XlsxState::default();
        for key in iter.iter() {
            self.write_key(&mut reg_items_sheet, &key, false, &mut state)?;
        }

        let mut logs_sheet = self.workbook.add_worksheet(Some("Logs"))?;
        if let Some(logs) = parser.get_parse_logs().get() {
            for (row, log) in logs.iter().enumerate() {
                logs_sheet.write_string(row as u32, 0, &format!("{:?}", log.code), None)?;
                Self::check_write_string(&mut logs_sheet, row as u32, 1, &log.text)?;
            }
        }
        Ok(())
    }

    fn write_key(
        &self,
        reg_items_sheet: &mut Worksheet,
        cell_key_node: &CellKeyNode,
        is_key_version: bool,
        state: &mut XlsxState,
    ) -> Result<(), Error> {
        state.row += 1;
        state.set_shading(&cell_key_node.path, None, cell_key_node.cell_state);
        reg_items_sheet.set_row(
            state.row,
            Self::ROW_HEIGHT,
            Some(&self.get_formatter(cell_key_node.cell_state, state.shaded, state.upper_border)),
        )?;

        let mut logs = cell_key_node.logs.clone();
        Self::check_write_string(
            reg_items_sheet,
            state.row,
            Self::COL_KEY_PATH,
            &cell_key_node.path,
        )?;
        reg_items_sheet.write_string(
            state.row,
            Self::COL_STATUS,
            &format!("{:?}", cell_key_node.cell_state),
            None,
        )?;
        if let Some(sequence_num) = cell_key_node.sequence_num {
            reg_items_sheet.write_number(
                state.row,
                Self::COL_PREV_SEQ_NUM,
                sequence_num as f64,
                None,
            )?;
        }
        if let Some(sequence_num) = cell_key_node.updated_by_sequence_num {
            reg_items_sheet.write_number(
                state.row,
                Self::COL_MOD_SEQ_NUM,
                sequence_num as f64,
                None,
            )?;
        }
        reg_items_sheet.write_string(
            state.row,
            Self::COL_TIMESTAMP,
            &format_date_time(cell_key_node.last_key_written_date_and_time()),
            None,
        )?;
        reg_items_sheet.write_string(
            state.row,
            Self::COL_FLAGS,
            &format!("{:?}", cell_key_node.key_node_flags(&mut logs)),
            None,
        )?;
        reg_items_sheet.write_string(
            state.row,
            Self::COL_ACCESS_FLAGS,
            &format!("{:?}", cell_key_node.access_flags(&mut logs)),
            None,
        )?;
        Self::check_write_string(
            reg_items_sheet,
            state.row,
            Self::COL_LOGS,
            &cell_key_node.logs.to_string(),
        )?;

        for sub_key in &cell_key_node.versions {
            self.write_key(reg_items_sheet, sub_key, true, state)?;
        }

        if !is_key_version {
            // don't output values for modified keys; current/modified/deleted vals will be output via the current version of the key
            for value in cell_key_node.value_iter() {
                self.write_value(reg_items_sheet, cell_key_node, &value, state)?;

                for sub_value in &value.versions {
                    self.write_value(reg_items_sheet, cell_key_node, sub_value, state)?;
                }
            }
        }
        Ok(())
    }

    fn write_value(
        &self,
        reg_items_sheet: &mut Worksheet,
        cell_key_node: &CellKeyNode,
        value: &CellKeyValue,
        state: &mut XlsxState,
    ) -> Result<(), Error> {
        state.row += 1;
        state.set_shading(
            &cell_key_node.path,
            Some(&value.detail.value_name()),
            value.cell_state,
        );
        reg_items_sheet.set_row(
            state.row,
            16.0,
            Some(&self.get_formatter(value.cell_state, state.shaded, state.upper_border)),
        )?;
        let mut content = format!("{:?}", value.get_content().0);
        if content.len() > Self::MAX_EXCEL_CELL_LEN {
            content.truncate(Self::MAX_EXCEL_CELL_LEN - Self::ELLIPSES.len());
            content += Self::ELLIPSES;
        }

        Self::check_write_string(
            reg_items_sheet,
            state.row,
            Self::COL_KEY_PATH,
            &cell_key_node.path,
        )?;
        Self::check_write_string(
            reg_items_sheet,
            state.row,
            Self::COL_VALUE_NAME,
            &value.get_pretty_name(),
        )?;
        reg_items_sheet.write_string(
            state.row,
            Self::COL_STATUS,
            &format!("{:?}", value.cell_state),
            None,
        )?;
        if let Some(sequence_num) = value.sequence_num {
            reg_items_sheet.write_number(
                state.row,
                Self::COL_PREV_SEQ_NUM,
                sequence_num as f64,
                None,
            )?;
        }
        if let Some(sequence_num) = value.updated_by_sequence_num {
            reg_items_sheet.write_number(
                state.row,
                Self::COL_MOD_SEQ_NUM,
                sequence_num as f64,
                None,
            )?;
        }
        reg_items_sheet.write_string(state.row, Self::COL_VALUE, &content, None)?;
        Self::check_write_string(
            reg_items_sheet,
            state.row,
            Self::COL_LOGS,
            &value.logs.to_string(),
        )?;
        Ok(())
    }

    fn check_write_string(
        sheet: &mut Worksheet,
        row: u32,
        col: u16,
        val: &str,
    ) -> Result<(), XlsxError> {
        // This check is here because xlsxwriter panics when provided certain input (they are unwrapping this result)
        if std::ffi::CString::new(val.to_string()).is_ok() {
            if val.len() > Self::MAX_EXCEL_CELL_LEN {
                let mut truncated = val.to_string();
                truncated.truncate(Self::MAX_EXCEL_CELL_LEN - Self::ELLIPSES.len());
                truncated += Self::ELLIPSES;
                sheet.write_string(row, col, &truncated, None)
            } else {
                sheet.write_string(row, col, val, None)
            }
        } else {
            sheet.write_string(row, col, "{Error writing text to document}", None)
        }
    }

    fn get_formatter(&self, cell_state: CellState, shaded: bool, upper_line: bool) -> Format {
        let mut format = self.workbook.add_format();
        if shaded {
            format = format.set_bg_color(FormatColor::Custom(0xF4F4F4));
        }
        if upper_line {
            format = format.set_border_top(FormatBorder::Hair);
        }
        if cell_state.is_deleted() {
            format = format.set_font_color(FormatColor::Custom(0xA51B1B));
        } else if cell_state == CellState::ModifiedTransactionLog {
            format = format.set_font_color(FormatColor::Custom(0x808080));
        }
        format
    }
}
