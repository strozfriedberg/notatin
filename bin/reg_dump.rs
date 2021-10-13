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
    borrow::Cow,
    convert::TryFrom,
    fs::File,
    io::{BufWriter, Write},
};
use xlsxwriter::{
    Format, FormatBorder, FormatColor, FormatUnderline, Workbook, Worksheet, XlsxError,
};

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

struct WorksheetState<'a> {
    sheet: Worksheet<'a>,
    row: u32,
    shaded: bool,
    upper_border: bool,
    key_path: String,
    value_name: Option<String>,
}

impl<'a> WorksheetState<'a> {
    fn new(sheet: Worksheet<'a>) -> Self {
        Self {
            sheet,
            row: 0,
            shaded: false,
            upper_border: false,
            key_path: String::new(),
            value_name: None,
        }
    }

    fn write_string(&mut self, col: u16, text: &str) -> Result<(), XlsxError> {
        self.sheet.write_string(self.row, col, text, None)
    }

    fn write_number(&mut self, col: u16, num: f64) -> Result<(), XlsxError> {
        self.sheet.write_number(self.row, col, num, None)
    }

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
    const MAX_TRUNCATED_CHARS: usize = 250;
    const TRUNCATED: &'static str = " [truncated]";
    const OVERFLOW: &'static str = "Overflow";

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

        let mut reg_items_sheet =
            WorksheetState::new(self.workbook.add_worksheet(Some("Registry Items"))?);
        let mut logs_sheet = WorksheetState::new(self.workbook.add_worksheet(Some("Logs"))?);
        let mut overflow_sheet =
            WorksheetState::new(self.workbook.add_worksheet(Some(Self::OVERFLOW))?);

        reg_items_sheet.sheet.set_column(
            Self::COL_KEY_PATH,
            Self::COL_KEY_PATH,
            Self::COL_WIDTH_WIDE,
            None,
        )?;
        reg_items_sheet.sheet.set_column(
            Self::COL_VALUE_NAME,
            Self::COL_ACCESS_FLAGS,
            Self::COL_WIDTH_NARROW,
            None,
        )?;
        reg_items_sheet.sheet.set_column(
            Self::COL_VALUE,
            Self::COL_LOGS,
            Self::COL_WIDTH_WIDE,
            None,
        )?;
        reg_items_sheet.sheet.set_row(
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

        reg_items_sheet.write_string(Self::COL_KEY_PATH, "Key Path")?;
        reg_items_sheet.write_string(Self::COL_VALUE_NAME, "Value Name")?;
        reg_items_sheet.write_string(Self::COL_STATUS, "Status")?;
        reg_items_sheet.write_string(Self::COL_PREV_SEQ_NUM, "Previous Seq Num")?;
        reg_items_sheet.write_string(Self::COL_MOD_SEQ_NUM, "Modifying Seq Num")?;
        reg_items_sheet.write_string(Self::COL_TIMESTAMP, "Timestamp")?;
        reg_items_sheet.write_string(Self::COL_FLAGS, "Flags")?;
        reg_items_sheet.write_string(Self::COL_ACCESS_FLAGS, "Access Flags")?;
        reg_items_sheet.write_string(Self::COL_VALUE, "Value")?;
        reg_items_sheet.write_string(Self::COL_LOGS, "Logs")?;
        reg_items_sheet.sheet.freeze_panes(1, 0);

        for key in iter.iter() {
            self.write_key(&mut reg_items_sheet, &mut overflow_sheet, &key, false)?;
        }

        if let Some(logs) = parser.get_parse_logs().get() {
            let mut link_format = self.workbook.add_format();
            link_format = link_format.set_underline(FormatUnderline::Single);
            for log in logs {
                logs_sheet.write_string(0, &format!("{:?}", log.code))?;
                Self::check_write_string(
                    &mut logs_sheet,
                    &mut overflow_sheet,
                    1,
                    &log.text,
                    &link_format,
                )?;
                logs_sheet.row += 1;
            }
        }
        Ok(())
    }

    fn write_key(
        &self,
        reg_items_sheet: &mut WorksheetState,
        overflow_sheet: &mut WorksheetState,
        cell_key_node: &CellKeyNode,
        is_key_version: bool,
    ) -> Result<(), Error> {
        reg_items_sheet.row += 1;
        reg_items_sheet.set_shading(&cell_key_node.path, None, cell_key_node.cell_state);
        let (row_format, link_format) = self.get_formatters(
            cell_key_node.cell_state,
            reg_items_sheet.shaded,
            reg_items_sheet.upper_border,
        );

        reg_items_sheet
            .sheet
            .set_row(reg_items_sheet.row, Self::ROW_HEIGHT, Some(&row_format))?;

        let mut logs = cell_key_node.logs.clone();
        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_KEY_PATH,
            &cell_key_node.path,
            &link_format,
        )?;
        reg_items_sheet
            .write_string(Self::COL_STATUS, &format!("{:?}", cell_key_node.cell_state))?;
        if let Some(sequence_num) = cell_key_node.sequence_num {
            reg_items_sheet.write_number(Self::COL_PREV_SEQ_NUM, sequence_num as f64)?;
        }
        if let Some(sequence_num) = cell_key_node.updated_by_sequence_num {
            reg_items_sheet.write_number(Self::COL_MOD_SEQ_NUM, sequence_num as f64)?;
        }
        reg_items_sheet.write_string(
            Self::COL_TIMESTAMP,
            &format_date_time(cell_key_node.last_key_written_date_and_time()),
        )?;
        reg_items_sheet.write_string(
            Self::COL_FLAGS,
            &format!("{:?}", cell_key_node.key_node_flags(&mut logs)),
        )?;
        reg_items_sheet.write_string(
            Self::COL_ACCESS_FLAGS,
            &format!("{:?}", cell_key_node.access_flags(&mut logs)),
        )?;
        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_LOGS,
            &cell_key_node.logs.to_string(),
            &link_format,
        )?;

        for sub_key in &cell_key_node.versions {
            self.write_key(reg_items_sheet, overflow_sheet, sub_key, true)?;
        }

        if !is_key_version {
            // don't output values for modified keys; current/modified/deleted vals will be output via the current version of the key
            for value in cell_key_node.value_iter() {
                self.write_value(reg_items_sheet, overflow_sheet, cell_key_node, &value)?;

                for sub_value in &value.versions {
                    self.write_value(reg_items_sheet, overflow_sheet, cell_key_node, sub_value)?;
                }
            }
        }
        Ok(())
    }

    fn write_value(
        &self,
        reg_items_sheet: &mut WorksheetState,
        overflow_sheet: &mut WorksheetState,
        cell_key_node: &CellKeyNode,
        value: &CellKeyValue,
    ) -> Result<(), Error> {
        reg_items_sheet.row += 1;
        reg_items_sheet.set_shading(
            &cell_key_node.path,
            Some(&value.detail.value_name()),
            value.cell_state,
        );
        let (row_format, link_format) = self.get_formatters(
            value.cell_state,
            reg_items_sheet.shaded,
            reg_items_sheet.upper_border,
        );
        reg_items_sheet
            .sheet
            .set_row(reg_items_sheet.row, Self::ROW_HEIGHT, Some(&row_format))?;

        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_KEY_PATH,
            &cell_key_node.path,
            &link_format,
        )?;
        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_VALUE_NAME,
            &value.get_pretty_name(),
            &link_format,
        )?;
        reg_items_sheet.write_string(Self::COL_STATUS, &format!("{:?}", value.cell_state))?;
        if let Some(sequence_num) = value.sequence_num {
            reg_items_sheet.write_number(Self::COL_PREV_SEQ_NUM, sequence_num as f64)?;
        }
        if let Some(sequence_num) = value.updated_by_sequence_num {
            reg_items_sheet.write_number(Self::COL_MOD_SEQ_NUM, sequence_num as f64)?;
        }
        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_VALUE,
            &format!("{:?}", value.get_content().0),
            &link_format,
        )?;
        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_LOGS,
            &value.logs.to_string(),
            &link_format,
        )?;
        Ok(())
    }

    fn remove_nulls(input: &str) -> Cow<str> {
        if input.contains('\0') {
            Cow::Owned(input.replace('\0', ""))
        } else {
            Cow::Borrowed(input)
        }
    }

    fn write_string_handle_overflow<'a>(
        primary_sheet: &mut WorksheetState,
        overflow_sheet: &mut WorksheetState,
        primary_sheet_col: u16,
        val: Cow<'a, str>,
        link_format: &Format,
    ) -> Result<(), Error> {
        if val.len() > Self::MAX_EXCEL_CELL_LEN {
            let full_val = val.into_owned();

            let mut full_val_chunks = vec![];
            let mut full_val_cur: &str = &full_val;
            while !full_val_cur.is_empty() {
                let (chunk, rest) = full_val_cur
                    .split_at(std::cmp::min(Self::MAX_EXCEL_CELL_LEN, full_val_cur.len()));
                full_val_chunks.push(chunk);
                full_val_cur = rest;
            }
            overflow_sheet.row += 1;
            for (col, chunk) in full_val_chunks.iter().enumerate() {
                overflow_sheet.write_string(u16::try_from(col)?, chunk)?
            }
            primary_sheet.sheet.write_url(
                primary_sheet.row,
                primary_sheet_col,
                &format!("internal:{}!A{}", Self::OVERFLOW, overflow_sheet.row + 1),
                Some(link_format),
            )?;

            let mut sample = full_val.clone();
            sample.truncate(Self::MAX_TRUNCATED_CHARS);
            sample += Self::TRUNCATED;
            primary_sheet.sheet.write_string(
                primary_sheet.row,
                primary_sheet_col,
                &sample,
                Some(link_format),
            )?
        } else {
            primary_sheet.write_string(primary_sheet_col, &val)?
        }
        Ok(())
    }

    fn check_write_string(
        primary_sheet: &mut WorksheetState,
        overflow_sheet: &mut WorksheetState,
        primary_sheet_col: u16,
        val: &str,
        link_format: &Format,
    ) -> Result<(), Error> {
        let val = Self::remove_nulls(val); // xlsxwriter panics when provided input with nulls
        Self::write_string_handle_overflow(
            primary_sheet,
            overflow_sheet,
            primary_sheet_col,
            val,
            link_format,
        )
    }

    fn get_formatters(
        &self,
        cell_state: CellState,
        shaded: bool,
        upper_line: bool,
    ) -> (Format, Format) {
        let mut row_format = self.workbook.add_format();
        let mut link_format = self.workbook.add_format();
        if shaded {
            row_format = row_format.set_bg_color(FormatColor::Custom(0xF4F4F4));
            link_format = link_format.set_bg_color(FormatColor::Custom(0xF4F4F4));
        }
        if upper_line {
            row_format = row_format.set_border_top(FormatBorder::Hair);
            link_format = link_format.set_border_top(FormatBorder::Hair);
        }
        if cell_state.is_deleted() {
            row_format = row_format.set_font_color(FormatColor::Custom(0xA51B1B));
            link_format = link_format.set_font_color(FormatColor::Custom(0xA51B1B));
        } else if cell_state == CellState::ModifiedTransactionLog {
            row_format = row_format.set_font_color(FormatColor::Custom(0x808080));
            link_format = link_format.set_font_color(FormatColor::Custom(0x808080));
        }
        link_format = link_format.set_underline(FormatUnderline::Single);
        (row_format, link_format)
    }
}
