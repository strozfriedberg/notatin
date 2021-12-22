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
    cell::{Cell, CellState},
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
    recovered_only: bool,
    console: Box<dyn progress::UpdateProgressTrait>,
}

impl WriteXlsx {
    const ROW_HEIGHT: f64 = 16.0;
    const COL_WIDTH_WIDE: f64 = 50.0;
    const COL_WIDTH_NARROW: f64 = 23.0;
    const COL_WIDTH_TINY: f64 = 6.0;
    const COL_INDEX: u16 = 0;
    const COL_KEY_PATH: u16 = 1;
    const COL_VALUE_NAME: u16 = 2;
    const COL_VALUE_DATA: u16 = 3;
    const COL_TIMESTAMP: u16 = 4;
    const COL_STATUS: u16 = 5;
    const COL_PREV_SEQ_NUM: u16 = 6;
    const COL_MOD_SEQ_NUM: u16 = 7;
    const COL_FLAGS: u16 = 8;
    const COL_ACCESS_FLAGS: u16 = 9;
    const COL_VALUE_TYPE: u16 = 10;
    const COL_LOGS: u16 = 11;
    const MAX_EXCEL_CELL_LEN: usize = 32767;
    const MAX_TRUNCATED_CHARS: usize = 250;
    const TRUNCATED: &'static str = "truncated";
    const OVERFLOW: &'static str = "Overflow";
    const COLOR_LIGHT_GREY: u32 = 0xF4F4F4;
    const COLOR_DARK_GREY: u32 = 0x808080;
    const COLOR_DARK_RED: u32 = 0xA51B1B;

    fn new(output: &str, recovered_only: bool) -> Self {
        WriteXlsx {
            workbook: Workbook::new(output),
            recovered_only,
            console: progress::new(true),
        }
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
            Self::COL_INDEX,
            Self::COL_INDEX,
            Self::COL_WIDTH_TINY,
            None,
        )?;
        reg_items_sheet.sheet.set_column(
            Self::COL_KEY_PATH,
            Self::COL_VALUE_DATA,
            Self::COL_WIDTH_WIDE,
            None,
        )?;
        reg_items_sheet.sheet.set_column(
            Self::COL_TIMESTAMP,
            Self::COL_LOGS,
            Self::COL_WIDTH_NARROW,
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

        reg_items_sheet.write_string(Self::COL_INDEX, "Index")?;
        reg_items_sheet.write_string(Self::COL_KEY_PATH, "Key Path")?;
        reg_items_sheet.write_string(Self::COL_VALUE_NAME, "Value Name")?;
        reg_items_sheet.write_string(Self::COL_VALUE_DATA, "Value Data")?;
        reg_items_sheet.write_string(Self::COL_TIMESTAMP, "Timestamp")?;
        reg_items_sheet.write_string(Self::COL_STATUS, "Status")?;
        reg_items_sheet.write_string(Self::COL_PREV_SEQ_NUM, "Previous Seq Num")?;
        reg_items_sheet.write_string(Self::COL_MOD_SEQ_NUM, "Modifying Seq Num")?;
        reg_items_sheet.write_string(Self::COL_FLAGS, "Flags")?;
        reg_items_sheet.write_string(Self::COL_ACCESS_FLAGS, "Access Flags")?;
        reg_items_sheet.write_string(Self::COL_VALUE_TYPE, "Value Type")?;
        reg_items_sheet.write_string(Self::COL_LOGS, "Logs")?;
        reg_items_sheet.sheet.freeze_panes(1, 0);

        for (index, key) in iter.iter().enumerate() {
            self.console.update_progress(index)?;
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
        if !self.recovered_only || cell_key_node.has_or_is_recovered() {
            reg_items_sheet.row += 1;
            reg_items_sheet.set_shading(&cell_key_node.path, None, cell_key_node.cell_state);
            let (row_format, link_format) = self.get_formatters(
                cell_key_node.cell_state,
                reg_items_sheet.shaded,
                reg_items_sheet.upper_border,
            );

            reg_items_sheet.sheet.set_row(
                reg_items_sheet.row,
                Self::ROW_HEIGHT,
                Some(&row_format),
            )?;

            let mut logs = cell_key_node.logs.clone();
            reg_items_sheet.write_number(Self::COL_INDEX, reg_items_sheet.row.into())?;
            Self::check_write_string(
                reg_items_sheet,
                overflow_sheet,
                Self::COL_KEY_PATH,
                &cell_key_node.path,
                &link_format,
            )?;
            reg_items_sheet.write_string(
                Self::COL_TIMESTAMP,
                &util::format_date_time(cell_key_node.last_key_written_date_and_time()),
            )?;
            reg_items_sheet
                .write_string(Self::COL_STATUS, &format!("{:?}", cell_key_node.cell_state))?;
            if let Some(sequence_num) = cell_key_node.sequence_num {
                reg_items_sheet.write_number(Self::COL_PREV_SEQ_NUM, sequence_num.into())?;
            }
            if let Some(sequence_num) = cell_key_node.updated_by_sequence_num {
                reg_items_sheet.write_number(Self::COL_MOD_SEQ_NUM, sequence_num.into())?;
            }
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
        if self.recovered_only && !value.has_or_is_recovered() {
            return Ok(());
        }
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

        reg_items_sheet.write_number(Self::COL_INDEX, reg_items_sheet.row.into())?;
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
        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_VALUE_DATA,
            &format!("{}", value.get_content().0),
            &link_format,
        )?;
        reg_items_sheet.write_string(Self::COL_STATUS, &format!("{:?}", value.cell_state))?;
        if let Some(sequence_num) = value.sequence_num {
            reg_items_sheet.write_number(Self::COL_PREV_SEQ_NUM, sequence_num.into())?;
        }
        if let Some(sequence_num) = value.updated_by_sequence_num {
            reg_items_sheet.write_number(Self::COL_MOD_SEQ_NUM, sequence_num.into())?;
        }

        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_VALUE_TYPE,
            &value.get_content().0.get_type(),
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
            // Putting the label here to tie this data back to the main sheet
            let truncated_label =
                format!(" [{}; row: {}]", Self::TRUNCATED, overflow_sheet.row + 1);
            overflow_sheet.write_string(0, &truncated_label)?;
            for (col, chunk) in full_val_chunks.iter().enumerate() {
                overflow_sheet.write_string(u16::try_from(col + 1)?, chunk)?
            }
            overflow_sheet.row += 1;
            primary_sheet.sheet.write_url(
                primary_sheet.row,
                primary_sheet_col,
                &format!("internal:{}!A{}", Self::OVERFLOW, overflow_sheet.row),
                Some(link_format),
            )?;

            let mut sample = full_val.clone();
            sample.truncate(Self::MAX_TRUNCATED_CHARS);
            sample += &truncated_label;
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
        if !val.is_empty() {
            let val = util::remove_nulls(val); // xlsxwriter panics when provided input with nulls
            Self::write_string_handle_overflow(
                primary_sheet,
                overflow_sheet,
                primary_sheet_col,
                val,
                link_format,
            )
        } else {
            Ok(())
        }
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
            row_format = row_format.set_bg_color(FormatColor::Custom(Self::COLOR_LIGHT_GREY));
            link_format = link_format.set_bg_color(FormatColor::Custom(Self::COLOR_LIGHT_GREY));
        }
        if upper_line {
            row_format = row_format.set_border_top(FormatBorder::Hair);
            link_format = link_format.set_border_top(FormatBorder::Hair);
        }
        if cell_state.is_deleted() {
            row_format = row_format.set_font_color(FormatColor::Custom(Self::COLOR_DARK_RED));
            link_format = link_format.set_font_color(FormatColor::Custom(Self::COLOR_DARK_RED));
        } else if cell_state == CellState::ModifiedTransactionLog {
            row_format = row_format.set_font_color(FormatColor::Custom(Self::COLOR_DARK_GREY));
            link_format = link_format.set_font_color(FormatColor::Custom(Self::COLOR_DARK_GREY));
        }
        link_format = link_format.set_underline(FormatUnderline::Single);
        (row_format, link_format)
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
