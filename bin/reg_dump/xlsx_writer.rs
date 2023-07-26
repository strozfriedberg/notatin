use notatin::{
    cell::{Cell, CellState},
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    cell_value::CellValue,
    err::Error,
    filter::Filter,
    parser::{Parser, ParserIterator},
    progress, util,
};
use std::{borrow::Cow, convert::TryFrom, path::*};
use xlsxwriter::format::{FormatBorder, FormatColor, FormatUnderline};
use xlsxwriter::{Format, Workbook, Worksheet, XlsxError};

pub(crate) struct WriteXlsx {
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
    const COL_SUBKEY_COUNT: u16 = 2;
    const COL_VALUE_NAME: u16 = 3;
    const COL_VALUE_DATA: u16 = 4;
    const COL_TIMESTAMP: u16 = 5;
    const COL_STATUS: u16 = 6;
    const COL_PREV_SEQ_NUM: u16 = 7;
    const COL_MOD_SEQ_NUM: u16 = 8;
    const COL_FLAGS: u16 = 9;
    const COL_ACCESS_FLAGS: u16 = 10;
    const COL_VALUE_TYPE: u16 = 11;
    const COL_LOGS: u16 = 12;

    const MAX_EXCEL_CELL_LEN: usize = 32767;
    const MAX_TRUNCATED_CHARS: usize = 250;
    const TRUNCATED: &'static str = "truncated";
    const OVERFLOW: &'static str = "Overflow";
    const COLOR_LIGHT_GREY: u32 = 0xF4F4F4;
    const COLOR_DARK_GREY: u32 = 0x808080;
    const COLOR_DARK_RED: u32 = 0xA51B1B;

    pub(crate) fn new(output: &PathBuf, recovered_only: bool) -> Result<Self, XlsxError> {
        Ok(WriteXlsx {
            workbook: Workbook::new(&output.to_string_lossy())?,
            recovered_only,
            console: progress::new(true),
        })
    }

    pub(crate) fn write(&mut self, parser: &Parser, filter: Option<Filter>) -> Result<(), Error> {
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
                Format::new()
                    .set_bold()
                    .set_border_bottom(FormatBorder::Medium),
            ),
        )?;

        reg_items_sheet.write_string(Self::COL_INDEX, "Index")?;
        reg_items_sheet.write_string(Self::COL_KEY_PATH, "Key Path")?;
        reg_items_sheet.write_string(Self::COL_SUBKEY_COUNT, "Subkey Count")?;
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
            let mut link_format = Format::new();
            link_format.set_underline(FormatUnderline::Single);
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
                &sanitize_for_xml_1_0(&cell_key_node.path),
                &link_format,
            )?;
            reg_items_sheet.write_number(Self::COL_SUBKEY_COUNT, cell_key_node.cell_sub_key_offsets_absolute.len() as f64)?;
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
                &sanitize_for_xml_1_0(&cell_key_node.logs.to_string()),
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
            &sanitize_for_xml_1_0(&cell_key_node.path),
            &link_format,
        )?;
        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_VALUE_NAME,
            &sanitize_for_xml_1_0(&value.get_pretty_name()),
            &link_format,
        )?;
        Self::check_write_string(
            reg_items_sheet,
            overflow_sheet,
            Self::COL_VALUE_DATA,
            &sanitize_cell(&value.get_content().0),
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
            &sanitize_for_xml_1_0(&value.logs.to_string()),
            &link_format,
        )?;
        Ok(())
    }

    fn write_string_handle_overflow(
        primary_sheet: &mut WorksheetState,
        overflow_sheet: &mut WorksheetState,
        primary_sheet_col: u16,
        val: Cow<str>,
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
            Self::write_string_handle_overflow(
                primary_sheet,
                overflow_sheet,
                primary_sheet_col,
                val.into(),
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
        let mut row_format = Format::new();
        let mut link_format = Format::new();
        if shaded {
            row_format.set_bg_color(FormatColor::Custom(Self::COLOR_LIGHT_GREY));
            link_format.set_bg_color(FormatColor::Custom(Self::COLOR_LIGHT_GREY));
        }
        if upper_line {
            row_format.set_border_top(FormatBorder::Hair);
            link_format.set_border_top(FormatBorder::Hair);
        }
        if cell_state.is_deleted() {
            row_format.set_font_color(FormatColor::Custom(Self::COLOR_DARK_RED));
            link_format.set_font_color(FormatColor::Custom(Self::COLOR_DARK_RED));
        } else if cell_state == CellState::ModifiedTransactionLog {
            row_format.set_font_color(FormatColor::Custom(Self::COLOR_DARK_GREY));
            link_format.set_font_color(FormatColor::Custom(Self::COLOR_DARK_GREY));
        }
        link_format.set_underline(FormatUnderline::Single);
        (row_format, link_format)
    }
}

fn is_legal_xml_1_0(c: char) -> bool {
    // Some Unicode code points are illegal in XML 1.0
    matches!(c,
        '\u{0009}' | '\u{000A}' | '\u{000D}' |
        '\u{0020}'..='\u{D7FF}' |
        '\u{E000}'..='\u{FFFD}' |
        '\u{10000}'..='\u{10FFFF}'
    )
}

fn sanitize_for_xml_1_0(s: &str) -> Cow<str> {
    // Replace code points illegal in XML 1.0 with U+FFFD
    let i = s.chars().position(|c| !is_legal_xml_1_0(c));
    match i {
        None => s.into(),
        Some(i) => s
            .chars()
            .take(i)
            .chain(s.chars().skip(i).map(|c| match c {
                _ if is_legal_xml_1_0(c) => c,
                _ => '\u{FFFD}',
            }))
            .collect::<String>()
            .into(),
    }
}

fn sanitize_cell(v: &CellValue) -> Cow<str> {
    match v {
        CellValue::String(v) => sanitize_for_xml_1_0(v),
        v => format!("{}", v).into(),
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
