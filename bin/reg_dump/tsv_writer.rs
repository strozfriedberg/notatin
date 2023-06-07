use notatin::{
    cell::Cell,
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    err::Error,
    filter::Filter,
    parser::{Parser, ParserIterator},
    progress, util,
};
use std::fs::File;
use std::io::{BufWriter, Write};

pub(crate) struct WriteTsv {
    index: usize,
    recovered_only: bool,
    writer: BufWriter<File>,
    console: Box<dyn progress::UpdateProgressTrait>,
}

impl WriteTsv {
    pub(crate) fn new(output: &str, recovered_only: bool) -> Result<Self, Error> {
        let write_file = File::create(output)?;
        let writer = BufWriter::new(write_file);
        Ok(WriteTsv {
            index: 0,
            recovered_only,
            writer,
            console: progress::new(true),
        })
    }

    pub(crate) fn write(&mut self, parser: &Parser, filter: Option<Filter>) -> Result<(), Error> {
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
