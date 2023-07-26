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
    pub(crate) fn write(
        out_path: &PathBuf,
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
