use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use crate::err::Error;
use crate::cell_key_node::CellKeyNode;
use crate::transaction_log::TransactionLog;
use crate::warn::Warnings;
/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct State {
    // file info
    pub file_start_pos: usize,
    pub hbin_offset_absolute: usize,
    pub file_buffer: Vec<u8>,
    pub transaction_logs: Option<Vec<TransactionLog>>,

    // parser iteration
    pub cell_key_node_stack: Vec<CellKeyNode>,

    // filter evaulation
    pub value_complete: bool,
    pub key_complete: bool,
    pub root_key_path_offset: usize, // path filters don't include the root name, but the cell key's paths do. This is the length of that root name so we can index into the string directly

    pub info: Warnings
}

impl State {
    pub(crate) fn from_path(filename: impl AsRef<Path>, hbin_offset_absolute: usize) -> Result<Self, Error> {
        let fh = std::fs::File::open(filename)?;
        State::from_read_seek(fh, hbin_offset_absolute)
    }

    pub(crate) fn from_read_seek<T: ReadSeek>(mut data: T, hbin_offset_absolute: usize) -> Result<Self, Error> {
        let mut file_buffer = Vec::new();
        data.read_to_end(&mut file_buffer)?;
        let slice = &file_buffer;
        Ok(State {
            file_start_pos: slice.as_ptr() as usize,
            hbin_offset_absolute,
            file_buffer,
            cell_key_node_stack: Vec::new(),
            value_complete: false,
            key_complete: false,
            root_key_path_offset: 0,
            transaction_logs: None,
            info: Warnings::default()
        })
    }

    pub(crate) fn from_path_with_logs(filename: impl AsRef<Path>, logs: Vec<impl AsRef<Path>>, hbin_offset_absolute: usize) -> Result<Self, Error> {
        let fh_primary = std::fs::File::open(filename)?;
        let mut fh_logs = Vec::new();
        for log in logs {
            fh_logs.push(std::fs::File::open(log)?);
        }
        State::from_read_seek_with_logs(fh_primary, fh_logs, hbin_offset_absolute)
    }

    pub(crate) fn from_read_seek_with_logs<T: ReadSeek>(mut data_primary: T, data_logs: Vec<T>, hbin_offset_absolute: usize) -> Result<Self, Error> {
        let mut file_buffer_primary = Vec::new();
        data_primary.read_to_end(&mut file_buffer_primary)?;
        let slice = &file_buffer_primary;

        let mut transaction_logs = Vec::new();
        for mut data_log in data_logs {
            let mut file_buffer_log = Vec::new();
            data_log.read_to_end(&mut file_buffer_log)?;
            let slice_log = &file_buffer_log[0..];
            let (_, log) = TransactionLog::from_bytes(slice_log.as_ptr() as usize, slice_log)?;
            transaction_logs.push(log);
        }

        Ok(State {
            file_start_pos: slice.as_ptr() as usize,
            hbin_offset_absolute,
            file_buffer: file_buffer_primary,
            cell_key_node_stack: Vec::new(),
            value_complete: false,
            key_complete: false,
            root_key_path_offset: 0,
            transaction_logs: Some(transaction_logs),
            info: Warnings::default()
        })
    }

    pub(crate) fn get_file_offset(&self, input: &[u8]) -> usize {
        input.as_ptr() as usize - self.file_start_pos
    }

    pub(crate) fn get_root_path_offset(&mut self, key_path: &str) -> usize {
        if self.root_key_path_offset == 0 {
            match key_path[1..].find('\\') {
                Some(second_backslash) => self.root_key_path_offset = second_backslash + 2,
                None => return 0
            }
        }
        self.root_key_path_offset
    }
}

pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek> ReadSeek for T {}
