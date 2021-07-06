use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use crate::err::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileInfo {
    pub hbin_offset_absolute: usize,
    pub buffer: Vec<u8>,
}

impl FileInfo {
    pub(crate) fn from_path<T>(filename: T) -> Result<Self, Error>
    where
        T: AsRef<Path>
    {
        Self::from_read_seek(std::fs::File::open(filename)?)
    }

    pub(crate) fn from_read_seek<T: ReadSeek>(mut data_primary: T) -> Result<Self, Error> {
        let mut file_buffer_primary = Vec::new();
        data_primary.read_to_end(&mut file_buffer_primary)?;

        Ok(Self {
            hbin_offset_absolute: 0,
            buffer: file_buffer_primary
        })
    }

    pub(crate) fn get_file_offset(&self, input: &[u8]) -> usize {
        self.get_file_offset_from_ptr(input.as_ptr() as usize)
    }

    pub(crate) fn get_file_offset_from_ptr(&self, ptr: usize) -> usize {
        ptr - self.buffer.as_ptr() as usize//self.start_pos
    }
}

pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek> ReadSeek for T {}
