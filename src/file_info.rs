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

use crate::err::Error;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileInfo {
    pub hbin_offset_absolute: usize,
    pub buffer: Vec<u8>,
}

impl FileInfo {
    pub(crate) fn from_path<T>(filename: T) -> Result<Self, Error>
    where
        T: AsRef<Path>,
    {
        Self::from_read_seek(std::fs::File::open(filename)?)
    }

    pub(crate) fn from_read_seek<T: ReadSeek>(mut data_primary: T) -> Result<Self, Error> {
        let mut file_buffer_primary = Vec::new();
        data_primary.read_to_end(&mut file_buffer_primary)?;

        Ok(Self {
            hbin_offset_absolute: 0,
            buffer: file_buffer_primary,
        })
    }

    pub(crate) fn get_file_offset(&self, input: &[u8]) -> usize {
        self.get_file_offset_from_ptr(input.as_ptr() as usize)
    }

    pub(crate) fn get_file_offset_from_ptr(&self, ptr: usize) -> usize {
        ptr - self.buffer.as_ptr() as usize
    }
}

pub trait ReadSeek: Read + Seek + Send {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek + Send> ReadSeek for T {}
