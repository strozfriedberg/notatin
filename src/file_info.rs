use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use nom::number::complete::le_i32;
use crate::err::Error;
use crate::hive_bin_header::HiveBinHeader;
use crate::track_cell::{TrackCell, TrackCellFlags, TrackHbin};

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

    pub(crate) fn walk_hbin(
        &self,
        mut file_offset_absolute: usize,
        sequence_number: u32,
        hasher: &mut blake3::Hasher
    ) -> Result<(usize, TrackHbin), Error> {
        let (input, hbin_header) =
            HiveBinHeader::from_bytes(
                &self,
                &self.buffer[file_offset_absolute..]
            )?;

        let hbin_size  = hbin_header.size as usize;
        let hbin_start = file_offset_absolute;
        file_offset_absolute = self.get_file_offset(input);

        let (file_offset_absolute, track_cells) =
            self.walk_cells(
                file_offset_absolute,
                hbin_start + hbin_size,
                sequence_number,
                hasher
            )?;

        Ok((
            file_offset_absolute,
            TrackHbin {
                file_offset_absolute: hbin_start,
                size: hbin_size,
                track_cells
            }
        ))
    }

    fn walk_cells(
        &self,
        mut file_offset_absolute: usize,
        hbin_max: usize,
        sequence_number: u32,
        hasher: &mut blake3::Hasher
    ) -> Result<(usize, Vec<TrackCell>), Error> {
        let mut track_cells = Vec::new();
        let mut input = &self.buffer[file_offset_absolute..];
        while file_offset_absolute < hbin_max {
            let (input_ret, size) = le_i32(input)?;
            if size == 0 {
                break;
            }
            input = input_ret;
            let cell_type = TrackCell::read_cell_type(input);
            let size_abs = size.abs() as usize;
            let cell_slice = &self.buffer[file_offset_absolute..file_offset_absolute + size_abs];
            hasher.update(cell_slice);
            let hash = hasher.finalize();
            hasher.reset();
            let cell_flags;
            if size < 0 {
                cell_flags = TrackCellFlags::TRACK_CELL_ALLOCATED;
            }
            else {
                cell_flags = TrackCellFlags::empty();
            }

            track_cells.push(
                TrackCell {
                    file_offset_absolute,
                    cell_type,
                    cell_flags,
                    sequence_num: sequence_number,
                    hash
                }
            );
            file_offset_absolute += size_abs;
            input = &self.buffer[file_offset_absolute..];
        }
        TrackCell::sort(&mut track_cells);

        Ok((file_offset_absolute, track_cells))
    }
}

pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek> ReadSeek for T {}
