use serde::Serialize;
use crate::base_block::FileBaseBlock;
use crate::hive_bin::HiveBin;
use crate::filter::Filter;
use crate::err::Error;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/

#[derive(Debug, Eq, PartialEq)]
pub struct State<'a> {
    pub file_start_pos: usize,
    pub hbin_offset_absolute: usize,
    pub file_buffer: &'a[u8]
}

impl<'a> State<'a> {
    pub fn new(f: &'a[u8], hbin_offset_absolute: usize) -> Self {
        State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset_absolute: hbin_offset_absolute,
            file_buffer: &f[..]
        }
    }

    pub fn get_file_offset(&self, input: &[u8]) -> usize {
        input.as_ptr() as usize - self.file_start_pos
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Registry {
    pub header: FileBaseBlock,
    pub hive_bin_root: Option<HiveBin>
}

impl Registry {
    /// Reads a Windows registry; returns a Registry object containing the information from the header and a tree of parsed hive bins
    pub fn from_bytes(file_buffer: &[u8], filter: &mut Filter) -> Result<Self, Error> {
        let file_start_pos = file_buffer.as_ptr() as usize;
        let (input, file_base_block) = FileBaseBlock::from_bytes(file_buffer)?;
        let state = State::new(&file_buffer, input.as_ptr() as usize - file_start_pos);
        Ok(Registry {
            header: file_base_block,
            hive_bin_root: HiveBin::read(&state, &input, String::new(), filter)?
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use crate::filter::Filter;
    use crate::registry::Registry;

    #[test]
    fn test_read_big_reg() {
        let f = std::fs::read("test_data/SOFTWARE_1_nfury").unwrap();

        let ret = Registry::from_bytes(&f[..], &mut Filter::new());
        let (keys, values) = ret.unwrap().hive_bin_root.unwrap().root.count_all_keys_and_values();
        assert_eq!(
            (177876, 293276),
            (keys, values)
        );
    }

    #[test]
    fn test_read_small_reg() {
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let ret = Registry::from_bytes(&f[..], &mut Filter::new());
        let (keys, values) = ret.unwrap().hive_bin_root.unwrap().root.count_all_keys_and_values();
        assert_eq!(
            (2287, 5470),
            (keys, values)
        );
    }

    #[test]
    fn dump_registry() {
        let f = std::fs::read("test_data/FuseHive").unwrap();
        let ret = Registry::from_bytes(&f[..], &mut Filter::new());

        let write_file = File::create("out.txt").unwrap();
        let mut writer = BufWriter::new(&write_file);
        write!(&mut writer, "{}", serde_json::to_string_pretty(&ret.unwrap()).unwrap()).expect("panic upon failure");
    }
}