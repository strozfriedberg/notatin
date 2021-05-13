use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use serde::Serialize;
use crate::base_block::FileBaseBlock;
use crate::filter::Filter;
use crate::err::Error;
use crate::cell_key_node::CellKeyNode;
use crate::hive_bin_header::HiveBinHeader;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/

#[derive(Debug, Eq, PartialEq)]
pub struct State {
    // file info
    pub file_start_pos: usize,
    pub hbin_offset_absolute: usize,
    pub file_buffer: Vec<u8>,

    // parser iteration
    pub cell_key_node_stack: Vec<CellKeyNode>,

    // filter evaulation
    pub value_complete: bool,
    pub key_complete: bool,
    pub root_key_path_offset: usize // path filters don't include the root name, but the cell key's paths do. This is the length of that root name so we can index into the string directly
}

impl State {
    pub fn from_path(filename: impl AsRef<Path>, hbin_offset_absolute: usize) -> Result<Self, Error> {
        let file_buffer = std::fs::read(filename)?;
        State::from_read_seek(Cursor::new(file_buffer), hbin_offset_absolute)
    }

    pub fn from_read_seek<T: ReadSeek>(mut data: T, hbin_offset_absolute: usize) -> Result<Self, Error> {
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
            root_key_path_offset: 0
        })
    }

    pub fn get_file_offset(&self, input: &[u8]) -> usize {
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

#[derive(Debug)]
pub struct Parser {
    pub state: State,
    pub filter: Filter,
    pub stack_to_traverse: Vec<CellKeyNode>,
    pub stack_to_return: Vec<CellKeyNode>,
    pub base_block: Option<FileBaseBlock>,
    pub hive_bin_header: Option<HiveBinHeader>
}

impl Parser {
    pub fn from_path(filename: impl AsRef<Path>, filter: Filter) -> Result<Self, Error> {
        Ok(Parser {
            state: State::from_path(filename, 0)?,
            filter,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            base_block: None,
            hive_bin_header: None
        })
    }

    pub fn from_read_seek<T: ReadSeek>(data: T, filter: Filter) -> Result<Self, Error> {
        Ok(Parser {
            state: State::from_read_seek(data, 0)?,
            filter,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            base_block: None,
            hive_bin_header: None
        })
    }

    pub fn init(&mut self) -> Result<bool, Error> {
        let file_start_pos = self.state.file_buffer.as_ptr() as usize;
        let (input, base_block) = FileBaseBlock::from_bytes(&self.state.file_buffer)?;
        self.base_block = Some(base_block);
        self.state.hbin_offset_absolute = input.as_ptr() as usize - file_start_pos;
        self.state.key_complete = false;
        self.state.value_complete = false;

        let (input, hive_bin_header) = HiveBinHeader::from_bytes(&self.state, input)?;
        self.hive_bin_header = Some(hive_bin_header);

        let offset = self.state.get_file_offset(input);
        let (kn, _) = CellKeyNode::read(&mut self.state, offset, &String::new(), &Filter::new())?; // we pass in a null filter for the root since matches by definition
        match kn {
            Some(cell_key_node_root) => {
                self.stack_to_traverse.push(cell_key_node_root);
                Ok(true)
            },
            None => Ok(false)
        }
    }

    /// Counts all subkeys and values
    pub fn count_all_keys_and_values(
        &mut self
    ) -> (usize, usize) {
        let mut keys = 0;
        let mut values = 0;
        for key in self {
            keys += 1;
            values += key.sub_values.len();
        }
        (keys, values)
    }
}

impl Iterator for Parser {
    type Item = CellKeyNode;

    // iterative post-order traversal
    fn next(&mut self) -> Option<Self::Item> {
        while !self.stack_to_traverse.is_empty() {
            // first check to see if we are done with anything on stack_to_return;
            // if so, we can pop, return it, and carry on (without this check we'd push every node onto the stack before returning anything)
            if !self.stack_to_return.is_empty() {
                let last = self.stack_to_return.last().expect("We checked that stack_to_return wasn't empty");
                if last.track_returned == last.number_of_sub_keys {
                    return Some(self.stack_to_return.pop().expect("We just checked that stack_to_return wasn't empty"));
                }
            }

            let mut node = self.stack_to_traverse.pop().expect("We just checked that stack_to_traverse wasn't empty");
            if node.number_of_sub_keys > 0 {
                let children = node.read_sub_keys(&mut self.state, &self.filter).unwrap();
                self.stack_to_traverse.extend(children);
            }
            if !self.stack_to_return.is_empty() {
                let last = self.stack_to_return.last_mut().expect("We checked that stack_to_return wasn't empty");
                last.track_returned += 1;
            }
            self.stack_to_return.push(node);
        }

        // Handle any remaining elements
        if !self.stack_to_return.is_empty() {
            return Some(self.stack_to_return.pop().expect("We just checked that stack_to_return wasn't empty"));
        }
        None
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Registry {
    pub header: FileBaseBlock,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use crate::filter::{Filter, FindPath};
    use md5;

    #[test]
    fn test_parser_iterator() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", Filter::new()).unwrap();
        let res = parser.init();
        assert_eq!(Ok(true), res);

        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (2288, 5470),
            (keys, values)
        );

        let res = parser.init();
        assert_eq!(Ok(true), res);
        let mut md5_context =  md5::Context::new();
        for key in parser {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "25c1c64894d5107d43d9edd3b17b1a9e",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn test_read_big_reg() {
        let mut parser = Parser::from_path("test_data/SOFTWARE_1_nfury", Filter::new()).unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );

        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (177877, 293276),
            (keys, values)
        );
    }

    #[test]
    fn test_read_small_reg() {
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", Filter::new()).unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );

        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (2288, 5470),
            (keys, values)
        );
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_kv_filter() {
        let filter = Filter::from_path(FindPath::from_key_value("Control Panel\\Accessibility\\HighContrast", "Flags"));
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", filter).unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );

        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (4, 1),
            (keys, values)
        );

        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );
        let mut md5_context =  md5::Context::new();
        for key in parser {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "2f0c1e14b72a26f61bdaf7128895b976",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn test_cell_key_node_count_all_keys_and_values_with_key_filter() {
        let filter = Filter::from_path(FindPath::from_key("Software\\Microsoft\\Office\\14.0\\Common"));
        let mut parser = Parser::from_path("test_data/NTUSER.DAT", filter).unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );
        let (keys, values) = parser.count_all_keys_and_values();
        assert_eq!(
            (45, 304),
            (keys, values),
            "key and/or value count doesn't match expected"
        );

        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );
        let mut md5_context =  md5::Context::new();
        for key in parser {
            md5_context.consume(key.path);
        }
        assert_eq!(
           "6ced711ecdfe62f4ae7f219f3e8341ef",
           format!("{:x}", md5_context.compute()),
           "Expected hash of paths doesn't match"
        );
    }

    #[test]
    fn dump_registry() {
        let write_file = File::create("NTUSER.DAT_iterative.jsonl").unwrap();
        let mut writer = BufWriter::new(&write_file);

        let mut parser = Parser::from_path("test_data/NTUSER.DAT", Filter::new()).unwrap();
        let res = parser.init();
        assert_eq!(
            Ok(true),
            res
        );
        for key in parser {
            writeln!(&mut writer, "{}", serde_json::to_string(&key).unwrap()).expect("panic upon failure");
        }
    }
}