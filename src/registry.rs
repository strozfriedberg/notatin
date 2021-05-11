use serde::Serialize;
use crate::base_block::FileBaseBlock;
use crate::hive_bin::HiveBin;
use crate::filter::Filter;
use crate::err::Error;
use crate::cell_key_node::CellKeyNode;
use crate::hive_bin_header::HiveBinHeader;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/

#[derive(Debug, Eq, PartialEq)]
pub struct State<'a> {
    // file info
    pub file_start_pos: usize,
    pub hbin_offset_absolute: usize,
    pub file_buffer: &'a[u8],

    // parser iteration
    pub cell_key_node_stack: Vec<CellKeyNode>,

    // filter evaulation
    pub value_complete: bool,
    pub key_complete: bool,
    pub root_key_path_offset: usize // path filters don't include the root name, but the cell key's paths do. This is the length of that root name so we can index into the string directly
}

impl<'a> State<'a> {
    pub fn new(f: &'a[u8], hbin_offset_absolute: usize) -> Self {
        State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset_absolute,
            file_buffer: f,
            cell_key_node_stack: Vec::new(),
            value_complete: false,
            key_complete: false,
            root_key_path_offset: 0
        }
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

#[derive(Debug)]
pub struct Parser<'a> {
    pub state: State<'a>,
    pub filter: &'a Filter,
    pub stack_to_traverse: Vec<CellKeyNode>,
    pub stack_to_return: Vec<CellKeyNode>,
    pub base_block: Option<FileBaseBlock>,
    pub hive_bin_header: Option<HiveBinHeader>

}

impl<'a> Parser<'a> {
    pub fn new(file_buffer: &'a[u8], filter: &'a Filter) -> Self {
        Parser {
            state: State::new(&file_buffer, 0),
            filter,
            stack_to_traverse: Vec::new(),
            stack_to_return: Vec::new(),
            base_block: None,
            hive_bin_header: None
        }
    }

    pub fn init(&mut self) -> Result<bool, Error> {
        let file_start_pos = self.state.file_buffer.as_ptr() as usize;
        let (input, base_block) = FileBaseBlock::from_bytes(self.state.file_buffer)?;
        self.base_block = Some(base_block);
        self.state.hbin_offset_absolute = input.as_ptr() as usize - file_start_pos;
        self.state.key_complete = false;
        self.state.value_complete = false;

        let (input, hive_bin_header) = HiveBinHeader::from_bytes(&self.state, input)?;
        self.hive_bin_header = Some(hive_bin_header);

        let (kn, _) = CellKeyNode::read(&mut self.state, input, &String::new(), &Filter::new())?; // we pass in a null filter for the root since matches by definition
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

impl Iterator for Parser<'_> {
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
    pub hive_bin_root: Option<HiveBin>
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
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let mut filter = Filter::new();
        let mut parser = Parser::new(&f, &mut filter);
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
        let f = std::fs::read("test_data/SOFTWARE_1_nfury").unwrap();

        let mut filter = Filter::new();
        let mut parser = Parser::new(&f, &mut filter);
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
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let mut filter = Filter::new();
        let mut parser = Parser::new(&f, &mut filter);
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
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let mut filter = Filter::from_path(FindPath::from_key_value("Control Panel\\Accessibility\\HighContrast", "Flags"));
        let mut parser = Parser::new(&f, &mut filter);
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
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();
        let mut filter = Filter::from_path(FindPath::from_key("Software\\Microsoft\\Office\\14.0\\Common"));
        let mut parser = Parser::new(&f, &mut filter);
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
        let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

        let write_file = File::create("NTUSER.DAT_iterative.jsonl").unwrap();
        let mut writer = BufWriter::new(&write_file);

        let mut filter = Filter::new();
        let mut parser = Parser::new(&f, &mut filter);
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