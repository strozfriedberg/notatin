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
    pub file_start_pos: usize,
    pub hbin_offset_absolute: usize,
    pub file_buffer: &'a[u8],

    pub cell_key_node_stack: Vec<CellKeyNode>
}

impl<'a> State<'a> {
    pub fn new(f: &'a[u8], hbin_offset_absolute: usize) -> Self {
        State {
            file_start_pos: f.as_ptr() as usize,
            hbin_offset_absolute: hbin_offset_absolute,
            file_buffer: &f[..],
            cell_key_node_stack: Vec::new()
        }
    }

    pub fn get_file_offset(&self, input: &[u8]) -> usize {
        input.as_ptr() as usize - self.file_start_pos
    }
}

#[derive(Debug)]
pub struct Parser<'a> {
    pub state: State<'a>,
    pub filter: &'a mut Filter,
    pub s1: Vec<CellKeyNode>,
    pub s2: Vec<CellKeyNode>,
    pub base_block: Option<FileBaseBlock>,
    pub hive_bin_header: Option<HiveBinHeader>

}

impl<'a> Parser<'a> {
    pub fn new(file_buffer: &'a[u8], filter: &'a mut Filter) -> Self {
        Parser {
            state: State::new(&file_buffer, 0),
            filter,
            s1: Vec::new(),
            s2: Vec::new(),
            base_block: None,
            hive_bin_header: None
        }
    }

    pub fn init(&mut self) -> Result<bool, Error> {
        let file_start_pos = self.state.file_buffer.as_ptr() as usize;
        let (input, base_block) = FileBaseBlock::from_bytes(self.state.file_buffer)?;
        self.base_block = Some(base_block);
        self.state.hbin_offset_absolute = input.as_ptr() as usize - file_start_pos;

        let (input, hive_bin_header) = HiveBinHeader::from_bytes(&self.state, input)?;
        self.hive_bin_header = Some(hive_bin_header);

        match CellKeyNode::read(&mut self.state, input,String::new(), &mut self.filter)? {
            Some(cell_key_node_root) => {
                self.s1.push(cell_key_node_root);
                Ok(true)
            },
            None => Ok(false)
        }
    }

    /// Counts all subkeys and values of the
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

    fn next(&mut self) -> Option<Self::Item> {
        // Run while first stack is not empty
        while !self.s1.is_empty() {
            // first check to see if we are done with anything on s2; if so, we can pop, return it, and carry on.
            if !self.s2.is_empty() {
                let last = self.s2.last().expect("We checked that s2 wasn't empty");
                if last.track_returned == last.number_of_sub_keys {
                    return Some(self.s2.pop().expect("We checked that s2 wasn't empty"));
                }
            }
            let mut node = self.s1.pop().expect("We checked that s1 wasn't empty");
            // push all children of node to s1
            if node.number_of_sub_keys > 0 {
                let children = node.read_sub_keys(&mut self.state, &mut self.filter).unwrap();
                self.s1.extend(children);
            }
            if !self.s2.is_empty() {
                let last = self.s2.last_mut().expect("We checked that s2 wasn't empty");
                last.track_returned += 1;
            }
            self.s2.push(node);
        }

        // Handle any remaining elements
        while !self.s2.is_empty() {
            return Some(self.s2.pop().expect("We checked that s2 wasn't empty"));
        }
        return None;
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
        let mut state = State::new(&file_buffer, input.as_ptr() as usize - file_start_pos);
        Ok(Registry {
            header: file_base_block,
            hive_bin_root: HiveBin::read(&mut state, &input, String::new(), filter)?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use crate::filter::Filter;
    use crate::registry::Registry;

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
    }

    #[test]
    fn test_read_big_reg() {
        let f = std::fs::read("test_data/SOFTWARE_1_nfury").unwrap();

        //let ret = Registry::from_bytes(&f[..], &mut Filter::new());
        //let (keys, values) = ret.unwrap().hive_bin_root.unwrap().root.count_all_keys_and_values();
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

        //let ret = Registry::from_bytes(&f[..], &mut Filter::new());
        //let (keys, values) = ret.unwrap().hive_bin_root.unwrap().root.count_all_keys_and_values();

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
    fn dump_registry() {
        let f = std::fs::read("test_data/FuseHive").unwrap();
        let ret = Registry::from_bytes(&f[..], &mut Filter::new());

        let write_file = File::create("out.txt").unwrap();
        let mut writer = BufWriter::new(&write_file);
        write!(&mut writer, "{}", serde_json::to_string_pretty(&ret.unwrap()).unwrap()).expect("panic upon failure");
    }
}