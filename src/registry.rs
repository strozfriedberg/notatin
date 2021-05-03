use nom::Finish;
use serde::Serialize;
use crate::base_block::FileBaseBlock;
use crate::hive_bin::HiveBin;
use crate::filter::Filter;
use crate::err::Error;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files
*/

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct State<'a> { // todo: this isn't actually state.  that's a terrible name.  improve!
    pub file_start_pos: usize,
    pub hbin_offset: usize,
    pub file_buffer: &'a[u8]
}

impl State<'_> {
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
        let state = State {
            file_start_pos,
            hbin_offset: input.as_ptr() as usize - file_start_pos,
            file_buffer
        };
        Ok(Registry {
            header: file_base_block,
            hive_bin_root: HiveBin::read(&state, &input, String::new(), filter)?
        })
    }
}