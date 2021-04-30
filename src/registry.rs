use nom::Finish;
use serde::Serialize;
use crate::base_block::FileBaseBlock;
use crate::hive_bin::HiveBin;
use crate::filter::Filter;
use crate::err::Error;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files

    Summary
        A Base block points to a root cell, which contains a Key node.
        A Key node points to a parent Key node, to a Subkeys list (a subkey is a Key node too), to a Key values list, to a Key security item.
        A Subkeys list can be subdivided with the help of the Index root structure.
        A Key value points to data. Data may be stored in the Data offset field of a Key value structure, in a separate cell, or in a bunch of cells. In the last case, a Key value points to the Big data structure in a cell.
*/


#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct State<'a> { // todo: this isn't actually state.  that's a terrible name.  improve!
    pub file_start_pos: usize,
    pub hbin_offset: usize,
    pub file_buffer: &'a[u8]
}

impl State<'_> {
    pub fn get_file_offset(&self, input: &[u8]) -> usize {
        return input.as_ptr() as usize - self.file_start_pos;
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Registry {
    pub header: FileBaseBlock,
    pub hive_bin_root: Option<HiveBin>
}

impl Registry {
    /// Reads a Windows registry; returns a Registry object containing the information from the header and a tree of parsed hive bins
    pub fn from_bytes(
        file_buffer: &[u8],
        filter: &mut Filter
    ) -> Result<Self, Error> {
        let file_start_pos = file_buffer.as_ptr() as usize;
        match FileBaseBlock::from_bytes(file_buffer).finish() {
        Ok((input, file_base_block)) => {
                let state = State {
                    file_start_pos,
                    hbin_offset: input.as_ptr() as usize - file_start_pos,
                    file_buffer
                };
                let ret = HiveBin::read(&state, &input, String::new(), filter);
                match ret {
                    Ok(hive_bin) =>
                        Ok(Registry {
                            header: file_base_block,
                            hive_bin_root: hive_bin
                        }),
                    Err(e) => Err(e)
                }
            },
            Err(e) => return Err(Error::Nom {
                detail: format!("read_registry: parse_base_block {:#?}", e)
            })
        }
    }
}