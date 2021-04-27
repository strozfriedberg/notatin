use nom::Finish;
use std::path::{PathBuf};
use crate::hive_bin_header;
use crate::hive_bin_cell_key_node;
use crate::filter;
use crate::err::Error;

#[derive(Debug, Eq, PartialEq)]
pub struct HiveBin {
    pub header: hive_bin_header::HiveBinHeader,
    pub root: hive_bin_cell_key_node::HiveBinCellKeyNode
}

pub fn read_hive_bin<'a>(
    input: &'a [u8], 
    file_buffer: &[u8], 
    path: PathBuf, 
    filter: &mut filter::Filter
) -> Result<Option<HiveBin>, Error> {
    match hive_bin_header::parse_hive_bin_header(input).finish() {
        Ok((input, hive_bin_header)) => {
            let res_hive_bin_root = hive_bin_cell_key_node::read_hive_bin_cell_key_node(input, file_buffer, hive_bin_header.size, path, filter);
            match res_hive_bin_root {
                Ok(hive_bin_root) =>
                    match hive_bin_root {
                        Some(hbr) =>
                            return Ok(Some(HiveBin {
                                    header: hive_bin_header,
                                    root: hbr
                                })
                            ),
                        None => return Ok(None) 
                    },
                Err(e) => return Err(Error::Nom {
                    detail: format!("read_hive_bin: hive_bin_cell_key_node::read_hive_bin_cell_key_node {:#?}", e)
                })
            }
        },
        Err(e) => return Err(Error::Nom {
            detail: format!("read_hive_bin: hive_bin_header::parse_hive_bin_header {:#?}", e)
        })
    }
}