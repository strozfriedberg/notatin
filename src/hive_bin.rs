use nom::Finish;
use std::path::{PathBuf};
use std::ffi::OsString;
use serde::Serialize;
use crate::hive_bin_header;
use crate::cell_key_node;
use crate::filter;
use crate::err::Error;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct HiveBin {
    pub header: hive_bin_header::HiveBinHeader,
    pub root: cell_key_node::CellKeyNode
}

pub fn read_hive_bin<'a>(
    input: &'a [u8],
    file_buffer: &[u8],
    path: String,
    filter: &mut filter::Filter
) -> Result<Option<HiveBin>, Error> {
    match hive_bin_header::parse_hive_bin_header(input).finish() {
        Ok((input, hive_bin_header)) => {
            let res_hive_bin_root = cell_key_node::read_cell_key_node(input, file_buffer, hive_bin_header.size, path, filter);
            match res_hive_bin_root {
                Ok(hive_bin_root) =>
                    match hive_bin_root {
                        Some(hbr) =>
                            Ok(Some(HiveBin {
                                    header: hive_bin_header,
                                    root: hbr
                                })
                            ),
                        None => Ok(None)
                    },
                Err(e) => return Err(Error::Nom {
                    detail: format!("read_hive_bin: cell_key_node::read_cell_key_node {:#?}", e)
                })
            }
        },
        Err(e) => return Err(Error::Nom {
            detail: format!("read_hive_bin: hive_bin_header::parse_hive_bin_header {:#?}", e)
        })
    }
}