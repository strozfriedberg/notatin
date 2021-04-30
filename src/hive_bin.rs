use nom::Finish;
use serde::Serialize;
use crate::base_block::State;
use crate::hive_bin_header::HiveBinHeader;
use crate::cell_key_node::CellKeyNode;
use crate::filter::Filter;
use crate::err::Error;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct HiveBin {
    pub header: HiveBinHeader,
    pub root: CellKeyNode
}

impl HiveBin {
    pub fn read(
        state: &State,
        input: &[u8],
        path: String,
        filter: &mut Filter
    ) -> Result<Option<HiveBin>, Error> {
        match HiveBinHeader::from_bytes(state, input).finish() {
            Ok((input, hive_bin_header)) => {
                let res_hive_bin_root = CellKeyNode::read(state, input, path, filter);
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
}