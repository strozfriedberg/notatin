use serde::Serialize;
use crate::registry::State;
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
        let (input, hive_bin_header) = HiveBinHeader::from_bytes(state, input)?;
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
            Err(e) => return Err(Error::Any {
                detail: format!("read_hive_bin: cell_key_node::read_cell_key_node {:#?}", e)
            })
        }
    }
}