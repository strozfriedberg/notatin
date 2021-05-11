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
        state: &mut State,
        input: &[u8],
        path: &str,
        filter: &Filter
    ) -> Result<Option<HiveBin>, Error> {
        let (input, hive_bin_header) = HiveBinHeader::from_bytes(state, input)?;
        let (kn, _) = CellKeyNode::read(state, input, path, filter)?;
        kn.map_or(
                Ok(None),
                |hbr| Ok(Some(HiveBin {
                    header: hive_bin_header,
                    root: hbr
                }))
            )
    }
}