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
        path: String,
        filter: &mut Filter
    ) -> Result<Option<HiveBin>, Error> {
        let (input, hive_bin_header) = HiveBinHeader::from_bytes(state, input)?;
        let res = CellKeyNode::read(state, input, path, filter)?;
        //HiveBin::postOrderIterative(state, filter, res.unwrap());

        /*

            .map_or(
                Ok(None),
                |hbr| Ok(Some(HiveBin {
                    header: hive_bin_header,
                    root: hbr
                }))
            );*/
        loop {
            match state.cell_key_node_stack.pop() {
                Some(mut cell_key_node) => {
                    println! ("pop: {}", cell_key_node.path);

                    for val in cell_key_node.cell_sub_key_offsets_absolute.iter() {
                        /*if let Some(kn) = CellKeyNode::read(
                           state,
                           &state.file_buffer[(*val as usize)..],
                           self.path.clone(),
                           filter
                       )? { self.sub_keys.push(kn) }*/

                       CellKeyNode::read(
                           state,
                           &state.file_buffer[(*val as usize)..],
                           cell_key_node.path.clone(),
                           filter
                       )?;
                    }

                    //cell_key_node.read_sub_keys(state, filter)?
                },
                None => break
            };
        }
        Ok(None)
    }
}