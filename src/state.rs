use crate::cell_key_node::CellKeyNode;
use crate::transaction_log::TransactionLog;
use crate::log::{LogCode, Logs};
use crate::track_cell::TrackCell;

#[derive(Debug)]
pub(crate) struct State {
    recover_deleted: bool,
    pub transaction_logs: Option<Vec<TransactionLog>>,

    // parser iteration
    pub cell_key_node_stack: Vec<CellKeyNode>,

    // filter evaulation
    pub value_complete: bool,
    pub key_complete: bool,

    // Path filters don't include the root name, but the cell key's path does.
    // This is the length of that root name so we can index into the string directly.
    pub root_key_path_offset: usize,

    pub track_cells: Vec<TrackCell>,

    pub info: Logs
}

impl State {
    pub(crate) fn get_root_path_offset(&mut self, key_path: &str) -> usize {
        if self.root_key_path_offset == 0 {
            match key_path[1..].find('\\') {
                Some(second_backslash) => self.root_key_path_offset = second_backslash + 2,
                None => return 0
            }
        }
        self.root_key_path_offset
    }

    pub(crate) fn update_track_cells(&mut self, file_offset_absolute: usize) {
        if self.recover_deleted {
            let res = self.track_cells.binary_search_by_key(&file_offset_absolute, |a| a.file_offset_absolute);
            match res {
                Ok(index) => self.track_cells[index as usize].is_used = true,
                Err(e) => self.info.add(LogCode::WarningOther, &format!("Missing track_cell for file_offset_absolute {} ({})", file_offset_absolute, e))
            }
        }
    }

    pub(crate) fn untouched_cells(&self) {
        for tc in &self.track_cells {
            if !tc.is_used { //&& tc.cell_type != CellType::CellOther {
                println!("unused: {} {:?} (is allocated: {})", tc.file_offset_absolute, tc.cell_type, tc.is_allocated);
            }
        }
    }

    pub(crate) fn from_transaction_logs(logs: Option<Vec<TransactionLog>>, recover_deleted: bool) -> Self {
        State { transaction_logs: logs, recover_deleted, ..Default::default() }
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            cell_key_node_stack: Vec::new(),
            recover_deleted: false,
            value_complete: false,
            key_complete: false,
            root_key_path_offset: 0,
            transaction_logs: None,
            track_cells: Vec::new(),
            info: Logs::default()
        }
    }
}