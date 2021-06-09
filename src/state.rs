use std::collections::HashMap;
use blake3::{Hash, Hasher};
use crate::file_info::FileInfo;
use crate::cell_key_node::CellKeyNode;
use crate::cell_key_value::CellKeyValue;
use crate::transaction_log::TransactionLog;
use crate::log::{LogCode, Logs};
use crate::track_cell::{TrackHbin, TrackCell, TrackCellFlags};

#[derive(Clone, Debug)]
pub(crate) struct ModifiedValueMap {
    pub map: HashMap<(String, String), Vec<CellKeyValue>>
}

impl ModifiedValueMap {
    pub(crate) fn new() -> Self {
        ModifiedValueMap {
            map: HashMap::new()
        }
    }

    pub(crate) fn add(&mut self, key_path: &str, value_name: &str, value: CellKeyValue) {
        match self.map.get_mut(&(key_path.to_string(), value_name.to_string())) {
            Some(vec) => { vec.push(value); },
            None => { self.map.insert((key_path.to_string(), value_name.to_string()), vec![value]); }
        }
    }

    pub(crate) fn get(&self, key_path: &str, value_name: &str) -> Option<&Vec<CellKeyValue>> {
        self.map.get(&(key_path.to_string(), value_name.to_string()))
    }

    pub(crate) fn remove(&mut self, key_path: &str, value_name: &str, hash: &Hash) {
        let key_value_name = &(key_path.to_string(), value_name.to_string());
        if let Some(values) = self.map.get_mut(key_value_name) {
            let mut index = 0;
            for value in values.iter() {
                if let Some(value_hash) = value.hash {
                    if hash == &value_hash {
                        values.remove(index);
                        if values.is_empty() {
                            self.map.remove(key_value_name);
                        }
                        break;
                    }
                }
                index += 1;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ModifiedKeyMap {
    pub map: HashMap<String, Vec<CellKeyNode>>
}

impl ModifiedKeyMap {
    pub(crate) fn new() -> Self {
        ModifiedKeyMap {
            map: HashMap::new()
        }
    }

    pub(crate) fn add(&mut self, path: &str, value: CellKeyNode) {
        match self.map.get_mut(path) {
            Some(vec) => { vec.push(value); },
            None => { self.map.insert(path.to_string(), vec![value]); }
        }
    }

    pub(crate) fn get(&self, path: &str) -> Option<&Vec<CellKeyNode>> {
        self.map.get(path)
    }

    pub(crate) fn remove(&mut self, path: &str, hash: &Hash) {
        let parent_path = &path[0..path.rfind('\\').unwrap_or_default()];
        if let Some(keys) = self.map.get_mut(parent_path) {
            let mut index = 0;
            for key in keys.iter() {
                if let Some(key_hash) = key.hash {
                    if hash == &key_hash && path == key.path {
                        keys.remove(index);
                        if keys.is_empty() {
                            self.map.remove(path);
                        }
                        break;
                    }
                }
                index += 1;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct State {
    pub recover_deleted: bool,
    pub transaction_logs: Option<Vec<TransactionLog>>,

    // parser iteration
    pub cell_key_node_stack: Vec<CellKeyNode>,

    // filter evaulation
    pub value_complete: bool,
    pub key_complete: bool,

    // Path filters don't include the root name, but the cell key's path does.
    // This is the length of that root name so we can index into the string directly.
    pub root_key_path_offset: usize,

   // pub track_cells: Vec<TrackCell>,
    pub track_hbins: Vec<TrackHbin>,

    pub info: Logs,

    pub hasher: Hasher,

    pub sequence_numbers: HashMap<(String, Option<String>), u32>,
    pub deleted_keys: ModifiedKeyMap,
    pub updated_keys: ModifiedKeyMap,
    pub deleted_values: ModifiedValueMap,
    pub updated_values: ModifiedValueMap,
}

impl State {
    pub(crate) fn reset_filter_state(&mut self) {
        self.key_complete = false;
        self.value_complete = false;
    }

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
        /*if self.recover_deleted {
            match TrackHbin::find_hbin_mut(&mut self.track_hbins, file_offset_absolute) {
                Some(hbin) => {
                    match hbin.track_cells.binary_search_by_key(&file_offset_absolute, |a| a.file_offset_absolute) {
                        Ok(index) => hbin.track_cells[index as usize].cell_flags |= TrackCellFlags::TRACK_CELL_USED,
                        Err(e) => self.info.add(LogCode::WarningOther, &format!("Missing track_cell for file_offset_absolute {} ({})", file_offset_absolute, e))
                    }
                },
                None => self.info.add(LogCode::WarningOther, &format!("Missing track_hbin for file_offset_absolute {}", file_offset_absolute))
            }
        }*/
    }

    pub(crate) fn untouched_cells(&self) {
        for th in &self.track_hbins {
            for tc in &th.track_cells {
                if !tc.cell_flags.contains(TrackCellFlags::TRACK_CELL_USED) { //&& tc.cell_type != CellType::CellOther {
                    println!("unused: {} {:?} (is allocated: {})", tc.file_offset_absolute, tc.cell_type, tc.cell_flags.contains(TrackCellFlags::TRACK_CELL_ALLOCATED));
                }
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
            track_hbins: Vec::new(),
            info: Logs::default(),
            hasher: Hasher::new(),
            sequence_numbers: HashMap::new(),
            deleted_keys: ModifiedKeyMap::new(),
            updated_keys: ModifiedKeyMap::new(),
            deleted_values: ModifiedValueMap::new(),
            updated_values: ModifiedValueMap::new()
        }
    }
}