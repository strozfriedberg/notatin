use std::collections::HashMap;
use blake3::{Hash, Hasher};
use crate::cell_key_node::CellKeyNode;
use crate::cell_key_value::CellKeyValue;
use crate::transaction_log::TransactionLog;
use crate::log::Logs;

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
            for (index, value) in values.iter().enumerate() {
                if let Some(value_hash) = value.hash {
                    if hash == &value_hash {
                        values.remove(index);
                        if values.is_empty() {
                            self.map.remove(key_value_name);
                        }
                        break;
                    }
                }
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
            for (index, key) in keys.iter().enumerate() {
                if let Some(key_hash) = key.hash {
                    if hash == &key_hash && path == key.path {
                        keys.remove(index);
                        if keys.is_empty() {
                            self.map.remove(path);
                        }
                        break;
                    }
                }
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

    // Path filters don't include the root name, but the cell key's path does.
    // This is the length of that root name so we can index into the string directly.
    pub root_key_path_offset: usize,

    pub info: Logs,

    pub hasher: Hasher,

    pub sequence_numbers: HashMap<(String, Option<String>), u32>,
    pub deleted_keys: ModifiedKeyMap,
    pub updated_keys: ModifiedKeyMap,
    pub deleted_values: ModifiedValueMap,
    pub updated_values: ModifiedValueMap,
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

    pub(crate) fn from_transaction_logs(logs: Option<Vec<TransactionLog>>, recover_deleted: bool) -> Self {
        State { transaction_logs: logs, recover_deleted, ..Default::default() }
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            cell_key_node_stack: Vec::new(),
            recover_deleted: false,
            root_key_path_offset: 0,
            transaction_logs: None,
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