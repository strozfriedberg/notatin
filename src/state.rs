/*
 * Copyright 2021 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::cell_key_node::CellKeyNode;
use crate::cell_key_value::CellKeyValue;
use crate::log::Logs;
use crate::util;
use blake3::{Hash, Hasher};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub(crate) struct ModifiedValueMap {
    pub map: HashMap<(String, String), Vec<CellKeyValue>>,
}

impl ModifiedValueMap {
    pub(crate) fn new() -> Self {
        ModifiedValueMap {
            map: HashMap::new(),
        }
    }

    pub(crate) fn add(&mut self, key_path: &str, value_name: &str, value: CellKeyValue) {
        match self
            .map
            .get_mut(&(key_path.to_string(), value_name.to_string()))
        {
            Some(vec) => {
                vec.push(value);
            }
            None => {
                self.map
                    .insert((key_path.to_string(), value_name.to_string()), vec![value]);
            }
        }
    }

    pub(crate) fn get(&self, key_path: &str, value_name: &str) -> Option<&Vec<CellKeyValue>> {
        self.map
            .get(&(key_path.to_string(), value_name.to_string()))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DeletedValueMap {
    pub map: HashMap<String, Vec<CellKeyValue>>,
}

impl DeletedValueMap {
    pub(crate) fn new() -> Self {
        DeletedValueMap {
            map: HashMap::new(),
        }
    }

    pub(crate) fn add(&mut self, key_path: &str, value: CellKeyValue) {
        match self.map.get_mut(&key_path.to_string()) {
            Some(vec) => {
                vec.push(value);
            }
            None => {
                self.map.insert(key_path.to_string(), vec![value]);
            }
        }
    }

    pub(crate) fn get(&self, key_path: &str) -> Option<&Vec<CellKeyValue>> {
        self.map.get(&key_path.to_string())
    }

    pub(crate) fn remove(&mut self, key_path: &str, value_name: &str, hash: &Hash) {
        if let Some(values) = self.map.get_mut(key_path) {
            for (index, value) in values.iter().enumerate() {
                if value.value_name == value_name {
                    if let Some(value_hash) = value.hash {
                        if hash == &value_hash {
                            values.remove(index);
                            if values.is_empty() {
                                self.map.remove(key_path);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ModifiedDeletedKeyMap {
    pub map: HashMap<String, Vec<CellKeyNode>>,
}

impl ModifiedDeletedKeyMap {
    pub(crate) fn new() -> Self {
        ModifiedDeletedKeyMap {
            map: HashMap::new(),
        }
    }

    pub(crate) fn add(&mut self, path: &str, value: CellKeyNode) {
        match self.map.get_mut(path) {
            Some(vec) => {
                vec.push(value);
            }
            None => {
                self.map.insert(path.to_string(), vec![value]);
            }
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
    // Path filters don't include the root name, but the cell key's path does.
    // This is the length of that root name so we can index into the string directly.
    pub root_key_path_offset: usize,

    pub info: Logs,

    pub hasher: Hasher,

    pub deleted_keys: ModifiedDeletedKeyMap,
    pub updated_keys: ModifiedDeletedKeyMap,
    pub deleted_values: DeletedValueMap,
    pub updated_values: ModifiedValueMap,
}

impl State {
    pub(crate) fn get_root_path_offset(&mut self, key_path: &str) -> usize {
        if self.root_key_path_offset == 0 {
            self.root_key_path_offset = util::get_root_path_offset(key_path)
        }
        self.root_key_path_offset
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            root_key_path_offset: 0,
            info: Logs::default(),
            hasher: Hasher::new(),
            deleted_keys: ModifiedDeletedKeyMap::new(),
            updated_keys: ModifiedDeletedKeyMap::new(),
            deleted_values: DeletedValueMap::new(),
            updated_values: ModifiedValueMap::new(),
        }
    }
}
