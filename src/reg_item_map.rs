/*
 * Copyright 2023 Aon Cyber Solutions
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

use std::collections::HashMap;

pub(crate) type RegItemMap = HashMap<RegItemMapKey, RegItemMapValue>;

#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) struct RegItemMapKey {
    pub(crate) key_path: String,
    pub(crate) value_name: Option<String>,
}

impl RegItemMapKey {
    pub(crate) fn new(key_path: String, value_name: Option<String>) -> Self {
        Self {
            key_path,
            value_name,
        }
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) struct RegItemMapValue {
    pub(crate) hash: blake3::Hash,
    pub(crate) file_offset_absolute: usize,
    pub(crate) sequence_num: u32,
}

impl RegItemMapValue {
    pub(crate) fn new(hash: blake3::Hash, file_offset_absolute: usize, sequence_num: u32) -> Self {
        Self {
            hash,
            file_offset_absolute,
            sequence_num,
        }
    }
}
