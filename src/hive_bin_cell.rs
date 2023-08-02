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

use core::fmt::Debug;

pub trait CellSubKeyList {
    fn size(&self) -> u32;
    fn get_offset_list(&self, hbin_offset_absolute: u32) -> Vec<u32>;
}

impl Debug for dyn CellSubKeyList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CellSubKeyList size:{}", self.size())
    }
}

impl PartialEq for dyn CellSubKeyList {
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() && self.get_offset_list(0) == other.get_offset_list(0)
    }
}

impl Eq for dyn CellSubKeyList {}
