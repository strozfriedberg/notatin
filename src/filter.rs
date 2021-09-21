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
use crate::err::Error;
use crate::impl_serialize_for_bitflags;
use crate::state::State;
use bitflags::bitflags;
use regex::Regex;

/// Filter allows specification of a condition to be met when reading the registry.
/// Evaluation will short-circuit when possible
#[derive(Clone, Debug, Default)]
pub struct Filter {
    reg_query: Option<RegQuery>,
}

impl Filter {
    pub fn new() -> Self {
        Filter { reg_query: None }
    }

    pub fn is_valid(&self) -> bool {
        self.reg_query.is_some()
    }

    pub(crate) fn check_cell(&self, state: &mut State, cell: &CellKeyNode) -> FilterFlags {
        if self.is_valid() {
            self.match_cell(state, cell)
        } else {
            FilterFlags::FILTER_ITERATE_KEYS
        }
    }

    pub(crate) fn match_cell(&self, state: &mut State, cell: &CellKeyNode) -> FilterFlags {
        if cell.is_key_root() {
            if let Some(reg_query) = &self.reg_query {
                if !reg_query.key_path_has_root {
                    return FilterFlags::FILTER_ITERATE_KEYS;
                }
            }
        }
        self.match_key(state, cell.lowercase())
    }

    fn match_key(&self, state: &mut State, key_path: String) -> FilterFlags {
        if let Some(reg_query) = &self.reg_query {
            reg_query.check_key_match(&key_path, state.get_root_path_offset(&key_path))
        } else {
            FilterFlags::FILTER_ITERATE_KEYS
        }
    }

    pub(crate) fn return_sub_keys(&self) -> bool {
        match &self.reg_query {
            Some(fp) => fp.children,
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub enum RegQueryComponent {
    ComponentString(String),
    ComponentRegex(Regex),
}

#[derive(Clone, Debug, Default)]
pub struct FilterBuilder {
    key_path: Vec<RegQueryComponent>,
    key_path_has_root: bool,
    children: bool,
    regex_errors: Vec<String>,
}

impl FilterBuilder {
    pub fn new() -> Self {
        FilterBuilder {
            key_path: vec![],
            key_path_has_root: false,
            children: false,
            regex_errors: vec![],
        }
    }

    pub fn add_key_path(mut self, key_path: &str) -> Self {
        for segment in key_path.trim_end_matches('\\').split('\\') {
            Self::add_literal_segment_internal(&mut self.key_path, segment);
        }
        self
    }

    pub fn add_literal_segment(mut self, segment: &str) -> Self {
        Self::add_literal_segment_internal(&mut self.key_path, segment.trim_matches('\\'));
        self
    }

    fn add_literal_segment_internal(key_path: &mut Vec<RegQueryComponent>, segment: &str) {
        key_path.push(RegQueryComponent::ComponentString(
            segment.to_ascii_lowercase(),
        ));
    }

    pub fn add_regex_segment(mut self, regex: &str) -> Self {
        match Regex::new(&regex.to_ascii_lowercase()) {
            Ok(r) => self.key_path.push(RegQueryComponent::ComponentRegex(r)),
            Err(e) => self.regex_errors.push(e.to_string()),
        }
        self
    }

    pub fn key_path_has_root(mut self, key_path_has_root: bool) -> Self {
        self.key_path_has_root = key_path_has_root;
        self
    }

    pub fn return_child_keys(mut self, children: bool) -> Self {
        self.children = children;
        self
    }

    pub fn build(self) -> Result<Filter, Error> {
        if self.regex_errors.is_empty() {
            Ok(Filter {
                reg_query: Some(RegQuery {
                    key_path: self.key_path,
                    key_path_has_root: self.key_path_has_root,
                    children: self.children,
                }),
            })
        } else {
            Err(Error::Any {
                detail: format!("Regex errors encountered: {}", self.regex_errors.join(", ")),
            })
        }
    }
}

/// ReqQuery is a structured filter which allows for regular expressions
#[derive(Clone, Debug, Default)]
pub struct RegQuery {
    pub(crate) key_path: Vec<RegQueryComponent>,
    /// True if `key_path` contains the root key name. Usually will be false, but useful if you are searching using a path from an existing key
    pub(crate) key_path_has_root: bool,
    /// Determines if subkeys are returned during iteration
    pub(crate) children: bool,
}

impl RegQuery {
    fn check_key_match(&self, key_path: &str, mut root_key_name_offset: usize) -> FilterFlags {
        if self.key_path_has_root {
            root_key_name_offset = 0;
        }
        let key_path_iterator = key_path[root_key_name_offset..].split('\\'); // key path can be shorter and match
        let mut filter_iterator = self.key_path.iter();
        let mut filter_path_segment = filter_iterator.next();

        for key_path_segment in key_path_iterator {
            match filter_path_segment {
                Some(fps) => match fps {
                    RegQueryComponent::ComponentString(s) => {
                        if s != &key_path_segment.to_ascii_lowercase() {
                            return FilterFlags::FILTER_NO_MATCH;
                        } else {
                            filter_path_segment = filter_iterator.next();
                        }
                    }
                    RegQueryComponent::ComponentRegex(r) => {
                        if r.is_match(&key_path_segment.to_ascii_lowercase()) {
                            filter_path_segment = filter_iterator.next();
                        } else {
                            return FilterFlags::FILTER_NO_MATCH;
                        }
                    }
                },
                None => return FilterFlags::FILTER_NO_MATCH,
            }
        }
        if filter_path_segment.is_none() {
            // we matched all the keys!
            FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_KEY_MATCH
        } else {
            FilterFlags::FILTER_ITERATE_KEYS
        }
    }
}

bitflags! {
    pub struct FilterFlags: u16 {
        const FILTER_NO_MATCH     = 0x0001;
        const FILTER_ITERATE_KEYS = 0x0002;
        const FILTER_KEY_MATCH    = 0x0004;
    }
}
impl_serialize_for_bitflags! {FilterFlags}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_key_node;

    #[test]
    fn test_check_cell_match_key() -> Result<(), Error> {
        let mut state = State::default();
        let filter = FilterBuilder::new()
            .add_key_path("HighContrast")
            .return_child_keys(true)
            .build()?;
        let mut key_node = cell_key_node::CellKeyNode {
            path: String::from("HighContrast"),
            ..Default::default()
        };
        assert_eq!(
            FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_KEY_MATCH,
            filter.check_cell(&mut state, &key_node),
            "check_cell: Same case key match failed"
        );

        key_node.path = String::from("Highcontrast");
        assert_eq!(
            FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_KEY_MATCH,
            filter.check_cell(&mut state, &key_node),
            "check_cell: Different case key match failed"
        );

        key_node.path = String::from("badVal");
        assert_eq!(
            FilterFlags::FILTER_NO_MATCH,
            filter.check_cell(&mut state, &key_node),
            "check_cell: No match key match failed"
        );
        Ok(())
    }
}
