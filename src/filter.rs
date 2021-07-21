use bitflags::bitflags;
use regex::Regex;
use crate::err::Error;
use crate::hive_bin_cell;
use crate::impl_serialize_for_bitflags;
use crate::state::State;

/// Filter allows specification of conditions to be met when reading the registry.
/// Execution will short-circuit for applicable filters (is_complete = true)
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub(crate) reg_query: Option<RegQuery>
}

impl Filter {
    pub fn new() -> Self {
        Filter {
            reg_query: None
        }
    }

    pub fn from_path(find_path: RegQuery) -> Self {
        Filter {
            reg_query: Some(find_path)
        }
    }

    pub fn is_valid(&self) -> bool {
        self.reg_query.is_some()
    }

    fn key_path_has_root(&self) -> bool {
        if let Some(reg_query) = &self.reg_query {
            reg_query.key_path_has_root
        }
        else {
            false
        }
    }

    pub(crate) fn check_cell(
        &self,
        state: &mut State,
        cell: &dyn hive_bin_cell::Cell
    ) -> Result<FilterFlags, Error> {
        if self.reg_query.is_some() {
            self.match_cell(state, cell)
        }
        else {
            Ok(FilterFlags::FILTER_ITERATE_KEYS)
        }
    }

    pub(crate) fn match_cell(
        &self,
        state: &mut State,
        cell: &dyn hive_bin_cell::Cell
    ) -> Result<FilterFlags, Error> {
        if cell.is_key_root() {
            if let Some(reg_query) = &self.reg_query {
                if !reg_query.key_path_has_root {
                    return Ok(FilterFlags::FILTER_ITERATE_KEYS);
                }
            }
        }
        match cell.lowercase() {
            Some(cell_lowercase) => {
                if cell.is_key() {
                    Ok(self.match_key(state, cell_lowercase))
                }
                else {
                    Ok(FilterFlags::FILTER_ITERATE_KEYS)
                }
            },
            None => Err(Error::Any{detail: String::from("Missing cell name")})
        }
    }

    fn match_key(
        &self,
        state: &mut State,
        key_path: String
    ) -> FilterFlags {
        if let Some(reg_query) = &self.reg_query {
            reg_query.check_key_match(
                &key_path,
                state.get_root_path_offset(&key_path)
            )
        }
        else {
            FilterFlags::FILTER_ITERATE_KEYS
        }
    }

    pub(crate) fn return_sub_keys(&self) -> bool {
        match &self.reg_query {
            Some(fp) => fp.children,
            _ => false
        }
    }
}

#[derive(Clone, Debug)]
pub enum RegQueryComponent {
    ComponentString(String),
    ComponentRegex(Regex),
}

/// ReqQuery is a structured filter which allows for regular expressions
#[derive(Clone, Debug, Default)]
pub struct RegQuery {
    pub(crate) key_path: Vec<RegQueryComponent>,
    /// True if `key_path` contains the root key name. Usually wil be false, but useful if you are searching using a path from an existing key.
    pub(crate) key_path_has_root: bool,
    /// Determines if subkeys are returned.
    pub(crate) children: bool
}

impl RegQuery {
    pub fn from_key(key_path: &str, key_path_has_root: bool, children: bool) -> RegQuery {
        let mut query_components = Vec::new();
        for segment in key_path.trim_end_matches('\\').to_ascii_lowercase().split('\\') {
            query_components.push(RegQueryComponent::ComponentString(segment.to_string()));
        }
        RegQuery {
            key_path: query_components,
            key_path_has_root,
            children
        }
    }

    fn check_key_match(
        &self,
        key_name: &str,
        mut root_key_name_offset: usize
    ) -> FilterFlags {
        if self.key_path_has_root {
            root_key_name_offset = 0;
        }
        let key_path_iterator = key_name[root_key_name_offset..].split('\\'); // key path can be shorter and match
        let mut filter_iterator = self.key_path.iter();
        let mut filter_path_segment = filter_iterator.next();

        for key_path_segment in key_path_iterator {
            match filter_path_segment {
                Some(fps) => {
                    match fps {
                        RegQueryComponent::ComponentString(s) => {
                            if s != &key_path_segment.to_ascii_lowercase() {
                                return FilterFlags::FILTER_NO_MATCH;
                            }
                            else {
                                filter_path_segment = filter_iterator.next();
                            }
                        },
                        RegQueryComponent::ComponentRegex(r) => {
                            if r.is_match(&key_path_segment.to_ascii_lowercase()) {
                                filter_path_segment = filter_iterator.next();
                            }
                            else {
                                return FilterFlags::FILTER_NO_MATCH;
                            }
                        }
                    }
                },
                None => return FilterFlags::FILTER_NO_MATCH
            }
        }
        if filter_path_segment.is_none() { // we matched all the keys!
            FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_KEY_MATCH
        }
        else {
            FilterFlags::FILTER_ITERATE_KEYS
        }
    }
}

bitflags! {
    pub struct FilterFlags: u16 {
        const FILTER_NO_MATCH                = 0x0001;
        const FILTER_ITERATE_KEYS            = 0x0002;
        const FILTER_ITERATE_KEYS_COMPLETE   = 0x0004;
        const FILTER_KEY_MATCH               = 0x0008;
    }
}
impl_serialize_for_bitflags! {FilterFlags}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_key_node;

    #[test]
    fn test_find_path_build() {
        //let find_path = RegQuery::from_key("First segment\\secondSEGMENT", false, true);
        //assert_eq!(find_path.key_path, String::from("first segment\\secondsegment"));
    }

    #[test]
    fn test_check_cell_match_key() {
        let mut state = State::default();
        let filter = Filter::from_path(RegQuery::from_key("HighContrast", false, true));
        let mut key_node = cell_key_node::CellKeyNode {
            path: String::from("HighContrast"),
            ..Default::default()
        };
        assert_eq!(FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_KEY_MATCH,
            filter.clone().check_cell(&mut state, &key_node).unwrap(),
            "check_cell: Same case key match failed");

        key_node.path = String::from("Highcontrast");
        assert_eq!(FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_KEY_MATCH,
            filter.clone().check_cell(&mut state, &key_node).unwrap(),
            "check_cell: Different case key match failed");

        key_node.path = String::from("badVal");
        assert_eq!(FilterFlags::FILTER_NO_MATCH,
            filter.clone().check_cell(&mut state, &key_node).unwrap(),
            "check_cell: No match key match failed");
    }
}