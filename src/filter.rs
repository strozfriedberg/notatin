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
    pub(crate) find_path: Option<FindPath>,
    pub(crate) reg_query: Option<RegQuery>
}

impl Filter {
    pub fn new() -> Self {
        Filter {
            find_path: None,
            reg_query: None
        }
    }

    pub fn from_path(find_path: FindPath) -> Self {
        Filter {
            find_path: Some(find_path),
            reg_query: None
        }
    }

    pub(crate) fn check_cell(
        &self,
        state: &mut State,
        cell: &dyn hive_bin_cell::Cell
    ) -> Result<FilterFlags, Error> {
        if !state.key_complete && (self.find_path.is_some() || self.reg_query.is_some()) {
            self.match_cell(state, cell)
        }
        else {
            Ok(FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES)
        }
    }

    pub(crate) fn match_cell(
        &self,
        state: &mut State,
        cell: &dyn hive_bin_cell::Cell
    ) -> Result<FilterFlags, Error> {
        if cell.is_key_root() {
            if let Some(find_path) = &self.find_path {
                if !find_path.key_path_has_root {
                    return Ok(FilterFlags::FILTER_ITERATE_KEYS);
                }
            }
            else if self.reg_query.is_some() {
                return Ok(FilterFlags::FILTER_ITERATE_KEYS);
            }
        }
        match cell.lowercase() {
            Some(cell_lowercase) => {
                if cell.is_key() {
                    Ok(self.match_key(state, cell_lowercase))
                }
                else {
                    Ok(self.match_value(cell_lowercase))
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
        let key_path_offset = state.get_root_path_offset(&key_path);
        if let Some(find_path) = &self.find_path {
            find_path.check_key_match(
                &key_path,
                key_path_offset
            )
        }
        else if let Some(reg_query) = &self.reg_query {
            reg_query.check_key_match(
                &key_path,
                key_path_offset
            )
        }
        else {
            FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES
        }
    }

    fn match_value(
        &self,
        value_name: String
    ) -> FilterFlags {
        if let Some(find_path) = &self.find_path {
            match &find_path.value {
                Some(match_val) => {
                    if match_val == &value_name {
                        FilterFlags::FILTER_VALUE_MATCH | FilterFlags::FILTER_ITERATE_VALUES_COMPLETE | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE
                    }
                    else {
                        FilterFlags::FILTER_NO_MATCH | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE
                    }
                },
                None => FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES
            }
        }
        else if let Some(reg_query) = &self.reg_query {
            match &reg_query.value {
                Some(match_val) => {
                    match &match_val {
                        RegQueryComponent::ComponentString(s) => {
                            if s == &value_name {
                                FilterFlags::FILTER_VALUE_MATCH | FilterFlags::FILTER_ITERATE_VALUES_COMPLETE | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE
                            }
                            else {
                                FilterFlags::FILTER_NO_MATCH | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE
                            }
                        },
                        RegQueryComponent::ComponentRegex(r) => {
                            if r.is_match(&value_name) {
                                FilterFlags::FILTER_VALUE_MATCH// | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE
                            }
                            else {
                                FilterFlags::FILTER_NO_MATCH// | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE
                            }
                        }
                    }
                },
                None => FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES
            }
        }
        else {
            FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES
        }
    }

    pub(crate) fn return_sub_keys(&self) -> bool {
        match &self.find_path {
            Some(fp) => fp.children,
            _ => false
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum RegQueryComponent {
    ComponentString(String),
    ComponentRegex(Regex),
}

/// ReqQuery is a structured filter which allows for regular expressions.
/// The value is optional; if only a key path is specified all values will be returned.
/// The `children` member determines if subkeys are returned.
#[derive(Clone, Debug, Default)]
pub(crate) struct RegQuery {
    pub key_path: Vec<RegQueryComponent>,
    pub value: Option<RegQueryComponent>,
    pub children: bool
}

impl RegQuery {
    fn check_key_match(
        &self,
        key_name: &str,
        root_key_name_offset: usize
    ) -> FilterFlags {
        let key_path_iterator = key_name[root_key_name_offset..].split('\\'); // key path can be shorter and match
        let mut filter_iterator = self.key_path.iter();
        let mut filter_path_segment = filter_iterator.next();
        let mut has_regex = false;

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
                            has_regex = true;
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
            if self.value.is_none() { // we only have a key path; should return all children / values then stop
                let mut ret = FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES;
                if !has_regex {
                    ret |= FilterFlags::FILTER_ITERATE_KEYS_COMPLETE;
                }
                ret
            }
            else {
                let mut ret = FilterFlags::FILTER_ITERATE_VALUES;
                if !has_regex {
                    ret |= FilterFlags::FILTER_ITERATE_KEYS_COMPLETE;
                }
                ret
            }
        }
        else {
            FilterFlags::FILTER_ITERATE_KEYS
        }
    }
}


/// FindPath is used when looking for a particular key path and/or value name.
/// The value name is optional; if only a key path is specified all values will be returned.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FindPath {
    key_path: String,
    value: Option<String>,
    /// True if `key_path` contains the root key name. Usually wil be false, but useful if you are searching using a path from an existing key.
    key_path_has_root: bool,
    /// Determines if subkeys are returned.
    children: bool
}

impl FindPath {
    pub fn from_key(key_path: &str, key_path_has_root: bool, children: bool) -> FindPath {
        FindPath::from_key_value_internal(key_path, None, key_path_has_root, children)
    }

    pub fn from_key_value(key_path: &str, value: &str, key_path_has_root: bool) -> FindPath {
        FindPath::from_key_value_internal(key_path, Some(value.to_string()), key_path_has_root, false)
    }

    fn from_key_value_internal(key_path: &str, value: Option<String>, key_path_has_root: bool, children: bool)-> FindPath {
        FindPath {
            key_path: key_path.trim_end_matches('\\').to_ascii_lowercase(),
            value: value.map(|v| v.to_ascii_lowercase()),
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
        let mut filter_iterator = self.key_path.split('\\');
        let mut filter_path_segment = filter_iterator.next();
        for key_path_segment in key_path_iterator {
            match filter_path_segment {
                Some(fps) => {
                    if fps != key_path_segment.to_ascii_lowercase() {
                        return FilterFlags::FILTER_NO_MATCH;
                    }
                    else {
                        filter_path_segment = filter_iterator.next();
                    }
                },
                None => return FilterFlags::FILTER_NO_MATCH
            }
        }
        if filter_path_segment.is_none() { // we matched all the keys!
            if self.value.is_none() { // we only have a key path; should return all children / values then stop
                FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE
            }
            else {
                FilterFlags::FILTER_ITERATE_VALUES | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE
            }
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
        const FILTER_ITERATE_VALUES          = 0x0004;
        const FILTER_ITERATE_KEYS_COMPLETE   = 0x0008;
        const FILTER_VALUE_MATCH             = 0x0010;
        const FILTER_ITERATE_VALUES_COMPLETE = 0x0020;
    }
}
impl_serialize_for_bitflags! {FilterFlags}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Logs;
    use crate::cell_key_node;
    use crate::cell_key_value;

    #[test]
    fn test_find_path_build() {
        let find_path = FindPath::from_key_value("First segment\\secondSEGMENT", "valueName", false);
        assert_eq!(find_path.key_path, String::from("first segment\\secondsegment"));
        assert_eq!(find_path.value, Some(String::from("valuename")));
    }

    #[test]
    fn test_check_cell_match_key() {
        let mut state = State::default();
        let filter = Filter::from_path(FindPath::from_key_value("HighContrast", "Flags", false));
        let mut key_node = cell_key_node::CellKeyNode {
            path: String::from("HighContrast"),
            ..Default::default()
        };
        assert_eq!(FilterFlags::FILTER_ITERATE_VALUES | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE,
            filter.clone().check_cell(&mut state, &key_node).unwrap(),
            "check_cell: Same case key match failed");

        key_node.path = String::from("Highcontrast");
        assert_eq!(FilterFlags::FILTER_ITERATE_VALUES | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE,
            filter.clone().check_cell(&mut state, &key_node).unwrap(),
            "check_cell: Different case key match failed");

        key_node.path = String::from("badVal");
        assert_eq!(FilterFlags::FILTER_NO_MATCH,
            filter.clone().check_cell(&mut state, &key_node).unwrap(),
            "check_cell: No match key match failed");
    }

    #[test]
    fn test_check_cell_match_value() {
        let mut state = State::default();
        let filter = Filter::from_path(FindPath::from_key_value("", "Flags", false));
        let mut key_value = cell_key_value::CellKeyValue {
            detail: cell_key_value::CellKeyValueDetail {
                file_offset_absolute: 0,
                size: 48,
                value_name_size: 18,
                data_size_raw: 8,
                data_offset_relative: 1928,
                data_type_raw: 0,
                flags_raw: 0,
                padding: 1280,
                value_bytes: None,
                slack: vec![]
            },
            flags: cell_key_value::CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            data_type: cell_key_value::CellKeyValueDataTypes::REG_SZ,
            value_name: String::from("Flags"),
            data_offsets_absolute: Vec::new(),
            logs: Logs::default(),
            versions: Vec::new(),
            hash: None,
            sequence_num: None,
            updated_by_sequence_num: None
        };
        assert_eq!(FilterFlags::FILTER_ITERATE_KEYS_COMPLETE | FilterFlags::FILTER_VALUE_MATCH | FilterFlags::FILTER_ITERATE_VALUES_COMPLETE,
            filter.clone().check_cell(&mut state, &key_value).unwrap(),
            "check_cell: Same case value match failed");

        key_value.value_name = String::from("flags");
        assert_eq!(FilterFlags::FILTER_ITERATE_KEYS_COMPLETE | FilterFlags::FILTER_VALUE_MATCH | FilterFlags::FILTER_ITERATE_VALUES_COMPLETE,
            filter.clone().check_cell(&mut state, &key_value).unwrap(),
            "check_cell: Different case value match failed");

        key_value.value_name = String::from("NoMatch");
        assert_eq!(FilterFlags::FILTER_NO_MATCH | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE,
            filter.clone().check_cell(&mut state, &key_value).unwrap(),
            "check_cell: No match value match failed");
    }
}