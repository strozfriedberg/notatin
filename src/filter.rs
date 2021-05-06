use bitflags::bitflags;
use std::path::{Path, PathBuf};
use crate::err::Error;
use crate::hive_bin_cell;
use crate::impl_serialize_for_bitflags;

/// Filter allows specification of conditions to be met when reading the registry.
/// Execution will short-circuit for applicable filters (is_complete = true)
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Filter {
    find_path: Option<FindPath>,
    is_complete: bool
}

impl Filter {
    pub fn new() -> Self {
        Filter {
            find_path: None,
            is_complete: false
        }
    }

    pub fn from_path(find_path: FindPath) -> Self {
        Filter {
            find_path: Some(find_path),
            is_complete: false
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.is_complete
    }

    pub(crate) fn set_complete(&mut self, is_complete: bool) {
        self.is_complete = is_complete;
    }

    pub(crate) fn check_cell(
        self: &mut Filter,
        is_first_iteration: bool,
        cell: &dyn hive_bin_cell::Cell
    ) -> Result<FilterFlags, Error> {
        if self.find_path.is_some() {
            self.handle_find_path(is_first_iteration, cell)
        }
        else {
            Ok(FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES)
        }
    }

    pub(crate) fn handle_find_path(
        self: &mut Filter,
        is_first_iteration: bool,
        cell: &dyn hive_bin_cell::Cell
    ) -> Result<FilterFlags, Error> {
        match cell.name_lowercase() {
            Some(cell_name_lowercase) => {
                let find_path = &self.find_path.as_ref().expect("We don't end up in this function unless find_path.is_some()");
                if !find_path.key_path.as_os_str().is_empty() {
                    self.match_key(is_first_iteration, cell_name_lowercase)
                }
                else {
                    match &find_path.value {
                        Some(match_val) => {
                            if match_val == &cell_name_lowercase {
                                Ok(FilterFlags::FILTER_ITERATE_KEYS_COMPLETE)
                            }
                            else {
                                Ok(FilterFlags::FILTER_NO_MATCH | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE)
                            }
                        },
                        None =>  Ok(FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES)
                    }
                }
            },
            None => Err(Error::Any{detail: String::from("Missing cell name")})
        }
    }

    fn match_key(self: &mut Filter, is_first_iteration: bool, key_name: String) -> Result<FilterFlags, Error> {
        if is_first_iteration { // skip the first iteration; it's the root hive name and therefore always matches
            Ok(FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES)
        }
        else {
            self.find_path.as_mut().expect("self.find_path was checked previously").check_key_match(&key_name)
        }
    }
}

/// FindPath is used when looking for a particular key path and/or value name.
/// The value name is optional; if only a key path is specified all subkeys and values will be returned.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FindPath {
    key_path: PathBuf,
    value: Option<String>
}

impl FindPath {
    pub fn from_key(key_path: &str) -> FindPath {
        FindPath::from_key_value_internal(key_path, None)
    }

    pub fn from_key_value(key_path: &str, value: &str) -> FindPath {
        FindPath::from_key_value_internal(key_path, Some(value.to_string()))
    }

    fn from_key_value_internal(key_path: &str, value: Option<String>) -> FindPath {
        FindPath {
            key_path: PathBuf::from(key_path.to_ascii_lowercase()),
            value: value.map(|v| v.to_ascii_lowercase())
        }
    }

    fn check_key_match(self: &mut FindPath, key_name: &str) -> Result<FilterFlags, Error> {
        if self.key_path.starts_with(Path::new(&key_name)) {
            self.key_path = self.key_path.strip_prefix(key_name)?.to_path_buf();
            if self.key_path.as_os_str().is_empty() { // we matched all the keys!
                if self.value.is_none() { // we only have a key path; should return all children / values then stop
                    Ok(FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE)
                }
                else {
                    Ok(FilterFlags::FILTER_ITERATE_VALUES | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE)
                }
            }
            else {
                Ok(FilterFlags::FILTER_ITERATE_KEYS)
            }
        }
        else {
            Ok(FilterFlags::FILTER_NO_MATCH)
        }
    }
}

bitflags! {
    pub struct FilterFlags: u16 {
        const FILTER_NO_MATCH              = 0x0001;
        const FILTER_ITERATE_KEYS          = 0x0002;
        const FILTER_ITERATE_VALUES        = 0x0004;
        const FILTER_ITERATE_KEYS_COMPLETE = 0x0008;
    }
}
impl_serialize_for_bitflags! {FilterFlags}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warn::Warnings;
    use crate::cell_key_node;
    use crate::cell_key_value;

    #[test]
    fn test_find_path_build() {
        let find_path = FindPath::from_key_value("First segment/secondSEGMENT", "valueName");
        assert_eq!(find_path.key_path, PathBuf::from("first segment/secondsegment"));
        assert_eq!(find_path.value, Some(String::from("valuename")));
    }

    #[test]
    fn test_check_cell_first_iteration() {
        let mut filter = Filter {
            find_path: Some(FindPath {
                key_path: PathBuf::from("HighContrast"),
                value: Some(String::from("Flags"))
            }),
            is_complete: false
        };

        let key_node = cell_key_node::CellKeyNode {
            key_name: String::from("Accessibility"),
             ..Default::default()
        };

        assert_eq!(FilterFlags::FILTER_ITERATE_KEYS | FilterFlags::FILTER_ITERATE_VALUES,
            filter.check_cell(true, &key_node).unwrap(),
            "check_cell: first_iteration success check failed");
        assert_eq!(FilterFlags::FILTER_NO_MATCH,
            filter.check_cell(false, &key_node).unwrap(),
            "check_cell: first_iteration failure check failed");
    }

    #[test]
    fn test_check_cell_match_key() {
        let filter = Filter {
            find_path: Some(FindPath::from_key_value("HighContrast", "Flags")),
            is_complete: false
        };
        let mut key_node = cell_key_node::CellKeyNode {
            key_name: String::from("HighContrast"),
            ..Default::default()
        };
        assert_eq!(FilterFlags::FILTER_ITERATE_VALUES | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE,
            filter.clone().check_cell(false, &key_node).unwrap(),
            "check_cell: Same case key match failed");

        key_node.key_name = String::from("Highcontrast");
        assert_eq!(FilterFlags::FILTER_ITERATE_VALUES | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE,
            filter.clone().check_cell(false, &key_node).unwrap(),
            "check_cell: Different case key match failed");

        key_node.key_name = String::from("badVal");
        assert_eq!(FilterFlags::FILTER_NO_MATCH,
            filter.clone().check_cell(false, &key_node).unwrap(),
            "check_cell: No match key match failed");
    }

    #[test]
    fn test_check_cell_match_value() {
        let filter = Filter::from_path(FindPath::from_key_value("", "Flags"));

        let mut key_value = cell_key_value::CellKeyValue {
            detail: cell_key_value::CellKeyValueDetail {
                file_offset_absolute: 0,
                size: 48,
                value_name_size: 18,
                data_size: 8,
                data_offset: 1928,
                padding: 1280,
            },
            flags: cell_key_value::CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
            data_type: cell_key_value::CellKeyValueDataTypes::REG_SZ,
            value_name: String::from("Flags"),
            value_content: None,
            parse_warnings: Warnings::default()
        };
        assert_eq!(FilterFlags::FILTER_ITERATE_KEYS_COMPLETE,
            filter.clone().check_cell(false, &key_value).unwrap(),
            "check_cell: Same case value match failed");

        key_value.value_name = String::from("flags");
        assert_eq!(FilterFlags::FILTER_ITERATE_KEYS_COMPLETE,
            filter.clone().check_cell(false, &key_value).unwrap(),
            "check_cell: Different case value match failed");

        key_value.value_name = String::from("NoMatch");
        assert_eq!(FilterFlags::FILTER_NO_MATCH | FilterFlags::FILTER_ITERATE_KEYS_COMPLETE,
            filter.clone().check_cell(false, &key_value).unwrap(),
            "check_cell: No match value match failed");
    }
}