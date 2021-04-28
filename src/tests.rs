#[cfg(test)]
mod tests {
    use crate::base_block;
    use crate::filter;
    use crate::cell_key_value;
    
    #[test]
    fn python_registry_test_issue22() {
        let f = std::fs::read("test_data/issue22.hive").unwrap();
        let res_registry = base_block::read_registry(&f[0..], &mut filter::Filter { ..Default::default() });
        let registry = res_registry.unwrap();
        let reg_val = registry.hive_bin_root.unwrap().root.sub_values.into_iter().find(|val| val.value_name == "TimeZoneKeyName");
        let expected_value_content = cell_key_value::CellValue::ValueString {
            content: "W. Europe Standard Time".to_string()
        };
        assert_eq!(expected_value_content, reg_val.unwrap().value_content);
    }
}