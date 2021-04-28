#[cfg(test)]
mod tests {
    use crate::base_block;
    use crate::filter::Filter;
    use crate::cell_key_value;

    #[test]
    fn python_registry_test_issue22() {
        let f = std::fs::read("test_data/issue22.hive").unwrap();
        let res_registry = base_block::Registry::from_bytes(&f[0..], &mut Filter { ..Default::default() });
        let registry = res_registry.unwrap();
        let reg_val = registry.hive_bin_root.unwrap().root.sub_values.into_iter().find(|val| val.value_name == "TimeZoneKeyName");
        let expected_value_content = cell_key_value::CellValue::ValueString {
            content: "W. Europe Standard Time".to_string()
        };
        let mut reg_val = reg_val.unwrap();
        reg_val.read_content(&f[0..], 4096);
        assert_eq!(expected_value_content, reg_val.value_content.unwrap());
    }
}