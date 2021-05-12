#[cfg(test)]
mod tests {
    use crate::registry::{State, Parser};
    use crate::filter::Filter;
    use crate::cell_value::CellValue;

    #[test]
    fn python_registry_test_issue22() {
        let mut filter = Filter::new();
        let mut parser = Parser::new("test_data/issue22.hive", &mut filter);
        let res = parser.init();
        assert_eq!(Ok(true), res);

        for key in parser {
            let mut reg_val = key.sub_values.into_iter().find(|val| val.value_name == "TimeZoneKeyName").unwrap();
            let expected_value_content = CellValue::ValueString("W. Europe Standard Time".to_string());
            let mut state = State::new("test_data/issue22.hive", 4096);
            reg_val.read_content(&mut state);
            assert_eq!(expected_value_content, reg_val.value_content.unwrap());
            break;
        }
    }
}