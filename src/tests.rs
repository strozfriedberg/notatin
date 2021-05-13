#[cfg(test)]
mod tests {
    use crate::registry::{State, Parser};
    use crate::filter::Filter;
    use crate::cell_value::CellValue;

    #[test]
    fn python_registry_test_issue22() {
        let mut parser = Parser::from_path("test_data/issue22.hive", Filter::new()).unwrap();
        let res = parser.init();
        assert_eq!(Ok(true), res);

        for key in parser {
            let mut reg_val = key.sub_values.into_iter().find(|val| val.value_name == "TimeZoneKeyName").unwrap();
            let expected_value_content = CellValue::ValueString("W. Europe Standard Time".to_string());
            let mut state = State::from_path("test_data/issue22.hive", 4096).unwrap();
            reg_val.read_content(&mut state);
            assert_eq!(expected_value_content, reg_val.value_content.unwrap());
            break;
        }
    }
}