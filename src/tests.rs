#[cfg(test)]
mod tests {
    use crate::registry::{State, Parser};
    use crate::filter::Filter;
    use crate::cell_value::CellValue;

    #[test]
    fn python_registry_test_issue22() {
        let f = std::fs::read("test_data/issue22.hive").unwrap();

        let mut filter = Filter::new();
        let mut parser = Parser::new(&f, &mut filter);
        let res = parser.init();
        assert_eq!(Ok(true), res);

        for key in parser {
            let mut reg_val = key.sub_values.into_iter().find(|val| val.value_name == "TimeZoneKeyName").unwrap();
            let expected_value_content = CellValue::ValueString("W. Europe Standard Time".to_string());
            let state = State::new(&f, 4096);
            reg_val.read_content(&state);
            assert_eq!(expected_value_content, reg_val.value_content.unwrap());
            break;
        }
    }
}