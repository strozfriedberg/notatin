use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
};
use blake3::Hash;
use notatin::{
    parser::Parser,
    err::Error,
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    filter::{Filter, FindPath},
    util::format_date_time
};

fn main() -> Result<(), Error> {
    let file1 = "/home/kstone/code/rust_parser_2/test_data/SYSTEM";
    let file2 = "/home/kstone/code/rust_parser_2/SYSTEM_transaction_logs_applied";
    let filter = None;//Some(Filter::from_path(FindPath::from_key(r"ControlSet001\Services", false, true)));

    fn write_value(writer: &mut BufWriter<File>, cell_key_node: &CellKeyNode, value: &CellKeyValue, prefix: &str) {
        writeln!(writer, "{}\t{} {}\t{:?}\t{}\t{:?}", prefix, cell_key_node.path, value.get_pretty_name(), value.data_type, value.hash.unwrap().to_hex(), value.get_content().0);
    }

    fn write_key(writer: &mut BufWriter<File>, cell_key_node: &CellKeyNode, prefix: &str) {
        writeln!(writer, "{}\t{}\t{}\t{:?}\t{:?}\t{}", prefix, cell_key_node.path, format_date_time(cell_key_node.last_key_written_date_and_time), cell_key_node.key_node_flags, cell_key_node.access_flags, cell_key_node.hash.unwrap().to_hex());
    }

    let write_file = File::create("compare_two_files_softwareKim.txt").unwrap();
    let mut writer = BufWriter::new(write_file);

    let mut original_map: HashMap<(String, Option<String>), Option<Hash>> = HashMap::new();

    // add all items from file1 into original_map
    let mut parser1 = Parser::from_path(file1, None, filter.clone(), false).unwrap();
    for key in parser1.iter() {
        original_map.insert((key.path.clone(), None), key.hash);
        for value in &key.sub_values {
            original_map.insert((key.path.clone(), Some(value.get_pretty_name())), value.hash);
        }
    }

    // For each item in file2, see if it's in original_map
    //   If missing, it's new
    //   If present, compare the hash
    //     If same, it's a match (ignore it)
    //     If different, it's an update
    let mut parser2 = Parser::from_path(file2, None, filter, false).unwrap();
    for key in parser2.iter() {
        match original_map.remove(&(key.path.clone(), None)) {
            Some(val) => {
                if val != key.hash {
                    write_key(&mut writer, &key, "UpdatedKey:");

                    let original_key = parser1.get_key(&key.path, true);
                    write_key(&mut writer, &original_key.unwrap().unwrap(), "\tOriginalKey:");
                }
            },
            None => write_key(&mut writer, &key, "NewKey:")
        }
        for value in &key.sub_values {
            match original_map.remove(&(key.path.clone(), Some(value.get_pretty_name()))) {
                Some(val) => {
                    if val != value.hash {
                        write_value(&mut writer, &key, &value, "UpdatedValue:");

                        let original_key = parser1.get_key(&key.path, true).unwrap().unwrap();
                        let original_value = original_key.get_value(&value.value_name).unwrap();
                        write_value(&mut writer, &original_key,  &original_value, "\tOriginalValue:");
                    }
                },
                None => write_value(&mut writer, &key, &value, "NewValue:")
            }
        }
    }

    // Any items remaining in original_map were deleted (not present in file2)
    for remaining in original_map {
        match remaining.0.1 {
            None => {
                let original_key = parser1.get_key(&remaining.0.0, true).unwrap().unwrap();
                write_key(&mut writer, &original_key, "DeletedKey:");
            }
            Some(val) => {
                let original_key = parser1.get_key(&remaining.0.0, true).unwrap().unwrap();
                let original_value = original_key.get_value(&val).unwrap();
                write_value(&mut writer, &original_key, &original_value, "DeletedValue:");
            }
        };
    }

    Ok(())
}