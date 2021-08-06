use std::{
    fs::File,
    io::{BufWriter, Write},
};
use notatin::{
    parser::Parser,
    err::Error,
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    util::format_date_time
};

fn write_value(value: &CellKeyValue, writer: &mut BufWriter<File>, tabs: &str) -> Result<(), Error> {
    writeln!(writer,"\t{}\t{}\t{:?}\t{}\t({:?}\\{:?})\t{}\t{:?}", tabs, value.value_name, value.data_type, value.detail.file_offset_absolute, value.sequence_num, value.updated_by_sequence_num, value.hash.unwrap().to_hex(), value.get_content().0)?;
    Ok(())
}

fn versions(cell_key_node: &CellKeyNode, writer: &mut BufWriter<File>, prefix: &str, tabs: &str, force: bool) -> Result<(), Error> {
    if force || !cell_key_node.versions.is_empty() || !cell_key_node.deleted_keys.is_empty() || !cell_key_node.deleted_values.is_empty() || cell_key_node.sub_values.iter().any(|v| !v.versions.is_empty()) {
        writeln!(writer,"{}{}({:?}\\{:?})\t{}\t{}\t{:?}\t{:?}\t{}\t{}", tabs, prefix, cell_key_node.sequence_num, cell_key_node.updated_by_sequence_num, cell_key_node.path, format_date_time(cell_key_node.last_key_written_date_and_time), cell_key_node.key_node_flags, cell_key_node.access_flags, cell_key_node.detail.file_offset_absolute, cell_key_node.hash.unwrap().to_hex())?;

        for sub_key in &cell_key_node.versions {
            versions(sub_key, writer, &format!("{}Updated Key:\t", tabs), &("\t".to_string() + &tabs.to_string()), true)?;
        }
        for sub_key in &cell_key_node.deleted_keys {
            versions(sub_key, writer, &format!("{}Deleted Key:\t", tabs), &("\t".to_string() + &tabs.to_string()), true)?;
        }
        for sub_value in &cell_key_node.deleted_values {
            write_value(sub_value, writer, &format!("{}\tDeleted Version:", tabs))?;
        }
        for value in &cell_key_node.sub_values {
            if !value.versions.is_empty() {
                write_value(value, writer, &format!("{}Value:", tabs))?;

                for sub_value in &value.versions {
                    write_value(sub_value, writer, &format!("{}\tValue Version:", tabs))?;
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    let mut parser = Parser::from_path(
        "/mnt/d/evidence/RegFiles/aws/v5/system",
        Some(vec!["/mnt/d/evidence/RegFiles/aws/v5/system.log1","/mnt/d/evidence/RegFiles/aws/v5/system.log2"]),
        None,
        true
    ).unwrap();

    /*let mut parser = Parser::from_path(
        "/home/kstone/code/rust_parser_2/test_data/systemKim",
        Some(vec!["/home/kstone/code/rust_parser_2/test_data/SystemKim.LOG1", "/home/kstone/code/rust_parser_2/test_data/SystemKim.LOG2"]),
        None,
        false
    ).unwrap();*/

    /*let mut parser = Parser::from_path(
        "/home/kstone/code/rust_parser_2/test_data/SoftwareKim",
        Some(vec!["/home/kstone/code/rust_parser_2/test_data/SoftwareKim.LOG1", "/home/kstone/code/rust_parser_2/test_data/SoftwareKim.LOG2"]),
        Some(Filter::from_path(RegQuery::from_key("WOW6432Node\\TortoiseOverlays\\", false, true))),
        true
    ).unwrap();*/

    let (k, v) = parser.count_all_keys_and_values();
    println!("{}, {}", k, v);

    let write_file = File::create("system_v5.txt").unwrap();
    let mut writer = BufWriter::new(write_file);

    for key in parser.iter_include_ancestors() {
        versions(&key, &mut writer, &"", &"", false)?;
    }
    writeln!(writer, "\nLogs\n-----------")?;
    parser.get_parse_logs().write(&mut writer)?;

    Ok(())
}