/*
 * Copyright 2021 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use blake3::Hash;
use clap::{App, Arg};
use notatin::{
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    err::Error,
    filter::{Filter, RegQuery},
    parser::Parser,
    util::format_date_time,
};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
};

fn main() -> Result<(), Error> {
    let matches = App::new("Notatin Registry Compare")
    .version("1.0")
    .arg(Arg::from_usage("-f --filter=[STRING] 'Key path to filter on (ex: \'ControlSet001\\Services\')'"))
    .arg(Arg::with_name("base")
        .short("b")
        .long("base")
        .value_name("FILES")
        .help("Base registry file with optional transaction file(s) (Comma separated list)")
        .required(true)
        .takes_value(true))
    .arg(Arg::with_name("comparison")
        .short("c")
        .long("comparison")
        .value_name("FILES")
        .help("Comparison registry file with optional transaction file(s) (Comma separated list)")
        .required(true)
        .takes_value(true))
    .arg(Arg::with_name("output")
        .short("o")
        .long("output")
        .value_name("FILE")
        .help("Output file")
        .required(true)
        .takes_value(true))
    .get_matches();

    let (base_primary, base_logs) = parse_paths(matches.value_of("base").expect("Required value"));
    let (comparison_primary, comparison_logs) =
        parse_paths(matches.value_of("comparison").expect("Required value"));

    let output = matches.value_of("output").expect("Required value");

    let filter;
    if let Some(f) = matches.value_of("filter") {
        filter = Some(Filter::from_path(RegQuery::from_key(f, false, true)));
    } else {
        filter = None;
    }

    let write_file = File::create(output)?;
    let mut writer = BufWriter::new(write_file);

    let mut original_map: HashMap<(String, Option<String>), Option<Hash>> = HashMap::new();

    // add all items from base into original_map
    let mut parser1 = Parser::from_path(base_primary, base_logs, filter.clone(), false)?;
    let (k_total, _) = parser1.count_all_keys_and_values();
    let mut k_added = 0;

    for key in parser1.iter() {
        let path = key.path.clone();
        original_map.insert((path.clone(), None), key.hash); // TODO: update this to support deleted/modified as well. Sequence numbers, deleted/modified - that should be enough to get us to the original item
        for value in key.value_iter() {
            original_map.insert((path.clone(), Some(value.get_pretty_name())), value.hash);
        }
        k_added += 1;
        if k_added % 1000 == 0 {
            println!("{}/{} keys parsed from base", k_added, k_total);
        }
    }
    println!("{}/{} keys parsed from base", k_added, k_total);

    let mut keys_added = Vec::new();
    let mut keys_modified = Vec::new();
    let mut keys_deleted = Vec::new();
    let mut values_added = Vec::new();
    let mut values_modified = Vec::new();
    let mut values_deleted = Vec::new();

    // For each item in comparison, see if it's in original_map
    //   If missing, it's new
    //   If present, compare the hash
    //     If same, it's a match (ignore it)
    //     If different, it's an update
    let mut parser2 = Parser::from_path(comparison_primary, comparison_logs, filter, false)?;
    let (k_total, _) = parser2.count_all_keys_and_values();
    let mut k_added = 0;
    for key in parser2.iter() {
        match original_map.remove(&(key.path.clone(), None)) {
            Some(val) => {
                if val != key.hash {
                    let original_key = parser1.get_key(&key.path, true);
                    keys_modified.push((original_key.unwrap().unwrap(), key.clone()));
                }
            }
            None => keys_added.push(key.clone()),
        }

        let path = key.path.clone();
        for value in key.value_iter() {
            match original_map.remove(&(path.clone(), Some(value.get_pretty_name()))) {
                Some(val) => {
                    if val != value.hash {
                        let original_key = parser1.get_key(&key.path, true).unwrap().unwrap();
                        let original_value = original_key.get_value(&value.value_name).unwrap();
                        values_modified.push((path.clone(), original_value, value));
                    }
                }
                None => values_added.push((path.clone(), value)),
            }
        }
        k_added += 1;
        if k_added % 100 == 0 {
            println!("{}/{} keys compared", k_added, k_total);
        }
    }
    println!("{}/{} keys compared", k_added, k_total);

    // Any items remaining in original_map were deleted (not present in file2)
    for remaining in original_map {
        match remaining.0 .1 {
            None => {
                let original_key = parser1.get_key(&remaining.0 .0, true).unwrap().unwrap();
                keys_deleted.push(original_key)
            }
            Some(val) => {
                let original_key = parser1.get_key(&remaining.0 .0, true).unwrap().unwrap();
                let original_value = original_key.get_value(&val).unwrap();
                values_deleted.push((original_key.path, original_value))
            }
        };
    }
    let total_changes = keys_deleted.len()
        + keys_added.len()
        + keys_modified.len()
        + values_deleted.len()
        + values_added.len()
        + values_modified.len();

    if !keys_deleted.is_empty() {
        writeln!(writer, "----------------------------------\nKeys deleted: {}\n----------------------------------", keys_deleted.len())?;
        for k in keys_deleted {
            write_key(&mut writer, &k);
        }
    }
    if !keys_added.is_empty() {
        writeln!(writer, "\n----------------------------------\nKeys added: {}\n----------------------------------", keys_added.len())?;
        for k in keys_added {
            write_key(&mut writer, &k);
        }
    }
    if !keys_modified.is_empty() {
        writeln!(writer, "\n----------------------------------\nKeys modified: {}\n----------------------------------", keys_modified.len())?;
        for k in keys_modified {
            write_key(&mut writer, &k.0);
            write_key(&mut writer, &k.1);
        }
    }
    if !values_deleted.is_empty() {
        writeln!(writer, "\n----------------------------------\nValues deleted: {}\n----------------------------------", values_deleted.len())?;
        for v in values_deleted {
            write_value(&mut writer, &v.0, &v.1);
        }
    }
    if !values_added.is_empty() {
        writeln!(writer, "\n----------------------------------\nValues added: {}\n----------------------------------", values_added.len())?;
        for v in values_added {
            write_value(&mut writer, &v.0, &v.1);
        }
    }
    if !values_modified.is_empty() {
        writeln!(writer, "\n----------------------------------\nValues modified: {}\n----------------------------------", values_modified.len())?;
        for v in values_modified {
            write_value(&mut writer, &v.0, &v.1);
            write_value(&mut writer, &v.0, &v.2);
        }
    }
    writeln!(writer, "\n----------------------------------\nTotal changes: {}\n----------------------------------", total_changes)?;

    Ok(())
}

fn parse_paths(paths: &str) -> (String, Option<Vec<String>>) {
    let mut logs = Vec::new();
    let mut primary = String::new();
    for component in paths.split(',') {
        let lower = component.trim().trim_matches('\'').to_ascii_lowercase();
        if lower.ends_with(".log1") || lower.ends_with(".log2") {
            logs.push(component.trim().trim_matches('\'').to_string());
        } else {
            primary = component.trim().trim_matches('\'').to_string();
        }
    }
    if logs.is_empty() {
        (primary, None)
    } else {
        (primary, Some(logs))
    }
}

fn write_value(writer: &mut BufWriter<File>, cell_key_node_path: &str, value: &CellKeyValue) {
    writeln!(
        writer,
        "{}\t{}\t{:?}",
        cell_key_node_path,
        value.get_pretty_name(),
        value.get_content().0
    )
    .unwrap();
}

fn write_key(writer: &mut BufWriter<File>, cell_key_node: &CellKeyNode) {
    writeln!(
        writer,
        "{}\t{}\t{:?}\t{:?}",
        cell_key_node.path,
        format_date_time(cell_key_node.last_key_written_date_and_time),
        cell_key_node.key_node_flags,
        cell_key_node.access_flags
    )
    .unwrap();
}
