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
use chrono::{DateTime, Utc};
use clap::{Arg, Command, arg};
use notatin::{
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    cli_util::parse_paths,
    err::Error,
    filter::FilterBuilder,
    log::Logs,
    parser::{Parser, ParserIterator},
    parser_builder::ParserBuilder,
    util::format_date_time,
};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    time::SystemTime
};

fn main() -> Result<(), Error> {
    let matches = Command::new("Notatin Registry Compare")
    .version("0.1")
    .arg(arg!(-f --filter [STRING] "Key path for filter (ex: 'ControlSet001\\Services')"))
    .arg(Arg::new("base")
        .short('b')
        .long("base")
        .value_name("FILES")
        .help("Base registry file with optional transaction file(s) (Comma separated list)")
        .required(true)
        .number_of_values(1))
    .arg(Arg::new("comparison")
        .short('c')
        .long("comparison")
        .value_name("FILES")
        .help("Comparison registry file with optional transaction file(s) (Comma separated list)")
        .required(true)
        .number_of_values(1))
    .arg(Arg::new("output")
        .short('o')
        .long("output")
        .value_name("FILE")
        .help("Output file")
        .required(true)
        .number_of_values(1))
    .arg(arg!(
            -d --diff "Export normal diff format output"
    ))
    .get_matches();

    let (base_primary, base_logs) = parse_paths(
        matches.get_one::<String>("base")
               .expect("Required value")
    );

    let (comparison_primary, comparison_logs) = parse_paths(
        matches.get_one::<String>("comparison")
               .expect("Required value")
    );

    let output: &str = matches.get_one::<String>("output")
                              .expect("Required value");

    let use_diff_format = matches.get_flag("diff");

    let write_file = File::create(output)?;
    let mut writer = BufWriter::new(write_file);

    let mut original_map: HashMap<(String, Option<String>), Option<Hash>> = HashMap::new();

    let filter = match matches.get_one::<String>("filter") {
        Some(f) => Some(
            FilterBuilder::new()
                .add_key_path(f)
                .return_child_keys(true)
                .build()?,
        ),
        None => None,
    };

    let mut parser1 = get_parser(base_primary, base_logs)?;
    let (k_total, _) = parser1.count_all_keys_and_values(filter.as_ref());
    let mut k_added = 0;

    let mut iter = ParserIterator::new(&parser1);
    if let Some(f) = &filter {
        iter.with_filter(f.clone());
    }
    for key in iter.iter() {
        let path = &key.path;
        original_map.insert((path.clone(), None), key.hash);
        for value in key.value_iter() {
            original_map.insert((path.clone(), Some(value.detail.value_name())), value.hash);
        }
        k_added += 1;
        if k_added % 1000 == 0 {
            update_parsed_keys(k_added, k_total);
        }
    }
    update_parsed_keys(k_added, k_total);

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

    let parser2 = get_parser(comparison_primary, comparison_logs)?;
    let (k_total, _) = parser2.count_all_keys_and_values(filter.as_ref());
    let mut k_added = 0;
    let mut iter = ParserIterator::new(&parser2);
    if let Some(f) = filter {
        iter.with_filter(f);
    }
    for key in iter.iter() {
        let path = &key.path;

        match original_map.remove(&(path.clone(), None)) {
            Some(val) => {
                if val != key.hash {
                    let original_key = parser1.get_key(path, true);
                    keys_modified.push((original_key.unwrap().unwrap(), key.clone()));
                }
            }
            None => keys_added.push(key.clone()),
        }

        for value in key.value_iter() {
            match original_map.remove(&(path.clone(), Some(value.detail.value_name().clone()))) {
                Some(val) => {
                    if val != value.hash {
                        let original_key = parser1.get_key(&key.path, true).unwrap().unwrap();
                        let original_value =
                            original_key.get_value(&value.detail.value_name()).unwrap();
                        values_modified.push((path.clone(), original_value, value));
                    }
                }
                None => values_added.push((path.clone(), value)),
            }
        }
        k_added += 1;
        if k_added % 100 == 0 {
            update_keys_compared(k_added, k_total);
        }
    }
    update_keys_compared(k_added, k_total);

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

    if use_diff_format {
        write_diff(
            &mut writer,
            keys_added, keys_deleted, keys_modified,
            values_added, values_deleted, values_modified
        )?;
    } else {
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
    }
    Ok(())
}

/*
fn write_diff(writer: &mut BufWriter<File>, Vec<String> left, lline: u64, Vec<String> right, rline: u64) -> Result<_> {
    writeln!(
        writer,
        "@@ -{},{} +{},{} @@",
        lline, left.len(),
        rline, right.len()
    )?;
    lline += left.len();
    rline += right.len();

    for l in left {
        write_key_prefix(&mut writer, &r, "- ");
    }
    for r in right {
        write_key_prefix(&mut writer, &r, "+ ");
    }
}
*/

fn write_diff(
    writer: &mut BufWriter<File>,
    keys_deleted: Vec<CellKeyNode>,
    keys_added: Vec<CellKeyNode>,
    keys_modified: Vec<(CellKeyNode, CellKeyNode)>,
    values_deleted: Vec<(String, CellKeyValue)>,
    values_added: Vec<(String, CellKeyValue)>,
    values_modified: Vec<(String, CellKeyValue, CellKeyValue)>
) -> Result<(), Error> {
    let now = DateTime::<Utc>::from(SystemTime::now()).to_rfc3339();

    writeln!(writer, "--- base {}", now)?;
    writeln!(writer, "+++ comp {}", now)?; 

    let mut lline = 1;
    let mut rline = 1;

    if !keys_deleted.is_empty() {
        writeln!(
            writer,
            "@@ -{},{} +{},{} @@",
            lline, keys_deleted.len(),
            rline, 0
        )?;
        lline += keys_deleted.len();
        for k in keys_deleted {
            write_key_prefix(writer, &k, "- ");
        }
    }

    if !keys_added.is_empty() {
        writeln!(
            writer,
            "@@ -{},{} +{},{} @@",
            lline, 0,
            rline, keys_added.len()
        )?;
        rline += keys_added.len();
        for k in keys_added {
            write_key_prefix(writer, &k, "+ ");
        }
    }

    if !keys_modified.is_empty() {
        writeln!(
            writer,
            "@@ -{},{} +{},{} @@",
            lline, keys_modified.len(),
            rline, keys_modified.len()
        )?;
        lline += keys_modified.len();
        rline += keys_modified.len();
        for k in &keys_modified {
            write_key_prefix(writer, &k.0, "- ");
        }
        for k in &keys_modified {
            write_key_prefix(writer, &k.1, "+ ");
        }
    }

    if !values_deleted.is_empty() {
        writeln!(
            writer,
            "@@ -{},{} +{},{} @@",
            lline, values_deleted.len(),
            rline, 0
        )?;
        lline += values_deleted.len();
        for v in values_deleted {
            write_value_prefix(writer, &v.0, &v.1, "- ");
        }
    }

    if !values_added.is_empty() {
        writeln!(
            writer,
            "@@ -{},{} +{},{} @@",
            lline, 0,
            rline, values_added.len()
        )?;
        rline += values_added.len();
        for v in values_added {
            write_value_prefix(writer, &v.0, &v.1, "+ ");
        }
    }

    if !values_modified.is_empty() {
        writeln!(
            writer,
            "@@ -{},{} +{},{} @@",
            lline, values_modified.len(),
            rline, values_modified.len()
        )?;
        lline += values_modified.len();
        rline += values_modified.len();
        for v in &values_modified {
            write_value_prefix(writer, &v.0, &v.1, "- ");
        }
        for v in &values_modified {
            write_value_prefix(writer, &v.0, &v.2, "+ ");
        }
    }
    Ok(())
}

fn get_parser(primary: String, logs: Option<Vec<String>>) -> Result<Parser, Error> {
    let mut parser_builder = ParserBuilder::from_path(primary);
    for log in logs.unwrap_or_default() {
        parser_builder.with_transaction_log(log);
    }
    parser_builder.build()
}

fn write_value(writer: &mut BufWriter<File>, cell_key_node_path: &str, value: &CellKeyValue) {
    write_value_prefix(writer, cell_key_node_path, value, "")
}

fn write_value_prefix(writer: &mut BufWriter<File>, cell_key_node_path: &str, value: &CellKeyValue, diff_prefix: &str) {
    writeln!(
        writer,
        "{}{}\t{}\t{:?}",
        diff_prefix,
        cell_key_node_path,
        value.get_pretty_name(),
        value.get_content().0
    )
    .unwrap();
}

fn write_key(writer: &mut BufWriter<File>, cell_key_node: &CellKeyNode) {
    write_key_prefix(writer, cell_key_node, "")
}

fn write_key_prefix(writer: &mut BufWriter<File>, cell_key_node: &CellKeyNode, diff_prefix: &str) {
    let mut logs = Logs::default();
    writeln!(
        writer,
        "{}{}\t{}\t{:?}\t{:?}",
        diff_prefix,
        cell_key_node.path,
        format_date_time(cell_key_node.last_key_written_date_and_time()),
        cell_key_node.key_node_flags(&mut logs),
        cell_key_node.access_flags(&mut logs)
    )
    .unwrap();
}

fn update_parsed_keys(k_added: usize, k_total: usize) {
    println!("{}/{} keys parsed from base", k_added, k_total);
}

fn update_keys_compared(k_added: usize, k_total: usize) {
    println!("{}/{} keys compared", k_added, k_total);
}
