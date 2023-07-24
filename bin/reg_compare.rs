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
    iter,
    str,
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

    (if use_diff_format { write_diff } else { write_report })(
        &mut writer,
        keys_added, keys_deleted, keys_modified,
        values_added, values_deleted, values_modified
    )?;

    Ok(())
}

fn write_report<W: Write>(
    writer: &mut W,
    keys_deleted: Vec<CellKeyNode>,
    keys_added: Vec<CellKeyNode>,
    keys_modified: Vec<(CellKeyNode, CellKeyNode)>,
    values_deleted: Vec<(String, CellKeyValue)>,
    values_added: Vec<(String, CellKeyValue)>,
    values_modified: Vec<(String, CellKeyValue, CellKeyValue)>
) -> Result<(), Error> {
    let total_changes = keys_deleted.len()
        + keys_added.len()
        + keys_modified.len()
        + values_deleted.len()
        + values_added.len()
        + values_modified.len();

    if !keys_deleted.is_empty() {
        writeln!(writer, "----------------------------------\nKeys deleted: {}\n----------------------------------", keys_deleted.len())?;
        for k in keys_deleted {
            write_key(writer, &k, "");
        }
    }
    if !keys_added.is_empty() {
        writeln!(writer, "\n----------------------------------\nKeys added: {}\n----------------------------------", keys_added.len())?;
        for k in keys_added {
            write_key(writer, &k, "");
        }
    }
    if !keys_modified.is_empty() {
        writeln!(writer, "\n----------------------------------\nKeys modified: {}\n----------------------------------", keys_modified.len())?;
        for k in keys_modified {
            write_key(writer, &k.0, "");
            write_key(writer, &k.1, "");
        }
    }
    if !values_deleted.is_empty() {
        writeln!(writer, "\n----------------------------------\nValues deleted: {}\n----------------------------------", values_deleted.len())?;
        for v in values_deleted {
            write_value(writer, &v.0, &v.1, "");
        }
    }
    if !values_added.is_empty() {
        writeln!(writer, "\n----------------------------------\nValues added: {}\n----------------------------------", values_added.len())?;
        for v in values_added {
            write_value(writer, &v.0, &v.1, "");
        }
    }
    if !values_modified.is_empty() {
        writeln!(writer, "\n----------------------------------\nValues modified: {}\n----------------------------------", values_modified.len())?;
        for v in values_modified {
            write_value(writer, &v.0, &v.1, "");
            write_value(writer, &v.0, &v.2, "");
        }
    }
    writeln!(writer, "\n----------------------------------\nTotal changes: {}\n----------------------------------", total_changes)?;
    Ok(())
}

fn write_diff_section<W: Write>(
    writer: &mut W,
    mut lline: usize,
    left: impl Iterator<Item = String>,
    llen: usize,
    mut rline: usize,
    right: impl Iterator<Item = String>,
    rlen: usize
) -> Result<(usize, usize), Error>
{
    if llen > 0 || rlen > 0 {
        writeln!(
            writer,
            "@@ -{},{} +{},{} @@",
            lline, llen,
            rline, rlen
        )?;

        lline += llen;
        rline += rlen;

        for l in left {
            writeln!(writer, "-{}", l)?;
        }

        for r in right {
            writeln!(writer, "+{}", r)?;
        }
    }

    Ok((lline, rline))
}

fn write_diff_k_del<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    keys_deleted: Vec<CellKeyNode>
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        keys_deleted.iter().map(|k| format_key(&k)),
        keys_deleted.len(),
        rline,
        iter::empty::<String>(),
        0
    )
}

fn write_diff_k_add<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    keys_added: Vec<CellKeyNode>
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        iter::empty::<String>(),
        0,
        rline,
        keys_added.iter().map(|k| format_key(&k)),
        keys_added.len()
    )
}

fn write_diff_k_mod<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    keys_modified: Vec<(CellKeyNode, CellKeyNode)>
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        keys_modified.iter().map(|k| format_key(&k.0)),
        keys_modified.len(),
        rline,
        keys_modified.iter().map(|k| format_key(&k.1)),
        keys_modified.len()
    )
}

fn write_diff_v_del<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    values_deleted: Vec<(String, CellKeyValue)>
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        values_deleted.iter().map(|v| format_value(&v.0, &v.1)),
        values_deleted.len(),
        rline,
        iter::empty::<String>(),
        0
    )
}

fn write_diff_v_add<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    values_added: Vec<(String, CellKeyValue)>
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        iter::empty::<String>(),
        0,
        rline,
        values_added.iter().map(|v| format_value(&v.0, &v.1)),
        values_added.len()
    )
}

fn write_diff_v_mod<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    values_modified: Vec<(String, CellKeyValue, CellKeyValue)>
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        values_modified.iter().map(|v| format_value(&v.0, &v.1)),
        values_modified.len(),
        rline,
        values_modified.iter().map(|v| format_value(&v.0, &v.2)),
        values_modified.len()
    )
}

fn write_diff<W: Write>(
    w: &mut W,
    keys_deleted: Vec<CellKeyNode>,
    keys_added: Vec<CellKeyNode>,
    keys_modified: Vec<(CellKeyNode, CellKeyNode)>,
    values_deleted: Vec<(String, CellKeyValue)>,
    values_added: Vec<(String, CellKeyValue)>,
    values_modified: Vec<(String, CellKeyValue, CellKeyValue)>
) -> Result<(), Error> {
    let now = DateTime::<Utc>::from(SystemTime::now()).to_rfc3339();

    writeln!(w, "--- base {}", now)?;
    writeln!(w, "+++ comp {}", now)?;

    let mut lline = 1;
    let mut rline = 1;

    (lline, rline) = write_diff_k_del(w, lline, rline, keys_deleted)?;
    (lline, rline) = write_diff_k_add(w, lline, rline, keys_added)?;
    (lline, rline) = write_diff_k_mod(w, lline, rline, keys_modified)?;
    (lline, rline) = write_diff_v_del(w, lline, rline, values_deleted)?;
    (lline, rline) = write_diff_v_add(w, lline, rline, values_added)?;
    (lline, rline) = write_diff_v_mod(w, lline, rline, values_modified)?;

    Ok(())
}

fn format_value(cell_key_node_path: &str, value: &CellKeyValue) -> String {
    format!(
        "{}\t{}\t{:?}",
        cell_key_node_path,
        value.get_pretty_name(),
        value.get_content().0
    )
}

fn format_key(cell_key_node: &CellKeyNode) -> String {
    let mut logs = Logs::default();
    format!(
        "{}\t{}\t{:?}\t{:?}",
        cell_key_node.path,
        format_date_time(cell_key_node.last_key_written_date_and_time()),
        cell_key_node.key_node_flags(&mut logs),
        cell_key_node.access_flags(&mut logs)
    )
}

fn write_value<W: Write>(writer: &mut W, cell_key_node_path: &str, value: &CellKeyValue, diff_prefix: &str) {
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

fn write_key<W: Write>(writer: &mut W, cell_key_node: &CellKeyNode, diff_prefix: &str) {
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

fn get_parser(primary: String, logs: Option<Vec<String>>) -> Result<Parser, Error> {
    let mut parser_builder = ParserBuilder::from_path(primary);
    for log in logs.unwrap_or_default() {
        parser_builder.with_transaction_log(log);
    }
    parser_builder.build()
}

fn update_parsed_keys(k_added: usize, k_total: usize) {
    println!("{}/{} keys parsed from base", k_added, k_total);
}

fn update_keys_compared(k_added: usize, k_total: usize) {
    println!("{}/{} keys compared", k_added, k_total);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_one() {
        let mut buf = Vec::<u8>::new();
        let right = ["abc"];

        assert_eq!(
            write_diff_section(
                &mut buf,
                0,
                iter::empty::<String>(),
                0,
                0,
                right.iter().map(|s| s.to_string()),
                right.len()
            ),
            Ok((0, 1))
        );

        assert_eq!(
            str::from_utf8(&buf).unwrap(),
            "@@ -0,0 +0,1 @@\n+abc\n"
        );
    }
    
    #[test]
    fn test_add_two() {
        let mut buf = Vec::<u8>::new();
        let right = ["abc", "xyz"];

        assert_eq!(
            write_diff_section(
                &mut buf,
                5,
                iter::empty::<String>(),
                0,
                18,
                right.iter().map(|s| s.to_string()),
                right.len() 
            ),
            Ok((5, 20))
        );

        assert_eq!(
            str::from_utf8(&buf),
            Ok("@@ -5,0 +18,2 @@\n+abc\n+xyz\n")
        );
    }

    #[test]
    fn test_del_one() {
        let mut buf = Vec::<u8>::new();
        let left = ["abc"];

        assert_eq!(
            write_diff_section(
                &mut buf,
                0,
                left.iter().map(|s| s.to_string()),
                left.len(),
                0,
                iter::empty::<String>(),
                0
            ),
            Ok((1, 0))
        );

        assert_eq!(
            str::from_utf8(&buf),
            Ok("@@ -0,1 +0,0 @@\n-abc\n")
        );
    }

    #[test]
    fn test_del_two() {
        let mut buf = Vec::<u8>::new();
        let left = ["abc", "xyz"];

        assert_eq!(
            write_diff_section(
                &mut buf,
                11,
                left.iter().map(|s| s.to_string()),
                left.len(),
                3,
                iter::empty::<String>(),
                0
            ),
            Ok((13, 3))
        );

        assert_eq!(
            str::from_utf8(&buf),
            Ok("@@ -11,2 +3,0 @@\n-abc\n-xyz\n")
        );
    }

    #[test]
    fn test_mod_one() {
        let mut buf = Vec::<u8>::new();
        let left = ["abc"];
        let right = ["xyz"];

        assert_eq!(
            write_diff_section(
                &mut buf,
                6,
                left.iter().map(|s| s.to_string()),
                left.len(),
                85,
                right.iter().map(|s| s.to_string()),
                right.len()
            ),
            Ok((7, 86))
        );

        assert_eq!(
            str::from_utf8(&buf),
            Ok("@@ -6,1 +85,1 @@\n-abc\n+xyz\n")
        );
    }

    #[test]
    fn test_mod_two() {
        let mut buf = Vec::<u8>::new();
        let left = ["abc", "def"];
        let right = ["uvw", "xyz"];

        assert_eq!(
            write_diff_section(
                &mut buf,
                6,
                left.iter().map(|s| s.to_string()),
                left.len(),
                85,
                right.iter().map(|s| s.to_string()),
                right.len()
            ),
            Ok((8, 87))
        );

        assert_eq!(
            str::from_utf8(&buf),
            Ok("@@ -6,2 +85,2 @@\n-abc\n-def\n+uvw\n+xyz\n")
        );
    }

}
