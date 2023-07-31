/*
 * Copyright 2023 Aon Cyber Solutions
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
use clap::{arg, Arg, Command};
use itertools::{EitherOrBoth, Itertools};
use notatin::{
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
    cli_util::*,
    err::Error,
    filter::{Filter, FilterBuilder},
    log::Logs,
    parser::{Parser, ParserIterator},
    parser_builder::ParserBuilder,
    util::format_date_time,
};
use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{BufWriter, Write},
    iter,
    path::*,
    str,
};
use walkdir::WalkDir;

fn main() -> Result<(), Error> {
    let matches = Command::new("Notatin Registry Compare")
    .version("0.2")
    .arg(Arg::new("base")
        .short('b')
        .long("base")
        .help("Base registry file or root folder to search")
        .required(true)
        .number_of_values(1))
    .arg(Arg::new("compare")
        .short('c')
        .long("compare")
        .help("Registry file or root folder to search for comparison")
        .required(true)
        .number_of_values(1))
    .arg(Arg::new("output")
        .short('o')
        .long("output")
        .help("Output file or folder")
        .required(true)
        .number_of_values(1))
    .arg(arg!(
        --recurse "Recurse through base and comparison folders looking for registry files; file trees must match"
    ))
    .arg(arg!(-f --filter [STRING] "Key path for filter (ex: 'ControlSet001\\Services')"))
    .arg(arg!(
            -d --diff "Export unified diff format output"
    ))
    .arg(arg!(
        -s --"skip-logs" "Skip transaction log files"
    ))
    .get_matches();

    let base = matches.get_one::<String>("base").expect("Required value");
    let compare = matches
        .get_one::<String>("compare")
        .expect("Required value");

    let output: &str = matches.get_one::<String>("output").expect("Required value");

    let use_diff_format = matches.get_flag("diff");
    let recurse = matches.get_flag("recurse");
    let skip_logs = matches.get_flag("skip-logs");

    let filter = match matches.get_one::<String>("filter") {
        Some(f) => Some(
            FilterBuilder::new()
                .add_key_path(f)
                .return_child_keys(true)
                .build()?,
        ),
        None => None,
    };

    if recurse {
        process_folders(
            output,
            &PathBuf::from(base),
            &PathBuf::from(compare),
            filter,
            use_diff_format,
            skip_logs,
        )
    } else {
        process_files(
            output,
            PathBuf::from(base),
            PathBuf::from(compare),
            filter,
            use_diff_format,
            skip_logs,
        )
    }
}

fn process_files<T>(
    outpath: T,
    base: PathBuf,
    comparison: PathBuf,
    filter: Option<Filter>,
    use_diff_format: bool,
    skip_logs: bool,
) -> Result<(), Error>
where
    T: AsRef<Path> + Debug,
{
    let base_logs = get_log_files(
        skip_logs,
        &base.file_name().unwrap().to_string_lossy(),
        &base,
    );
    let comp_logs = get_log_files(
        skip_logs,
        &comparison.file_name().unwrap().to_string_lossy(),
        &comparison,
    );

    reg_compare(
        &outpath,
        base,
        base_logs,
        comparison,
        comp_logs,
        filter,
        use_diff_format,
    )
}

fn process_folders<T>(
    outfolder: T,
    base: &PathBuf,
    comparison: &PathBuf,
    filter: Option<Filter>,
    use_diff_format: bool,
    skip_logs: bool,
) -> Result<(), Error>
where
    T: AsRef<Path> + std::convert::AsRef<std::ffi::OsStr>,
{
    let reg_files = vec![
        "sam",
        "security",
        "software",
        "system",
        "default",
        "amcache",
        "ntuser.dat",
        "usrclass.dat",
    ];
    let comparison_path = Path::new(&comparison);

    for entry in WalkDir::new(base)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| !e.file_type().is_dir())
    {
        if let Some(f) = entry.file_name().to_str() {
            let f_lower = f.to_lowercase();
            if reg_files.contains(&f_lower.as_str()) && file_has_size(entry.path()) {
                match entry.path().strip_prefix(base) {
                    Err(e) => println!("{:?}", e),
                    Ok(primary_path_from_base) => {
                        let comparison_path_to_find = comparison_path.join(primary_path_from_base);
                        if comparison_path_to_find.is_file()
                            && file_has_size(&comparison_path_to_find)
                        {
                            let base_logs = get_log_files(skip_logs, f, entry.path());
                            let comp_logs = get_log_files(skip_logs, f, &comparison_path_to_find);
                            let outpath =
                                get_outpath(primary_path_from_base, &outfolder, use_diff_format);
                            if let Err(e) = reg_compare(
                                &outpath,
                                PathBuf::from(entry.path()),
                                base_logs,
                                comparison_path_to_find,
                                comp_logs,
                                filter.clone(),
                                use_diff_format,
                            ) {
                                println!(
                                    "Error processing {:?} and {:?}: {:?}",
                                    base, comparison, e
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn get_outpath<T>(primary_path_from_base: &Path, outfolder: T, use_diff_folder: bool) -> PathBuf
where
    T: AsRef<Path> + std::convert::AsRef<std::ffi::OsStr>,
{
    let path = primary_path_from_base.to_string_lossy();
    let output_filename = str::replace(&path, std::path::MAIN_SEPARATOR, "_");
    let mut output_path = Path::new(&outfolder).join(output_filename);
    if use_diff_folder {
        output_path.set_extension("diff");
    } else {
        output_path.set_extension("txt");
    }
    output_path
}

fn reg_compare<T>(
    output: T,
    base_primary: PathBuf,
    base_logs: Option<Vec<PathBuf>>,
    comparison_primary: PathBuf,
    comparison_logs: Option<Vec<PathBuf>>,
    filter: Option<Filter>,
    use_diff_format: bool,
) -> Result<(), Error>
where
    T: AsRef<Path> + Debug + Copy,
{
    let write_file = File::create(output)
        .map_err(|e| Error::buffer(format!("Error creating file {:?}: {}", output, e).as_str()))?;
    let mut writer = BufWriter::new(write_file);

    let mut base_filenames = base_primary.to_string_lossy().into_owned();
    if let Some(logs) = &base_logs {
        base_filenames = format!("{:?} {:?}", base_filenames, logs)
    }
    let mut comparison_filenames = comparison_primary.to_string_lossy().into_owned();
    if let Some(logs) = &comparison_logs {
        comparison_filenames = format!("{:?} {:?}", comparison_filenames, logs)
    }

    println!("Comparing {:?} and {:?}", base_primary, comparison_primary);

    let mut original_map: HashMap<(String, Option<String>), Option<Hash>> = HashMap::new();

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

    (if use_diff_format {
        write_diff
    } else {
        write_text
    })(
        &mut writer,
        &base_filenames,
        &comparison_filenames,
        keys_deleted,
        keys_added,
        keys_modified,
        values_deleted,
        values_added,
        values_modified,
    )?;

    Ok(())
}

fn write_text_section<W: Write>(
    writer: &mut W,
    header: &str,
    removed: impl Iterator<Item = String>,
    added: impl Iterator<Item = String>,
    len: usize,
) -> Result<(), Error> {
    writeln!(
        writer,
        "\n----------------------------------\n{}: {}\n----------------------------------",
        header, len
    )?;

    for item in removed.zip_longest(added) {
        match item {
            EitherOrBoth::Both(removed, added) => {
                writeln!(writer, "{}", removed)?;
                writeln!(writer, "{}", added)?;
            }
            EitherOrBoth::Left(removed) => writeln!(writer, "{}", removed)?,
            EitherOrBoth::Right(added) => writeln!(writer, "{}", added)?,
        }
    }
    Ok(())
}

fn write_text<W: Write>(
    writer: &mut W,
    base_filenames: &String,
    comparison_filenames: &String,
    keys_deleted: Vec<CellKeyNode>,
    keys_added: Vec<CellKeyNode>,
    keys_modified: Vec<(CellKeyNode, CellKeyNode)>,
    values_deleted: Vec<(String, CellKeyValue)>,
    values_added: Vec<(String, CellKeyValue)>,
    values_modified: Vec<(String, CellKeyValue, CellKeyValue)>,
) -> Result<(), Error> {
    writeln!(writer, "Base: {} ", base_filenames)?;
    writeln!(writer, "Comparison: {}", comparison_filenames)?;

    let total_changes = keys_deleted.len()
        + keys_added.len()
        + keys_modified.len()
        + values_deleted.len()
        + values_added.len()
        + values_modified.len();

    write_text_section(
        writer,
        "Keys deleted",
        keys_deleted.iter().map(format_key),
        iter::empty::<String>(),
        keys_deleted.len(),
    )?;

    write_text_section(
        writer,
        "Keys added",
        iter::empty::<String>(),
        keys_added.iter().map(format_key),
        keys_added.len(),
    )?;

    write_text_section(
        writer,
        "Keys modified",
        keys_modified.iter().map(|k| format_key(&k.0)),
        keys_modified.iter().map(|k| format_key(&k.1)),
        keys_modified.len(),
    )?;

    write_text_section(
        writer,
        "Values deleted",
        values_deleted.iter().map(|v| format_value(&v.0, &v.1)),
        iter::empty::<String>(),
        values_deleted.len(),
    )?;

    write_text_section(
        writer,
        "Values added",
        iter::empty::<String>(),
        values_added.iter().map(|v| format_value(&v.0, &v.1)),
        values_added.len(),
    )?;

    write_text_section(
        writer,
        "Values modified",
        values_modified.iter().map(|v| format_value(&v.0, &v.1)),
        values_modified.iter().map(|v| format_value(&v.0, &v.2)),
        values_modified.len(),
    )?;

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
    rlen: usize,
) -> Result<(usize, usize), Error> {
    if llen > 0 || rlen > 0 {
        writeln!(writer, "@@ -{},{} +{},{} @@", lline, llen, rline, rlen)?;

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
    keys_deleted: Vec<CellKeyNode>,
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        keys_deleted.iter().map(format_key),
        keys_deleted.len(),
        rline,
        iter::empty::<String>(),
        0,
    )
}

fn write_diff_k_add<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    keys_added: Vec<CellKeyNode>,
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        iter::empty::<String>(),
        0,
        rline,
        keys_added.iter().map(format_key),
        keys_added.len(),
    )
}

fn write_diff_k_mod<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    keys_modified: Vec<(CellKeyNode, CellKeyNode)>,
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        keys_modified.iter().map(|k| format_key(&k.0)),
        keys_modified.len(),
        rline,
        keys_modified.iter().map(|k| format_key(&k.1)),
        keys_modified.len(),
    )
}

fn write_diff_v_del<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    values_deleted: Vec<(String, CellKeyValue)>,
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        values_deleted.iter().map(|v| format_value(&v.0, &v.1)),
        values_deleted.len(),
        rline,
        iter::empty::<String>(),
        0,
    )
}

fn write_diff_v_add<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    values_added: Vec<(String, CellKeyValue)>,
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        iter::empty::<String>(),
        0,
        rline,
        values_added.iter().map(|v| format_value(&v.0, &v.1)),
        values_added.len(),
    )
}

fn write_diff_v_mod<W: Write>(
    writer: &mut W,
    lline: usize,
    rline: usize,
    values_modified: Vec<(String, CellKeyValue, CellKeyValue)>,
) -> Result<(usize, usize), Error> {
    write_diff_section(
        writer,
        lline,
        values_modified.iter().map(|v| format_value(&v.0, &v.1)),
        values_modified.len(),
        rline,
        values_modified.iter().map(|v| format_value(&v.0, &v.2)),
        values_modified.len(),
    )
}

fn write_diff<W: Write>(
    w: &mut W,
    base_filenames: &String,
    comparison_filenames: &String,
    keys_deleted: Vec<CellKeyNode>,
    keys_added: Vec<CellKeyNode>,
    keys_modified: Vec<(CellKeyNode, CellKeyNode)>,
    values_deleted: Vec<(String, CellKeyValue)>,
    values_added: Vec<(String, CellKeyValue)>,
    values_modified: Vec<(String, CellKeyValue, CellKeyValue)>,
) -> Result<(), Error> {
    writeln!(w, "--- {}", base_filenames)?;
    writeln!(w, "+++ {}", comparison_filenames)?;

    let mut lline = 1;
    let mut rline = 1;

    (lline, rline) = write_diff_k_del(w, lline, rline, keys_deleted)?;
    (lline, rline) = write_diff_k_add(w, lline, rline, keys_added)?;
    (lline, rline) = write_diff_k_mod(w, lline, rline, keys_modified)?;
    (lline, rline) = write_diff_v_del(w, lline, rline, values_deleted)?;
    (lline, rline) = write_diff_v_add(w, lline, rline, values_added)?;
    write_diff_v_mod(w, lline, rline, values_modified)?;

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

fn get_parser(primary: PathBuf, logs: Option<Vec<PathBuf>>) -> Result<Parser, Error> {
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
    fn test_add_one_diff() {
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

        assert_eq!(str::from_utf8(&buf).unwrap(), "@@ -0,0 +0,1 @@\n+abc\n");
    }

    #[test]
    fn test_add_two_diff() {
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

        assert_eq!(str::from_utf8(&buf), Ok("@@ -5,0 +18,2 @@\n+abc\n+xyz\n"));
    }

    #[test]
    fn test_del_one_diff() {
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

        assert_eq!(str::from_utf8(&buf), Ok("@@ -0,1 +0,0 @@\n-abc\n"));
    }

    #[test]
    fn test_del_two_diff() {
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

        assert_eq!(str::from_utf8(&buf), Ok("@@ -11,2 +3,0 @@\n-abc\n-xyz\n"));
    }

    #[test]
    fn test_mod_one_diff() {
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

        assert_eq!(str::from_utf8(&buf), Ok("@@ -6,1 +85,1 @@\n-abc\n+xyz\n"));
    }

    #[test]
    fn test_mod_two_diff() {
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

    #[test]
    fn test_add_one_text() {
        let mut buf = Vec::<u8>::new();
        let right = ["abc"];

        assert_eq!(
            write_text_section(
                &mut buf,
                "Add One Text",
                iter::empty::<String>(),
                right.iter().map(|s| s.to_string()),
                right.len()
            ),
            Ok(())
        );

        assert_eq!(str::from_utf8(&buf).unwrap(), "\n----------------------------------\nAdd One Text: 1\n----------------------------------\nabc\n");
    }

    #[test]
    fn test_add_two_text() {
        let mut buf = Vec::<u8>::new();
        let right = ["abc", "xyz"];

        assert_eq!(
            write_text_section(
                &mut buf,
                "Add Two Text",
                iter::empty::<String>(),
                right.iter().map(|s| s.to_string()),
                right.len()
            ),
            Ok(())
        );

        assert_eq!(str::from_utf8(&buf), Ok("\n----------------------------------\nAdd Two Text: 2\n----------------------------------\nabc\nxyz\n"));
    }

    #[test]
    fn test_del_one_text() {
        let mut buf = Vec::<u8>::new();
        let left = ["abc"];

        assert_eq!(
            write_text_section(
                &mut buf,
                "Del One Text",
                left.iter().map(|s| s.to_string()),
                iter::empty::<String>(),
                left.len(),
            ),
            Ok(())
        );

        assert_eq!(str::from_utf8(&buf), Ok("\n----------------------------------\nDel One Text: 1\n----------------------------------\nabc\n"));
    }

    #[test]
    fn test_del_two_text() {
        let mut buf = Vec::<u8>::new();
        let left = ["abc", "xyz"];

        assert_eq!(
            write_text_section(
                &mut buf,
                "Del Two Text",
                left.iter().map(|s| s.to_string()),
                iter::empty::<String>(),
                left.len(),
            ),
            Ok(())
        );

        assert_eq!(str::from_utf8(&buf), Ok("\n----------------------------------\nDel Two Text: 2\n----------------------------------\nabc\nxyz\n"));
    }

    #[test]
    fn test_mod_one_text() {
        let mut buf = Vec::<u8>::new();
        let left = ["abc"];
        let right = ["xyz"];

        assert_eq!(
            write_text_section(
                &mut buf,
                "Mod One Text",
                left.iter().map(|s| s.to_string()),
                right.iter().map(|s| s.to_string()),
                right.len()
            ),
            Ok(())
        );

        assert_eq!(str::from_utf8(&buf), Ok("\n----------------------------------\nMod One Text: 1\n----------------------------------\nabc\nxyz\n"));
    }

    #[test]
    fn test_mod_two_text() {
        let mut buf = Vec::<u8>::new();
        let left = ["abc", "def"];
        let right = ["uvw", "xyz"];

        assert_eq!(
            write_text_section(
                &mut buf,
                "Mod Two Text",
                left.iter().map(|s| s.to_string()),
                right.iter().map(|s| s.to_string()),
                right.len()
            ),
            Ok(())
        );

        assert_eq!(
            str::from_utf8(&buf),
            Ok("\n----------------------------------\nMod Two Text: 2\n----------------------------------\nabc\nuvw\ndef\nxyz\n")
        );
    }
}
