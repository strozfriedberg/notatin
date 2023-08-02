# Notatin

Notatin is a Rust library for parsing offline Windows Registry files. It includes Python bindings for the library (pynotatin) and binaries for working directly with registry files.

## Features
 - Implemented using 100% safe Rust, and works on all platforms supported by Rust (that have stdlib). Tested in Windows and Ubuntu.
 - Supports applying transaction logs, and recovering deleted and modified keys and values.
 - Supports exporting to JSONL, XLSX, TSV, and Eric Zimmerman's common registry format (https://github.com/EricZimmerman/Registry).
 - Python bindings are included in the project (pynotatin).

### notatin (crate)
 `notatin` is a library that parses offline Windows Registry files.

### reg_dump (utility)
`reg_dump` is a binary utility. It parses registry files, or a tree of registry files using the `--recurse` argument, and exports to JSONL, XLSX, TSV, or common format.
An optional key path filter may also be supplied. Optional recovery of deleted and prior versions of keys and values is also supported.

JSONL dumps _all_ the data. The `--full-field-info` argument will include file offset information for each field.

XLSX and TSV dump some of the data; the data in both outputs is the same but XLSX has context-specific formatting which is especially helpful when reviewing recovered data.
And, if you are focusing on recovered items, the `--recovered-only` argument will return only items that are modified, deleted, or that contain a modified or deleted value.

Common dumps what common wants.

```
Notatin Registry Dump 1.0.0

Usage: reg_dump [OPTIONS] --input <input> --output <output> -t <TYPE>

Options:
  -i, --input <input>      Base registry file, or root folder if recursing
  -o, --output <output>    Output file. or folder if recursing
  -t <TYPE>                output type [default: jsonl] [possible values: jsonl, xlsx, tsv, common]
  -r, --recurse            Recurse through input looking for registry files
      --recover            Recover deleted and versioned keys and values
      --recovered-only     Only export recovered items (applicable to tsv and xlsx output)
      --full-field-info    Get the offset and length for each key/value field (applicable to jsonl output)
  -s, --skip-logs          Skip transaction log files
  -f, --filter [<STRING>]  Key path for filter (ex: 'ControlSet001\Services')
  -h, --help               Print help
  -V, --version            Print version
```

### reg_compare (utility)
`reg_compare` is a binary utility. It will compare two registry files, or trees of files using `--recurse` argument (the structure of the trees must match). The default output is a report of the differences
in a format similar to that of Regshot. The `--diff` argument will format the results in a unified diff format.

```
Usage: reg_compare [OPTIONS] --base <base> --compare <compare> --output <output>

Options:
  -b, --base <base>        Base registry file or root folder to search
  -c, --compare <compare>  Registry file or root folder to search for comparison
  -o, --output <output>    Output file or folder
  -r, --recurse            Recurse through base and comparison folders looking for registry files; file trees must match
  -f, --filter [<STRING>]  Key path for filter (ex: 'ControlSet001\Services')
  -d, --diff               Export unified diff format output
  -s, --skip-logs          Skip transaction log files
  -h, --help               Print help
  -V, --version            Print version
```

## Library usage
```rust,no_run
use notatin::{
    err::Error,
    parser_builder::{ParserBuilder, ParserBuilderTrait},
};

fn main() -> Result<(), Error> {
    let mut parser = ParserBuilder::from_path("system")
        .recover_deleted(false)
        .with_transaction_log("system.log1")
        .with_transaction_log("system.log2")
        .build()?;

    for key in parser.iter() {
        println!("{}", key.path);
        for value in key.value_iter() {
            println!("\t{} {:?}", value.value_name, value.get_content());
        }
    }
    Ok(())
}
```
Opening files and iterating the results is intended to be straightforward.
By default, iteration is prefix order (displayed in the code sample above). Postorder traversal (children before parents) is available as well:
```rust,no_run
for key in parser.iter_postorder() {
    //...
}
```
Result filters are optional, but they can speed up processing as Notatin will skip parsing what doesn't match.
Filters may include regular expressions and/or literal paths and are applied at iteration time.
```rust,no_run
let filter = FilterBuilder::new()
    .add_literal_segment("control Panel")
    .add_regex_segment("access.*")
    .add_regex_segment("keyboard.+")
    .return_child_keys(false)
    .build();
```

### pynotatin (Python bindings)
Please see the pynotatin README.md for details on using pynotatin.

 ## What is Notatin?
 _Notatin_ is another name for the enzyme glucose oxidase. Glucose oxidase catalyzes the oxidation of glucose to hydrogen peroxide.
 It is present in honey because honeybees synthesize the enzyme and deposit it into the honey, where it acts as a natural preservative.
 So, Notatin helps preserve things in hives.
 * https://en.wikipedia.org/wiki/Glucose_oxidase
 * https://en.wikipedia.org/wiki/Windows_Registry#Hives

 ## Copyright
 Copyright 2023 Aon Cyber Solutions. Notatin is licensed under the Apache License, Version 2.0.
