# Notatin

Notatin is a Rust parser for offline Windows Registry files. This project is currently pre-release and should not be used for active investigations.

## Features
 - Implemented using 100% safe Rust and works on all platforms supported by Rust (that have stdlib). Tested in Windows and Ubuntu.
 - Supports applying transaction logs and recovering deleted and modified keys and values.
 - Supports exporting to JSONL, XLSX, TSV, and Eric Zimmerman's common registry format (https://github.com/EricZimmerman/Registry).
 - Python bindings are included in the project (pynotatin).

### notatin (crate)
 `notatin` is a library that parses Windows Registry files.

### reg_dump (utility)
`reg_dump` is a binary utility provided with this crate. It parses primary registry files (with optional transaction logs) and exports to JSONL, TSV, XLSX, or common format.
An optional key path filter may also be supplied. Optional analysis to recover deleted and prior versions of keys and values from the transaction log is also supported.

JSONL dumps _all_ the data. The `--full-field-info` argument will include file offset information for each field.

XLSX and TSV dump some of the data; the data in both outputs is the same but XLSX has context-specific formatting which is especially helpful when reviewing recovered data.
And, if you are focusing on recovered items, the `--recovered-only` argument will return only items that are modified, deleted, or that contain a modified or deleted value.

Common dumps what common wants.

```
Notatin Registry Dump 0.2

USAGE:
    reg_dump [FLAGS] [OPTIONS] -t <TYPE> --input <FILE(S)> --output <FILE>

FLAGS:
        --full-field-info    Get the offset and length for each key/value field (applicable for jsonl output only)
    -h, --help               Prints help information
    -r, --recover            Recover deleted and versioned keys and values
        --recovered-only     Only export recovered items (applicable for tsv and xlsx output only)
    -V, --version            Prints version information

OPTIONS:
    -t <TYPE>                output type [default: jsonl]  [possible values: Jsonl, Common, Tsv, Xlsx]
    -f, --filter <STRING>    Key path for filter (ex: 'ControlSet001\Services')
    -i, --input <FILE(S)>    Base registry file with optional transaction log(s) (Comma separated list)
    -o, --output <FILE>      Output file
```

### reg_compare (utility)
`reg_compare` is a binary utility provided with this crate. It will compare two registry files (with optional transaction logs) and produce a report of the differences
in a format similar to that of Regshot.

```
Notatin Registry Compare 0.1

USAGE:
    reg_compare [OPTIONS] --base <FILES> --comparison <FILES> --output <FILE>

OPTIONS:
    -b, --base <FILES>          Base registry file with optional transaction file(s) (Comma separated list)
    -c, --comparison <FILES>    Comparison registry file with optional transaction file(s) (Comma separated list)
    -f, --filter <STRING>       Key path for filter (ex: 'ControlSet001\Services')
    -o, --output <FILE>         Output file
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

## Upcoming improvements
 - Support for optional Hachoir-light style struct information
 - Improve performance of transaction log analysis

 ## What is Notatin?
 _Notatin_ is another name for the enzyme glucose oxidase. Glucose oxidase catalyzes the oxidation of glucose to hydrogen peroxide.
 It is present in honey because honeybees synthesize the enzyme and deposit it into the honey, where it acts as a natural preservative.
 So, Notatin helps preserve things in hives.
 * https://en.wikipedia.org/wiki/Glucose_oxidase
 * https://en.wikipedia.org/wiki/Windows_Registry#Hives

 ## Copyright
 Copyright 2021 Aon Cyber Solutions. Notatin is licensed under the Apache License, Version 2.0.
