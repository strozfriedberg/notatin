# Notatin

This is a Rust parser for offline Windows Registry files.

Python bindings are included in the project (pyreg).

## Features
 - Implemented using 100% safe Rust and works on all platforms supported by Rust (that have stdlib). Tested in Windows and Ubuntu.
 - Supports applying transaction logs and recovering deleted and modified keys and values.
 - Supports exporting to JSONL, TSV, and Eric Zimmerman's common registry format (https://github.com/EricZimmerman/Registry)

# `notatin` (crate):
 `notatin` is a library that parses Windows Registry files.

# `reg_dump` (Binary utility):
`reg_dump` is a binary utility provided with this crate. It parses primary registry files (with optional transaction logs) and exports to JSONL, TSV, or common format.
An optional key path filter may also be supplied. Optional analysis to recover deleted and prior versions of keys and values from the transaction log is also supported.

JSONL dumps _all_ the data. TSV dumps some of the data. Common dumps what common wants.

```
Notatin Registry Dump 0.1

USAGE:
    reg_dump [FLAGS] [OPTIONS] --input <FILE(S)> --output <FILE> -t <type>

FLAGS:
    -r, --recover    Recover deleted and versioned keys and values

OPTIONS:
    -i, --input <FILE(S)>    Base registry file with optional transaction log(s) (Comma separated list)
    -o, --output <FILE>      Output file
    -f, --filter <STRING>    Key path for filter (ex: 'ControlSet001\Services')
    -t <TYPE>                output type [default: jsonl]  [possible values: Jsonl, Common, Tsv]
```

# `reg_compare` (Binary utility):
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

# Library usage:
```rust,no_run
use notatin::{
    err::Error,
    filter::{Filter, RegQuery},
    parser::Parser,
};

fn main() -> Result<(), Error> {
    let mut parser = Parser::from_path(
        "system",
        Some(vec!["system.log1", "system.log2"]),
        Some(Filter::from_path(RegQuery::from_key(
            r"Software\Microsoft",
            false, // key path doesn't contain the root name
            true, // return children of the key path
        ))),
        false, // don't recover deleted/modified
    )?;

    for key in parser.iter() {
        println!("{}", key.path);
        for value in key.value_iter() {
            println!("\t{} {:?}", value.value_name, value.get_content());
        }
    }
    Ok(())
}
```
Opening files and iterating the results is intended to be pretty straightforward. By default, iteration is prefix order;
postorder traversal (children before parents) is available as well.

Result filters are optional, but they can speed up processing as Notatin will skip what it doesn't need.
Regular expression filters are supported
as well as literal paths, but setting up a regular expression filter needs to be streamlined.
```
let filter = Filter {
    reg_query: Some(RegQuery {
        key_path: vec![
            RegQueryComponent::ComponentString(
                "control Panel".to_string().to_ascii_lowercase(),
            ),
            RegQueryComponent::ComponentRegex(Regex::new("access.*").unwrap()),
            RegQueryComponent::ComponentRegex(Regex::new("keyboard.+").unwrap()),
        ],
        key_path_has_root: false,
        children: false,
    }),
};
```

## Upcoming improvements:
 - Recover deleted keys and values from the primary registry file
 - Support for optional Hachoir-light style struct information
 - Improve regular expression filter creation
 - Improve performance of transaction log analysis

 ## What is Notatin?
 _Notatin_ is another name for the enzyme glucose oxidase. Glucose oxidase catalyzes the oxidation of glucose to hydrogen peroxide.
 It is present in honey because honeybees synthesize the enzyme and deposit it into the honey, where it acts as a natural preservative.
 So, Notatin preserves honey. https://en.wikipedia.org/wiki/Glucose_oxidase

