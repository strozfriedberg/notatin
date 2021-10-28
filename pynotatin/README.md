# PyNotatin
Python bindings for the Notatin crate. This project is currently pre-release and should not be used for active investigations.

## Install
### From source:

```
pip install . --use-feature=in-tree-build
```

### From Github:
```
pip install git+https://github.com/strozfriedberg/notatin.git#subdirectory=pynotatin
```

## Library usage
```python,no_run
from notatin import PyNotatinParser

def py_notatin_dump():
    parser = PyNotatinParser("../test_data/NTUSER.DAT")
    for key in parser.reg_keys():
        print(key.path)
        for value in key.values():
            print("\t" + value.pretty_name + "\t" + str(value.content))
}
```
See `test_reg.py` for other usage examples (particularly regarding accessing specific keys and values directly).

## Unit tests
Use `cargo test --no-default-features` to run the Rust unit tests. The `--no-default-featues` option is required due to this [known issue](https://pyo3.rs/v0.13.2/faq.html#i-cant-run-cargo-test-im-having-linker-issues-like-symbol-not-found-or-undefined-reference-to-_pyexc_systemerror) in PyO3.

## Copyright
Copyright 2021 Aon Cyber Solutions. Notatin and PyNotatin are licensed under the Apache License, Version 2.0.

