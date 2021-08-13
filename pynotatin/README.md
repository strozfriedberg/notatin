# PyNotatin
Python bindings for the Notatin crate. This project is currently pre-release and should not be used for active investigations.

## Build

```
pip install . --use-feature=in-tree-build
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

## Copyright
Copyright 2021 Aon Cyber Solutions. Notatin and PyNotatin are licensed under the Apache License, Version 2.0.

