# Pynotatin
Python bindings for the Notatin crate. This project is currently pre-release and should not be used for active investigations.

## Build
### Maturin - for development
```
maturin develop
```
### Docker - for installation
Docker builds must be initiated from the top-level Notatin directory.
```
docker build -t pynotatin .
docker run --rm -v $(pwd)/pynotatin_out:/out pynotatin
```
After building, install the appropriate wheel from the `pynotatin_out` directory.

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
Copyright 2021 Aon Cyber Solutions. Notatin is licensed under the Apache License, Version 2.0.

