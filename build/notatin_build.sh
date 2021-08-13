#!/bin/sh -ex

cargo test
cargo clippy --all-features --all-targets

cd pynotatin
cargo test --no-default-features # --no-default-features is specified to avoid a bug in pyo3 (https://aeshirey.github.io/code/2020/04/01/tests-and-pyo3.html)
cargo clippy --all-features --all-targets
poetry run maturin develop
poetry run pytest

