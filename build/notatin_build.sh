#!/bin/sh -ex

cargo test
cargo clippy --all-features --all-targets

cd pynotatin
cargo test --no-default-features
cargo clippy --all-features --all-targets
poetry run maturin develop
poetry run pytest

