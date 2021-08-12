#!/bin/sh -ex

cargo test
cargo clippy --all-features --all-targets

cd pyreg
cargo test --no-default-features
cargo clippy --all-features --all-targets
poetry run maturin develop
poetry run pytest

