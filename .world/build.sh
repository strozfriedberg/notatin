#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || "$Architecture" != '64' ]]; then
  exit
fi
BASEDIR=$(pwd)

cargo test
cargo clippy --all-features --all-targets

pushd pynotatin

cargo test --no-default-features # --no-default-features is specified to avoid a bug in PyO3 (https://aeshirey.github.io/code/2020/04/01/tests-and-pyo3.html)
cargo clippy --all-features --all-targets
poetry run maturin develop
poetry run pytest

poetry run maturin build --release

popd