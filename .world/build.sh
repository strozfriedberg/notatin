#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || "$Target" != 'linux' ]]; then
  exit
fi

BASEDIR=$(pwd)

PYTHON=python3
VENV=venv
VENVBIN=bin

. "$VENV/$VENVBIN/activate"

maturin build --release -o out

cargo test
cargo clippy --all-features --all-targets

pushd pynotatin

cargo test --no-default-features # --no-default-features is specified to avoid a bug in PyO3 (https://aeshirey.github.io/code/2020/04/01/tests-and-pyo3.html)
cargo clippy --all-features --all-targets
poetry run maturin develop
poetry run pytest

popd

deactivate
