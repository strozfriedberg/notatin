#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || ("$Target" == 'windows') ]]; then
  exit
fi

pushd pynotatin
poetry run maturin build --release --interpreter python --no-sdist
mkdir -p $INSTALL/lib/python/pynotatin
cp target/wheels/* $INSTALL/lib/python/pynotatin
popd

mkdir -p $INSTALL/bin
cp target/release/reg_compare${EXE_EXT} $INSTALL/bin
cp target/release/reg_dump${EXE_EXT} $INSTALL/bin
