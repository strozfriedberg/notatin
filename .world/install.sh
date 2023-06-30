#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || ( "$Target" == 'windows' ) ]]; then
  exit
fi

mkdir -p $INSTALL/lib/python/pynotatin
cp pynotatin/target/wheels/* $INSTALL/lib/python/pynotatin

mkdir -p $INSTALL/bin
cp target/release/reg_compare${EXE_EXT} $INSTALL/bin
cp target/release/reg_dump${EXE_EXT} $INSTALL/bin

if [[ "$Target" == 'windows_package' ]]; then
  pushd pynotatin
  pip install .
  popd
fi