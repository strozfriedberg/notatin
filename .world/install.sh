#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || ( "$Target" == 'windows' ) ]]; then
  exit
fi

mkdir -p $INSTALL/lib/python/pynotatin
cp pynotatin/target/wheels/* $INSTALL/lib/python/pynotatin

if [[ "$Target" == 'windows_package' ]]; then
  pushd pynotatin
  pip install . --use-feature=in-tree-build
  popd
fi
