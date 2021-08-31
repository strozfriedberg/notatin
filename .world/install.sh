#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || "$Target" != 'linux' ]]; then
  exit
fi

mkdir -p $INSTALL/lib/python/pynotatin
cp pynotatin/target/wheels/* $INSTALL/lib/python/pynotatin
