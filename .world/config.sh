#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || ( "$Target" != 'linux' && "$Target" != 'windows_package' ) ]]; then
  exit
fi

pushd pynotatin
poetry install
popd