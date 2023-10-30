#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || ("$Target" == 'windows') ]]; then
  exit
fi

pushd pynotatin
poetry config virtualenvs.in-project true --local

if [[ "$Target" == 'windows_package' ]]; then
  poetry config cache-dir .poetry --local
fi

poetry lock --check && poetry install --no-cache
popd
