#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || ("$Target" == 'windows') ]]; then
  exit
fi

if [[ "$Target" == 'windows_package' ]]; then
  export POETRY_CACHE_DIR=pynotatin/.poetry
fi

pushd pynotatin
poetry lock --check && poetry install --no-cache
popd
