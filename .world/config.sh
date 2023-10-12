#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || ( "$Target" == 'windows' ) ]]; then
  exit
fi

fi
pushd pynotatin
poetry lock --check && poetry install --no-cache
popd
