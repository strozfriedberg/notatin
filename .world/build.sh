#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || "$Target" != 'linux' ]]; then
  exit
fi

. .world/build_base.sh
