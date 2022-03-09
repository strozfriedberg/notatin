#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || "$Architecture" != '64' ]]; then
  exit
fi

rm -rf pynotatin/out
