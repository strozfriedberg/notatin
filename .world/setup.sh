#!/bin/bash -ex

. .world/build_config.sh

if [[ "$Linkage" == 'static' || "$Target" != 'linux' ]]; then
  exit
fi

#BASEDIR=$(pwd)
#
#PYTHON=python3
#VENV=venv
#VENVBIN=bin
#
#$PYTHON -m venv --clear $VENV
#. "$VENV/$VENVBIN/activate"
#pip install toml maturin==0.8.3
#deactivate
