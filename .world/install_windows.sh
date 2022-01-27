#!bash.exe -ex

. .world/install_base.sh
pushd pynotatin
pip install . --use-feature=in-tree-build
popd