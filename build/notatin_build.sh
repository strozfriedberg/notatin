#!/bin/sh -ex

cargo test
cargo clippy

cd pyreg
cargo test
cargo clippy
