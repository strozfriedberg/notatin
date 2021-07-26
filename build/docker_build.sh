#!/bin/bash -ex

IMAGE_NAME=$1

docker build -f build/Dockerfile -t $IMAGE_NAME .
