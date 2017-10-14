#!/bin/sh
set -ex

git clone -b $(curl -L https://grpc.io/release) https://github.com/grpc/grpc

cd grpc
git submodule update --init
make

(cd grpc/third_party/protobuf; sudo make install;)

sudo make install