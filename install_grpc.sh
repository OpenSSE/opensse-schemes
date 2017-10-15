#!/bin/sh
set -ex

if [ -d "$HOME/deps/include/google" ] && [ -d "$HOME/deps/include/grpc" ] && [ -d "$HOME/deps/include/grpc++" ]  && [ -f "$HOME/deps/lib/libprotobuf.a" ] && [ -f "$HOME/deps/lib/libgrpc.a" ]  && [ -f "$HOME/deps/bin/protoc" ]; then
	
	echo "gRPC is already installed"

else
	
	echo "Install gRPC"
	
INSTALL_DIR=$HOME/deps

git clone -b $(curl -L https://grpc.io/release) https://github.com/grpc/grpc

cd grpc
git submodule update --init

PROTOBUF_CONFIG_OPTS="--prefix=$INSTALL_DIR" make prefix=$INSTALL_DIR  -j2
PROTOBUF_CONFIG_OPTS="--prefix=$INSTALL_DIR" sudo make prefix=$INSTALL_DIR install

cd third_party/protobuf
sudo make install

# make clean
fi