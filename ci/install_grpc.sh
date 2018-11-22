#!/bin/sh
set -ex

INSTALL_DIR=$HOME/deps

if [ -d "$INSTALL_DIR/include/google" ] && [ -d "$INSTALL_DIR/include/grpc" ] && [ -d "$INSTALL_DIR/include/grpc++" ]  && [ -f "$INSTALL_DIR/lib/libprotobuf.a" ] && [ -f "$INSTALL_DIR/lib/libgrpc.a" ]  && [ -f "$INSTALL_DIR/bin/protoc" ]; then
	
	echo "gRPC is already installed"

else
	
	echo "Install gRPC"
	
git clone -b $(curl -L https://grpc.io/release) https://github.com/grpc/grpc

cd grpc
git submodule update --init

PROTOBUF_CONFIG_OPTS="--prefix=$INSTALL_DIR" make prefix=$INSTALL_DIR  -j
PROTOBUF_CONFIG_OPTS="--prefix=$INSTALL_DIR" sudo make prefix=$INSTALL_DIR install

cd third_party/protobuf
sudo make install

# make clean
fi