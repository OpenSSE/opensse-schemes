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

# install protobuf
# we have to do it that way because we need to cache the dependencies
cd third_party/protobuf

autoreconf -f -i -Wall,no-obsolete && ./configure --prefix=$INSTALL_DIR && make
sudo make install
sudo ldcondfig

cd ../..


make prefix=$INSTALL_DIR -j2
sudo make prefix=$INSTALL_DIR install
make clean
fi