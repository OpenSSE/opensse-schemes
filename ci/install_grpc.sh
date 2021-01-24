#!/bin/sh

INSTALL_DIR=$HOME/deps

bold=$(tput bold)
normal=$(tput sgr0)
green=$(tput setaf 2)


if [ -d "$INSTALL_DIR/include/google" ] && [ -d "$INSTALL_DIR/include/grpc" ] && [ -d "$INSTALL_DIR/include/grpcpp" ]  && [ -f "$INSTALL_DIR/lib/libprotobuf.a" ] && [ -f "$INSTALL_DIR/lib/libgrpc.a" ]  && [ -f "$INSTALL_DIR/bin/protoc" ]; then
	echo "${bold}${green}gRPC is already installed${normal}"
else
	echo "${bold}${green}Install gRPC${normal}"

	set -ex

	git clone -b v1.34.0 --single-branch --depth 1 https://github.com/grpc/grpc

	cd grpc
	git submodule update --init --recursive

	mkdir -p cmake/build
	cd cmake/build
	cmake ../.. -DCMAKE_BUILD_TYPE=Release -DgRPC_INSTALL=ON -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"
	
	make -j4
	make install

	# PROTOBUF_CONFIG_OPTS="--prefix=$INSTALL_DIR" make prefix="$INSTALL_DIR"  -j4
	# PROTOBUF_CONFIG_OPTS="--prefix=$INSTALL_DIR" sudo -E make prefix="$INSTALL_DIR" install

	# cd third_party/protobuf
	# sudo -E make install

	# make clean
fi