#!/bin/sh

set -ex

version=3.19
build=3
CMAKE_INSTALL_DIR=$HOME/installs/cmake
mkdir ~/temp
cd ~/temp
wget https://cmake.org/files/v$version/cmake-$version.$build-Linux-x86_64.tar.gz
tar xf cmake-$version.$build-Linux-x86_64.tar.gz
mkdir -p $CMAKE_INSTALL_DIR
mv cmake-$version.$build-Linux-x86_64/* $CMAKE_INSTALL_DIR/
#sh cmake-$version.$build-Linux-x86_64.sh --prefix=$HOME/installs/cmake
which cmake