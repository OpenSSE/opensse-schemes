#! /bin/bash
set -ex
mkdir -p build
cd build
CMAKE_PREFIX_PATH=${HOME}/deps cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ..
VERBOSE=1 cmake --build . --clean-first
