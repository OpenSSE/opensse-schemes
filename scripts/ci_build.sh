#! /bin/bash
set -ex
mkdir -p build
cd build
CMAKE_PREFIX_PATH=${HOME}/deps cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ..
# VERBOSE=1 cmake --build . --clean-first

#Show the first 80 lines of the make file
head -n 80 lib/CMakeFiles/runners.dir/build.make
make