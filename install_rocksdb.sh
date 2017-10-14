#!/bin/sh
set -ex

git clone https://github.com/facebook/rocksdb.git
cd rocksdb

make static_lib
sudo make install