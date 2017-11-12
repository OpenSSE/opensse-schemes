#!/bin/sh
set -ex

cd third_party/crypto

# get Boost
wget -q http://sourceforge.net/projects/boost/files/boost/1.60.0/boost_1_60_0.tar.gz;
tar xf boost_1_60_0.tar.gz
mv boost_1_60_0/boost src/.

# install relic
./install_relic.sh

# install libsodium
./install_libsodium.sh