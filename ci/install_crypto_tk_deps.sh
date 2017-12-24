#!/bin/sh
set -ex

cd third_party/crypto/install_dependencies

# install relic
./install_relic_ubuntu_14_easy.sh

# install libsodium
./install_libsodium.sh