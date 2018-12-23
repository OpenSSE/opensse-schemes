#!/bin/sh

cd third_party/crypto/install_dependencies || exit

# install relic
./install_relic_easy.sh

# install libsodium
./install_libsodium.sh