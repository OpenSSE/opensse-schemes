#!/bin/sh
set -ex

if [ -d "$HOME/deps/include/rocksdb" ] && [ -f "$HOME/deps/lib/librocksdb.a" ]; then
	echo "RocksDB is already installed"
else
	
	echo "Install RocksDB"
	
	git clone https://github.com/facebook/rocksdb.git
	cd rocksdb

	make INSTALL_PATH=$HOME/deps static_lib -j2
	sudo make INSTALL_PATH=$HOME/deps install
	make clean
fi