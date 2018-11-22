#!/bin/sh
set -ex

INSTALL_DIR=$HOME/deps

if [ -d "$INSTALL_DIR/include/rocksdb" ] && [ -f "$INSTALL_DIR/lib/librocksdb.a" ]; then
	echo "RocksDB is already installed"
else
	
	echo "Install RocksDB"
	
	git clone https://github.com/facebook/rocksdb.git
	cd rocksdb

	make INSTALL_PATH=$INSTALL_DIR shared_lib -j
	sudo make INSTALL_PATH=$INSTALL_DIR install
	make clean
fi