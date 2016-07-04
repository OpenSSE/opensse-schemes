# Sophos

Sophos is a forward private Symmetric Searchable Encryption scheme, with optimal asymptotic performance.
This repo holds a C++ implementation of this scheme.


# Pre-requisites
## All
Sophos' dependencies need a compiler supporting C++14 (Sophos' core codebase doesn't). It has been successfully built and tested on Ubuntu 14 LTS using both clang 3.6 and gcc 4.9.3 and on Mac OS X.10 using clang 7.0.0

## Linux

```sh
 $ [sudo] apt-get install build-essential autoconf libtool yasm openssl scons
```

## Mac OS X

```sh
 $ [sudo] xcode-select --install
```

If you still haven't, you should get [Homebrew](http://brew.sh/). 
You will actually need it to install dependencies: 

```sh
 $ brew install automake autoconf yasm openssl scons
```

## Installing gRPC
Sophos uses Google's [gRPC](http://grpc.io) as its RPC machinery.
Follow the instructions to install gRPC's C++ binding (see [here](https://github.com/grpc/grpc/tree/release-0_14/src/cpp) for the 0.14 release).

## Installing RocksDB
Sophos uses Facebook's [RocksDB](http://rocksdb.org) as its storage engine. Sophos has been tested with the 4.9 release, which is available via git:

```sh
 $ git clone -b 4.9.fb https://github.com/facebook/rocksdb.git
```
Running ```[sudo] make install``` will compile the source and copy the library and headers in ```/usr/local``` by default. To set an other install path, set the ```INSTALL_PATH``` variable:

```sh
 $ export INSTALL_PATH=/path/to/rocksdb
```



## Getting the code
The code is available *via* git:

```sh
 $ git clone https://gitlab.com/sse/sophos.git
```

You will also need to fetch the submodules:

```sh
 $ git submodule update --init
```


# Building

Building is done through [SConstruct](http://www.scons.org). 

To build the submodules, you can either run

```sh
 $ scons deps
```
or do it by hand:

```sh
 $ (cd third_party/crypto; scons lib); (cd third_party/ssdmap; scons lib); (cd third_party/db-parser; scons lib); 
```

Then, to build Sophos itself, just enter in your terminal

```sh
 $ scons 
```

## Configuration

The SConstruct files default values might not fit your system. For example, you might want to choose a specific C++ compiler.
You can easily change these default values without modifying the SConstruct file itself. Instead, create a file called `config.scons` and change the values in this file. For example, say you want to use clang instead of your default gcc compiler and you placed the headers and shared library for gRPC in some directories that are not in the compiler's include path, say
`~/grpc/include` and `~/grpc/lib`. Then you can use the following configuration file:

```python
Import('*')

env['CC'] = 'clang'
env['CXX'] = 'clang++'

env.Append(CPPPATH=['~/grpc/include'])
env.Append(LIBPATH=['~/grpc/lib'])
```

# Contributors

Unless otherwise stated, the code has been written by [Raphael Bost](http://people.irisa.fr/Raphael.Bost/).

# Licensing

Sophos is licensed under the [GNU Affero General Public License v3](http://www.gnu.org/licenses/agpl.html).

![AGPL](http://www.gnu.org/graphics/agplv3-88x31.png)

