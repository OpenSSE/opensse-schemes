# OpenSSE Schemes

Implementation of SSE schemes. For now, the repo includes a C++ implementation of Sophos, Diana and Janus. Sophos has been described in *[Σoφoς – Forward Secure Searchable Encryption](https://eprint.iacr.org/2016/728.pdf)* by Bost, and Diana and Janus in *[Forward and Backward Private Searchable Encryption from Constrained Cryptographic Primitives](https://eprint.iacr.org/2017/805.pdf)* by Bost, Minaud and Ohrimenko.


# Pre-requisites
## All
OpenSSE's schemes implementation dependencies need a compiler supporting C++14 (although the core codebase doesn't). It has been successfully built and tested on Ubuntu 14 LTS using both clang 3.6 and gcc 4.9.3 and on Mac OS X.10 using clang 7.0.0

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
OpenSSE uses Google's [gRPC](http://grpc.io) as its RPC machinery.
Follow the instructions to install gRPC's C++ binding (see [here](https://github.com/grpc/grpc/tree/release-0_14/src/cpp) for the 0.14 release).

## Installing RocksDB
OpenSSE uses Facebook's [RocksDB](http://rocksdb.org) as its storage engine. OpenSSE has been tested with the 5.7 release. See the [installation guide](https://github.com/facebook/rocksdb/blob/master/INSTALL.md).

Note that on OS X, RocksDB ca be installed *via* Homebrew:

```sh
brew install rocksdb
```


## Getting the code
The code is available *via* git:

```sh
 $ git clone https://github.com/OpenSSE/opensse-schemes.git
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

Then, to build the code itself, just enter in your terminal

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

# Usage

This repository provides implementations of SSE as a proof of concept, and cannot really be used for real sensitive applications. In particular, the cryptographic toolkit most probably has many implementation flaws.

The building script builds basic test programs for Sophos, Diana and Janus (respectively `sophos_debug`, `diana_debug`, and `janus_debug`), that are of no use *per se*, and two pairs of client/server programs for Sophos and Diana (`sophos_server` and `sophos_client` for Sophos, and `diana_server` and `diana_client` for Diana). These are the ones you are looking for.

## Client
The clients usage is as follows
`sophos_client [-b client.db] [-l inverted_index.json] [-p] [-r count] [-q] [keyword1 [... keywordn]]`

* `-b client.db` : use file as the client database (test.csdb by default)


* `-l file.json` : load the reversed index file.json and add it to the database. file.json is a JSON file with the following structure : 
```json
{
	"keyword1" : [1,2,3,4],
	"keyword2": [11,22,33,44,55]
}
```
In the repo, `inverted_index.json` is an example of such file.
* `-p` : print stats about the loaded database (number of keywords)
* `-r count` : generate a database with count entries. Look at the aux/db_generator.* files to see how such databases are generated
* `keyword1 … keywordn` : search queries with keyword1 … keywordn. 


## Server
The servers usage is as follows
`sophos_server [-b server.db] [-s]`

* `-b server.db` : use file as the server database (test.ssdb by default)
* `-s` : use synchronous searches (when searching, the server retrieves all the results before sending them to the client. By default, results are sent once retrieved). I used this option for the benchmarks without RPC.



# Contributors

Unless otherwise stated, the code has been written by [Raphael Bost](http://people.irisa.fr/Raphael.Bost/).

# Licensing

OpenSSE Schemes is licensed under the [GNU Affero General Public License v3](http://www.gnu.org/licenses/agpl.html).

![AGPL](http://www.gnu.org/graphics/agplv3-88x31.png)

