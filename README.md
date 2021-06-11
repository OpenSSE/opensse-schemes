# OpenSSE Schemes

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![build status](https://badges.herokuapp.com/travis/OpenSSE/opensse-schemes?branch=master&label=build&env=COMPILER=gcc)](https://travis-ci.org/OpenSSE/opensse-schemes)
[![static analysis](https://badges.herokuapp.com/travis/OpenSSE/opensse-schemes?branch=master&label=static%20analysis&env=STATIC_ANALYSIS=true)](https://travis-ci.org/OpenSSE/opensse-schemes)
[![Coverage Status](https://coveralls.io/repos/github/OpenSSE/opensse-schemes/badge.svg?branch=master)](https://coveralls.io/github/OpenSSE/opensse-schemes?branch=master)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/cb6959a0c8db41629fdcf94424a4290d)](https://www.codacy.com/gh/OpenSSE/opensse-schemes/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=OpenSSE/opensse-schemes&amp;utm_campaign=Badge_Grade)

Implementation of SSE schemes. For now, the repo includes a C++ implementation of the following schemes: 

| Name           | Comments                                                                                                                                                                   | Authors                                                                     | Reference               |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------- |
| Σoφoς (Sophos) | First forward-private SSE scheme. Optimal asymptotic performance, but slow in practice because of its use of RSA.                                                          | [Bost][webpage_bost]                                                        | _[\[1\]][sophos_link]_  |
| Diana          | Very fast (practical) forward-private scheme, using only symetric cryptography.                                                                                            | Bost, [Minaud][webpage_minaud] and [Ohrimenko][webpage_ohrimenko]           | _[\[2\]][bmo_link]_     |
| Janus          | First 'practical' backward-private scheme, based on puncturable encryption. In practice, very slow when the number of deletions grows.                                     | Bost, Minaud and Ohrimenko                                                  | _[\[2\]][bmo_link]_     |
| Tethys         | Static scheme designed for flash storage. Best in class throughput (as of 2021) and small ciphertext expansion, but with building time that can become prohibitively high. | [Bossuat][webpage_bossuat], Bost, [Fouque][webpage_fouque], Minaud, Reichle | _[\[3\]][sse_ssd_link]_ |
| Pluto          | Practical improvement over Tethys for the setup time, but at the cost of an increased ciphertext expansion.                                                                | Bossuat, Bost, Fouque, Minaud, Reichle                                      | _[\[3\]][sse_ssd_link]_ |

## References
| Article                                                                                                          | Authors                                                                     |
| ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| \[1\] _[Σoφoς – Forward Secure Searchable Encryption][sophos_link]_                                              | [Bost][webpage_bost]                                                        |
| \[2\] _[Forward and Backward Private Searchable Encryption from Constrained Cryptographic Primitives][bmo_link]_ | Bost, [Minaud][webpage_minaud] and [Ohrimenko][webpage_ohrimenko]           |
| \[3\] _[SSE and SSD: Page-Efficient Searchable Symmetric Encryption][sse_ssd_link]_                              | [Bossuat][webpage_bossuat], Bost, [Fouque][webpage_fouque], Minaud, Reichle |

## Pre-requisites

### All

OpenSSE's schemes implementation dependencies need a compiler supporting C++14 (although the core codebase doesn't). It has been successfully built and tested on Ubuntu 14 LTS using both clang 3.6 and gcc 4.9.3 and on Mac OS X.10 using clang 7.0.0

#### The Cryptographic Toolkit

This repository uses a cryptographic toolkit specially designed for searchable encryption applications: `crypto-tk`.
This toolkit is integrated as a git submodule, and will be automatically compiled when building the schemes.
However, it has its own set of dependencies, and you should make sure they are available on your computer.
Take a look at the [build instructions](https://github.com/OpenSSE/crypto-tk#building) for detailed information.

### Linux

```sh
 [sudo] apt-get install build-essential autoconf libtool yasm openssl cmake libaio-dev
```

The `libaio-dev` dependency is optional. However, if you are willing to use the Tethys and/or the Pluto schemes, we strongly advise you to install it, for performance's sake.

#### Installing gRPC

OpenSSE uses Google's [gRPC](http://grpc.io) as its RPC machinery.
On Linux, there is, for now, no other way than installing gRPC from source.
The procedure is described [here](https://github.com/grpc/grpc/blob/master/BUILDING.md).
Note that OpenSSE has been tested with gRPC v1.34.

#### Installing RocksDB

OpenSSE uses Facebook's [RocksDB](http://rocksdb.org) as its storage engine. See the [installation guide](https://github.com/facebook/rocksdb/blob/master/INSTALL.md).
Note that the build system currently used by this project does not support static builds of RocksDB. If you see linker errors involving compression libraries (`libzstd`, `libz4`, `libsnappy`, ...), it probably comes from OpenSSE linking against RocksDB's static library.

### Mac OS X

```sh
 [sudo] xcode-select --install
```

If you still haven't, you should get [Homebrew](http://brew.sh/).
You can then directly install all the dependencies using Homebrew:

```sh
brew install automake autoconf yasm openssl cmake grpc rocksdb
```

### Getting the code

The code is available _via_ git:

```sh
git clone https://github.com/OpenSSE/opensse-schemes.git
```

You will also need to fetch the submodules (this might take a while):

```sh
git submodule update --init --recursive
```

## Building

Building is done using CMake. The minimum required version is CMake 3.1.

Then, to build the code itself, just enter in your terminal

```sh
mkdir build && cd build
cmake ..
make
```

### Build Configuration and Options

As the library builds using CMake, the configuration is highly configurable.
Like other CMake-based projects, options are set by passing `-DOPTION_NAME=value` to the `cmake` command.
For example, for a debug build, use `-DCMAKE_BUILD_TYPE=Debug`.
Also, you can change the compiler used for the project by setting the `CC` and `CXX` environment variables.
For example, if you wish to use Clang, you can set the project up with the following command
`CC=clang CXX=clang++ cmake ..`.

#### Options

-   `ENABLE_COVERAGE=On|Off`: Respectively enables and disable the code coverage functionalities. Disabled by default.
-   `SANITIZE_ADDRESS=On|Off`: Compiles the library with [AddressSanitizer (ASan)](https://github.com/google/sanitizers/wiki/AddressSanitizer) when set to `On`. Great to check for stack/heap buffer overflows, memory leaks, ... Disabled by default.
-   `SANITIZE_UNDEFINED=On|Off`: When set to `On`, compiles the library with [UndefinedBehaviorSanitizer (UBSan)](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html). UBSan detects undefined behavior at runtime in your code. Disabled by default. 
-   `opensse_ENABLE_WALL=On|Off`: Toggles the `-Wall` compiler option. On by default
-   `opensse_ENABLE_WEXTRA=On|Off`: Toggles the `-Wextra` compiler option. On by default
-   `opensse_ENABLE_WERROR=On|Off`: Toggles the `-Werror` compiler option to turn all warnings into errors. On by default
-   `CMAKE_BUILD_TYPE`: Sets the build type. See [CMake's documentation](https://cmake.org/cmake/help/v3.12/variable/CMAKE_BUILD_TYPE.html) for more details. The `Debug` build type is used by default. Use `Release` for an optimized build.

To see all the available options, and interactively edit them, you can also use the `ccmake` tool.

For more information about how to use CMake, take a look at [CMake's FAQ](https://gitlab.kitware.com/cmake/community/wikis/FAQ), or at the [documentation](https://cmake.org/cmake/help/v3.0/index.html).

In this project, CMake can also be used to configure the cryptographic toolkit. See [`crypto-tk`'s documentation](https://github.com/OpenSSE/crypto-tk#options) for details and configuration points.

## Usage

This repository provides implementations of SSE as a proof of concept, and cannot really be used for real sensitive applications. In particular, the cryptographic toolkit most probably has many implementation flaws.

The building script builds basic test programs for Sophos, Diana and Janus (respectively `sophos_debug`, `diana_debug`, and `janus_debug`), that are of no use _per se_, and two pairs of client/server programs for Sophos and Diana (`sophos_server` and `sophos_client` for Sophos, and `diana_server` and `diana_client` for Diana). These are the ones you are looking for.

### Client

The clients usage is as follows
`sophos_client [-b client.db] [-l inverted_index.json] [-p] [-r count] [-q] [keyword1 [... keywordn]]`

-   `-b client.db` : use file as the client database (test.csdb by default)
-   `-l file.json` : load the reversed index file.json and add it to the database. file.json is a JSON file with the following structure :
```json
{
	"keyword1" : [1,2,3,4],
	"keyword2": [11,22,33,44,55]
}
```
In the repo, `inverted_index.json` is an example of such file.
-   `-p` : print stats about the loaded database (number of keywords)
-   `-r count` : generate a database with count entries. Look at the aux/db_generator.\* files to see how such databases are generated
-   `keyword1 … keywordn` : search queries with keyword1 … keywordn.

### Server

The servers usage is as follows
`sophos_server [-b server.db] [-s]`

-   `-b server.db` : use file as the server database (test.ssdb by default)
-   `-s` : use synchronous searches (when searching, the server retrieves all the results before sending them to the client. By default, results are sent once retrieved). I used this option for the benchmarks without RPC.

## Contributors

Unless otherwise stated, the code has been written by [Raphael Bost](https://raphael.bost.fyi).

## Licensing

OpenSSE Schemes is licensed under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl.html).

![AGPL](https://www.gnu.org/graphics/agplv3-88x31.png)

<!-- links -->

[sophos_link]: https://eprint.iacr.org/2016/728.pdf "Sophos"
[bmo_link]: https://eprint.iacr.org/2017/805.pdf "Diana & Janus"
[sse_ssd_link]: https://eprint.iacr.org/2021/716.pdf "Tethys & Pluto"

[webpage_bossuat]: https://people.irisa.fr/Angele.Bossuat/ "A. Bossuat"
[webpage_bost]: https://raphael.bost.fyi "R. Bost"
[webpage_fouque]: https://www.di.ens.fr/~fouque/ "P.-A. Fouque"
[webpage_minaud]: https://www.di.ens.fr/~bminaud "B. Minaud"
[webpage_ohrimenko]: https://people.eng.unimelb.edu.au/oohrimenko/ "O. Ohrimenko"
