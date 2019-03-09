# Changelog

## Version 0.3

### Improvements

-   Replace SConstruct by CMake to build the project.
-   Package the code as a library.
-   Add unit tests (with sanitizers support) and code coverage.
-   Use [`spdlog`](https://github.com/gabime/spdlog) instead of a custom logging system.
-   Cleanup some APIs.
-   Replace the library-defined `TokenTree` class by the range-constrained pseudo-random function implementation introduced in `crypto-tk` v0.3.
-   Introduce new server runner classes (`DianaServerRunner` and `SophosServerRunner`) to improve the management of the different components of a runner, namely the service and the gRPC server.
-   Added contribution guidelines.
-   Improve the bash scripts of the project.
-   Enable `-Werror` by default when compiling.


### Fixes

-   Fix numerous issues found using static analysis tools (`clang-tidy`, `cppcheck`)

## Version 0.2

First stable and usable version:

-   Implementation of Sophos
-   Implementation of Diana
-   (Partial) implementation of Janus
