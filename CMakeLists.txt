cmake_minimum_required(VERSION 3.1)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/externals/CMake-codecov/cmake")

# Build in Debug mode by default
set(default_build_type "Debug")

# Options
option(opensse_ENABLE_WALL "Enable all warnings" ON)
option(opensse_ENABLE_WEXTRA "Enable extra warnings" ON)
option(opensse_ENABLE_WERROR "Make all warnings into errors" OFF)
option(
    opensse_OPTIMIZE_FOR_NATIVE_ARCH
    "Enable compiler optimizations for the native processor architecture (if available)"
    ON
)

# Load modules

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# enable code coverage
find_package(codecov)
list(APPEND LCOV_REMOVE_PATTERNS '${CMAKE_CURRENT_SOURCE_DIR}/test/*' '${CMAKE_CURRENT_SOURCE_DIR}/externals/*' '${CMAKE_CURRENT_SOURCE_DIR}/third_party/*' '*.pb.h')

# We use CMake's integrated testing features
enable_testing()

if(opensse_ENABLE_WALL)
    check_cxx_compiler_flag("-Wall" COMPILER_OPT_WALL_SUPPORTED)
    if(COMPILER_OPT_WALL_SUPPORTED)
        add_compile_options(-Wall)
    endif()
endif()

if(opensse_ENABLE_WEXTRA)
    check_cxx_compiler_flag("-Wextra" COMPILER_OPT_WEXTRA_SUPPORTED)
    if(COMPILER_OPT_WEXTRA_SUPPORTED)
        add_compile_options(-Wextra)
    endif()
endif()

if(opensse_ENABLE_WERROR)
    check_cxx_compiler_flag("-Werror" COMPILER_OPT_WERROR_SUPPORTED)
    if(COMPILER_OPT_WERROR_SUPPORTED)
        add_compile_options(-Werror)
    endif()
endif()

if(opensse_OPTIMIZE_FOR_NATIVE_ARCH)
    check_cxx_compiler_flag("-march=native" COMPILER_OPT_ARCH_NATIVE_SUPPORTED)
    if(COMPILER_OPT_ARCH_NATIVE_SUPPORTED)
        add_compile_options(-march=native)
    endif()
endif()

# Go for external dependencies
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(RocksDB REQUIRED)

find_package(Protobuf)
find_package(GRPC)
message(STATUS "Protoc path: " ${Protobuf_PROTOC_EXECUTABLE})
message(STATUS "GRPC plugin path: " ${GRPC_CPP_PLUGIN})

add_subdirectory(third_party/crypto/src)
add_subdirectory(third_party/db-parser/src)

add_subdirectory(lib)
add_coverage(schemes)
add_coverage(runners)


add_subdirectory(src)

# Build googletest for the tests
add_subdirectory(externals/googletest)
add_subdirectory(test)
add_coverage(check)

coverage_evaluate()

