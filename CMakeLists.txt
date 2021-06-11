cmake_minimum_required(VERSION 3.5.1)
project(opensse-schemes VERSION 0.3 DESCRIPTION "OpenSSE's Schemes Implementation")


list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_SOURCE_DIR}/externals/CMake-codecov/cmake"
)
list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_SOURCE_DIR}/externals/sanitizers-cmake/cmake"
)

# Build in Debug mode by default
set(default_build_type "Debug")

# Options
option(opensse_ENABLE_WALL "Enable all warnings" ON)
option(opensse_ENABLE_WEXTRA "Enable extra warnings" ON)
option(opensse_ENABLE_WERROR "Make all warnings into errors" ON)
option(
    opensse_OPTIMIZE_FOR_NATIVE_ARCH
    "Enable compiler optimizations for the native processor architecture (if available)"
    ON
)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Load modules

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# enable code coverage
find_package(codecov)
list(
    APPEND
    LCOV_REMOVE_PATTERNS
    '${CMAKE_CURRENT_SOURCE_DIR}/test/*'
    '${CMAKE_CURRENT_SOURCE_DIR}/externals/*'
    '${CMAKE_CURRENT_SOURCE_DIR}/third_party/*'
    '*/deps/*' # For Travis
    '*/usr/*' # For Travis
    '*.pb.h'
)

# Find Sanitizers
find_package(Sanitizers)

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
        add_compile_options(
            -Werror -Wno-error=unknown-pragmas -Wno-error=unused-function
        )
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

# Import spdlog
add_subdirectory(externals/spdlog)

# Disable memory locks because of race conditions.
set(ENABLE_MEMORY_LOCK
    OFF
    CACHE BOOL "Disable Memory Lock" FORCE
)
add_subdirectory(third_party/crypto/src)

add_subdirectory(third_party/db-parser/src)

add_subdirectory(lib)
add_coverage(schemes)
add_coverage(runners)
add_sanitizers(schemes)
add_sanitizers(runners)

add_subdirectory(src)

foreach(runner ${runner_bins})
    add_sanitizers(${runner})
endforeach(runner ${runner_bins})

# Build googletest for the tests
set(BUILD_GMOCK
    OFF
    CACHE BOOL "Disable GMock" FORCE
)
add_subdirectory(externals/googletest)
add_subdirectory(test)
add_coverage(check)
add_sanitizers(check)
add_sanitizers(sophos_debug)
add_sanitizers(diana_debug)
add_sanitizers(janus_debug)
# add_sanitizers(oceanus_debug)
add_sanitizers(tethys_core_debug)
add_sanitizers(tethys_debug)
add_sanitizers(pluto_debug)

coverage_evaluate()
