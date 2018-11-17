add_library(
    schemes
    SHARED
    utils/logger.cpp
    utils/rocksdb_wrapper.cpp
    utils/utils.cpp
    sophos/sophos_common.cpp
    sophos/sophos_client.cpp
    sophos/sophos_server.cpp
    diana/diana_common.cpp
    diana/token_tree.cpp
    janus/janus_client.cpp
    janus/janus_server.cpp
)
# Add an alias
add_library(OpenSSE::schemes ALIAS schemes)

# Generate PIC for the library
set_target_properties(schemes PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_features(
    schemes
    PUBLIC
    cxx_auto_type
    cxx_nullptr
    cxx_constexpr
    cxx_defaulted_functions
    cxx_deleted_functions
    cxx_extern_templates
    cxx_noexcept
    cxx_static_assert
    cxx_thread_local
    PRIVATE
    cxx_lambdas
)

target_include_directories(
    schemes
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/sse/schemes
    PRIVATE ${ROCKSDB_INCLUDE_DIRS}
)

target_link_libraries(
    schemes
    OpenSSE::crypto
    OpenSSE::dbparser
    ${ROCKSDB_LIBRARIES}
)
