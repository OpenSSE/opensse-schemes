
set(utils_SOURCE utils/logger.cpp
                 utils/rocksdb_wrapper.cpp
                 utils/utils.cpp)

add_executable(sophos_debug sophos/sophos_common.cpp 
                            sophos/sophos_client.cpp 
                            sophos/sophos_server.cpp
                            ../test_sophos.cpp
                            ${utils_SOURCE})

target_include_directories(sophos_debug PUBLIC .)
target_include_directories(sophos_debug PRIVATE ${ROCKSDB_INCLUDE_DIRS})
target_link_libraries(sophos_debug OpenSSE::crypto ${ROCKSDB_LIBRARIES})

add_executable(diana_debug diana/diana_common.cpp 
                           diana/token_tree.cpp
                           ../test_diana.cpp
                           ${utils_SOURCE})

target_include_directories(diana_debug PUBLIC .)
target_include_directories(diana_debug PRIVATE ${ROCKSDB_INCLUDE_DIRS})
target_link_libraries(diana_debug OpenSSE::crypto OpenSSE::dbparser ${ROCKSDB_LIBRARIES})

add_executable(janus_debug diana/diana_common.cpp 
                           diana/token_tree.cpp
                           janus/janus_client.cpp
                           janus/janus_server.cpp
                           ../test_janus.cpp
                           ${utils_SOURCE})

target_include_directories(janus_debug PUBLIC .)
target_include_directories(janus_debug PRIVATE ${ROCKSDB_INCLUDE_DIRS})
target_link_libraries(janus_debug OpenSSE::crypto OpenSSE::dbparser ${ROCKSDB_LIBRARIES})




# Make sure to compile with C++11

target_compile_features(sophos_debug
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