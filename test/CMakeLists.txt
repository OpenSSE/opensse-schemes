add_executable(sophos_debug debug_sophos.cpp)
target_link_libraries(sophos_debug OpenSSE::schemes)
add_executable(diana_debug debug_diana.cpp)
target_link_libraries(diana_debug OpenSSE::schemes)
add_executable(janus_debug debug_janus.cpp)
target_link_libraries(janus_debug OpenSSE::schemes)

if(${CMAKE_VERSION} VERSION_GREATER "3.10.0") 
    include(GoogleTest)
endif()

add_executable(test test.cpp sophos.cpp)
target_link_libraries(test gtest OpenSSE::schemes)

if(${CMAKE_VERSION} VERSION_GREATER "3.10.0") 
    gtest_discover_tests(test)
else()
    add_test(test_sophos test)
endif()

