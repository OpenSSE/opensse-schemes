add_executable(sophos_client sophos_client.cpp)
target_link_libraries(sophos_client OpenSSE::runners)
add_executable(sophos_server sophos_server.cpp)
target_link_libraries(sophos_server OpenSSE::runners)

add_executable(diana_client diana_client.cpp)
target_link_libraries(diana_client OpenSSE::runners)
add_executable(diana_server diana_server.cpp)
target_link_libraries(diana_server OpenSSE::runners)
