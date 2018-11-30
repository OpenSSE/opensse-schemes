add_executable(sophos_client sophos_client.cpp)
target_link_libraries(sophos_client OpenSSE::runners)
add_executable(sophos_server sophos_server.cpp)
target_link_libraries(sophos_server OpenSSE::runners)
list(APPEND runner_bins sophos_client sophos_server)

add_executable(diana_client diana_client.cpp)
target_link_libraries(diana_client OpenSSE::runners)
add_executable(diana_server diana_server.cpp)
target_link_libraries(diana_server OpenSSE::runners)
list(APPEND runner_bins diana_client diana_server)

# Propagate to the parent scope
set(runner_bins ${runner_bins} PARENT_SCOPE)