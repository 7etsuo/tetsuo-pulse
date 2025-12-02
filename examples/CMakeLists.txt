# =============================================================================
# Socket Library Examples - CMake Configuration
# =============================================================================
# Build with: cmake -DBUILD_EXAMPLES=ON ..
# =============================================================================

# All examples link against the socket library (static for simplicity)
set(EXAMPLE_LIBS socket_static)

# Add OpenSSL if TLS is enabled
if(OPENSSL_FOUND)
    list(APPEND EXAMPLE_LIBS OpenSSL::SSL OpenSSL::Crypto)
endif()

# Add zlib if compression is enabled
if(ZLIB_FOUND)
    list(APPEND EXAMPLE_LIBS ${ZLIB_LIBRARIES})
endif()

# Add pthread
list(APPEND EXAMPLE_LIBS pthread)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# =============================================================================
# HTTP Examples
# =============================================================================

add_executable(example_http_get http_get.c)
target_link_libraries(example_http_get ${EXAMPLE_LIBS})

add_executable(example_http_post http_post.c)
target_link_libraries(example_http_post ${EXAMPLE_LIBS})

add_executable(example_http2_client http2_client.c)
target_link_libraries(example_http2_client ${EXAMPLE_LIBS})

add_executable(example_http_server http_server.c)
target_link_libraries(example_http_server ${EXAMPLE_LIBS})

# =============================================================================
# WebSocket Examples
# Note: WebSocket recv API not fully implemented yet - examples disabled
# =============================================================================

# TODO: Enable when SocketWS_recv_message and SocketWS_recv_available are implemented
# add_executable(example_websocket_client websocket_client.c)
# target_link_libraries(example_websocket_client ${EXAMPLE_LIBS})

# add_executable(example_websocket_server websocket_server.c)
# target_link_libraries(example_websocket_server ${EXAMPLE_LIBS})

# =============================================================================
# Proxy Example
# =============================================================================

add_executable(example_proxy_connect proxy_connect.c)
target_link_libraries(example_proxy_connect ${EXAMPLE_LIBS})

# =============================================================================
# Installation (optional)
# =============================================================================

# Don't install examples by default - they're for learning/testing

