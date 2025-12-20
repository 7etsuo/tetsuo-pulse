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
# =============================================================================

add_executable(example_websocket_client websocket_client.c)
target_link_libraries(example_websocket_client ${EXAMPLE_LIBS})

add_executable(example_websocket_server websocket_server.c)
target_link_libraries(example_websocket_server ${EXAMPLE_LIBS})

# =============================================================================
# Proxy Example
# =============================================================================

add_executable(example_proxy_connect proxy_connect.c)
target_link_libraries(example_proxy_connect ${EXAMPLE_LIBS})

# =============================================================================
# Signal Handling Example
# =============================================================================

add_executable(example_graceful_shutdown graceful_shutdown.c)
target_link_libraries(example_graceful_shutdown ${EXAMPLE_LIBS})

# =============================================================================
# Networking Examples (Core Socket APIs)
# =============================================================================

add_executable(example_tcp_echo_server tcp_echo_server.c)
target_link_libraries(example_tcp_echo_server ${EXAMPLE_LIBS})

add_executable(example_tcp_echo_client tcp_echo_client.c)
target_link_libraries(example_tcp_echo_client ${EXAMPLE_LIBS})

add_executable(example_udp_echo_server udp_echo_server.c)
target_link_libraries(example_udp_echo_server ${EXAMPLE_LIBS})

add_executable(example_udp_echo_client udp_echo_client.c)
target_link_libraries(example_udp_echo_client ${EXAMPLE_LIBS})

# =============================================================================
# DNS Example
# =============================================================================

add_executable(example_dns_lookup dns_lookup.c)
target_link_libraries(example_dns_lookup ${EXAMPLE_LIBS})

# =============================================================================
# TLS Example (conditional)
# =============================================================================

if(OPENSSL_FOUND)
    add_executable(example_tls_client tls_client.c)
    target_link_libraries(example_tls_client ${EXAMPLE_LIBS})
endif()

# =============================================================================
# Connection Pool Example
# =============================================================================

add_executable(example_connection_pool connection_pool.c)
target_link_libraries(example_connection_pool ${EXAMPLE_LIBS})

# =============================================================================
# Simple API Examples (subdirectory)
# =============================================================================

add_subdirectory(simple)

# =============================================================================
# Installation (optional)
# =============================================================================

# Don't install examples by default - they're for learning/testing

