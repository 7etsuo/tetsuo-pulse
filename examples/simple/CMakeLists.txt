# =============================================================================
# Simple API Examples - CMake Configuration
# =============================================================================
# These examples use the Simple (return-code based) API layer.
# Build with: cmake -DBUILD_EXAMPLES=ON ..
# =============================================================================

# Inherit EXAMPLE_LIBS from parent
# (socket_static, OpenSSL, pthread, etc.)

# =============================================================================
# curl_clone - Minimal curl-like HTTP client
# =============================================================================
# Demonstrates:
#   - HTTP GET/POST/PUT/DELETE
#   - Custom headers
#   - Redirect following
#   - File output
#   - Basic auth (structure, not fully wired yet)

add_executable(simple_curl_clone curl_clone.c)
target_link_libraries(simple_curl_clone ${EXAMPLE_LIBS})

# =============================================================================
# Future examples (uncomment as implemented):
# =============================================================================

# add_executable(simple_chat_room chat_room.c)
# target_link_libraries(simple_chat_room ${EXAMPLE_LIBS})

# add_executable(simple_tcp_relay tcp_relay.c)
# target_link_libraries(simple_tcp_relay ${EXAMPLE_LIBS})

# add_executable(simple_webhook_tester webhook_tester.c)
# target_link_libraries(simple_webhook_tester ${EXAMPLE_LIBS})

# add_executable(simple_reverse_proxy reverse_proxy.c)
# target_link_libraries(simple_reverse_proxy ${EXAMPLE_LIBS})
