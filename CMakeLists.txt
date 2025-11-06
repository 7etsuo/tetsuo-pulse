cmake_minimum_required(VERSION 3.10)
project(socket VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # Enable GNU extensions (_GNU_SOURCE)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -D_GNU_SOURCE -pthread -fno-strict-aliasing -fPIC")
set(CMAKE_C_FLAGS_DEBUG "-g -Og")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Default to Debug build
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Detect platform and select appropriate poll backend
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(POLL_BACKEND "epoll")
    set(POLL_BACKEND_SRC "src/poll/SocketPoll_epoll.c")
    message(STATUS "Building with epoll backend for Linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(POLL_BACKEND "kqueue")
    set(POLL_BACKEND_SRC "src/poll/SocketPoll_kqueue.c")
    message(STATUS "Building with kqueue backend for macOS")
elseif(CMAKE_SYSTEM_NAME MATCHES "BSD")
    set(POLL_BACKEND "kqueue")
    set(POLL_BACKEND_SRC "src/poll/SocketPoll_kqueue.c")
    message(STATUS "Building with kqueue backend for BSD")
else()
    set(POLL_BACKEND "poll")
    set(POLL_BACKEND_SRC "src/poll/SocketPoll_poll.c")
    message(STATUS "Building with poll(2) fallback backend")
endif()

# Collect all source files
set(LIB_SOURCES
    # Core foundation
    src/core/Arena.c
    src/core/Except.c
    src/core/SocketError.c
    src/core/SocketLog.c
    src/core/SocketMetrics.c
    src/core/SocketEvents.c
    
    # Socket core
    src/socket/Socket.c
    src/socket/SocketDgram.c
    src/socket/SocketBuf.c
    src/socket/SocketCommon.c
    
    # DNS module
    src/dns/SocketDNS.c
    
    # Poll module
    src/poll/SocketPoll.c
    ${POLL_BACKEND_SRC}
    
    # Pool module
    src/pool/SocketPool.c
)

# Collect all header files for installation
set(CORE_HEADERS
    include/core/Arena.h
    include/core/Except.h
    include/core/SocketConfig.h
    include/core/SocketError.h
    include/core/SocketLog.h
    include/core/SocketMetrics.h
    include/core/SocketEvents.h
)

set(SOCKET_HEADERS
    include/socket/Socket.h
    include/socket/SocketDgram.h
    include/socket/SocketBuf.h
    include/socket/SocketCommon.h
)

set(DNS_HEADERS
    include/dns/SocketDNS.h
)

set(POLL_HEADERS
    include/poll/SocketPoll.h
    include/poll/SocketPoll_backend.h
)

set(POOL_HEADERS
    include/pool/SocketPool.h
)

set(TEST_HEADERS
    include/test/Test.h
)

# Object library for reuse in tests (avoids static library constructor issues)
add_library(socket_objects OBJECT ${LIB_SOURCES})
target_include_directories(socket_objects PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Static library
add_library(socket_static STATIC $<TARGET_OBJECTS:socket_objects>)
set_target_properties(socket_static PROPERTIES OUTPUT_NAME socket)
target_link_libraries(socket_static pthread)

# Shared library
add_library(socket_shared SHARED $<TARGET_OBJECTS:socket_objects>)
set_target_properties(socket_shared PROPERTIES OUTPUT_NAME socket)
target_link_libraries(socket_shared pthread)

# Custom target to build both libraries (default)
add_custom_target(lib ALL DEPENDS socket_static socket_shared)

# Installation targets (optional)
install(TARGETS socket_static socket_shared
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${CORE_HEADERS} DESTINATION include/socket/core)
install(FILES ${SOCKET_HEADERS} DESTINATION include/socket/socket)
install(FILES ${DNS_HEADERS} DESTINATION include/socket/dns)
install(FILES ${POLL_HEADERS} DESTINATION include/socket/poll)
install(FILES ${POOL_HEADERS} DESTINATION include/socket/pool)
install(FILES ${TEST_HEADERS} DESTINATION include/socket/test)

# Print build configuration
message(STATUS "Socket Library Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C Flags: ${CMAKE_C_FLAGS}")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "  Debug Flags: ${CMAKE_C_FLAGS_DEBUG}")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "  Release Flags: ${CMAKE_C_FLAGS_RELEASE}")
endif()
message(STATUS "  Poll Backend: ${POLL_BACKEND}")

# Enable testing
enable_testing()

# Test framework
add_library(test_framework OBJECT src/test/Test.c)
target_include_directories(test_framework PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Test source files
set(TEST_SOURCES
    test_arena
    test_except
    test_socketerror
    test_socket
    test_socketbuf
    test_socketdgram
    test_socketpoll
    test_socketpool
    test_socketdns
    test_integration
    test_threadsafety
)

# Create test executables (link against object files to preserve constructor attributes)
foreach(test_name ${TEST_SOURCES})
    add_executable(${test_name} src/test/${test_name}.c $<TARGET_OBJECTS:socket_objects> $<TARGET_OBJECTS:test_framework>)
    target_link_libraries(${test_name} pthread)
    target_include_directories(${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Custom target to build all tests
add_custom_target(build_tests ALL DEPENDS ${TEST_SOURCES})

# Print test configuration
message(STATUS "Test Suite Configuration:")
message(STATUS "  Test files: 11")
message(STATUS "  Total tests: 216+")
message(STATUS "  Run with: make test (or ctest)")

