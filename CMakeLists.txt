cmake_minimum_required(VERSION 3.10)
project(socket VERSION 1.0.0 LANGUAGES C)

# Generate compile_commands.json for IDE integration (clangd)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # Enable GNU extensions (_GNU_SOURCE)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-variable -D_GNU_SOURCE -pthread -fno-strict-aliasing -fPIC")
set(CMAKE_C_FLAGS_DEBUG "-g -Og")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Sanitizer options for debugging memory/undefined behavior issues
option(ENABLE_ASAN "Enable AddressSanitizer (ASan)" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer (UBSan)" OFF)
option(ENABLE_SANITIZERS "Enable both ASan and UBSan" OFF)

# If ENABLE_SANITIZERS is ON, enable both
if(ENABLE_SANITIZERS)
    set(ENABLE_ASAN ON)
    set(ENABLE_UBSAN ON)
endif()

# AddressSanitizer flags
if(ENABLE_ASAN)
    message(STATUS "AddressSanitizer (ASan) enabled")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
endif()

# UndefinedBehaviorSanitizer flags
if(ENABLE_UBSAN)
    message(STATUS "UndefinedBehaviorSanitizer (UBSan) enabled")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=undefined")
endif()

# Code coverage option
option(ENABLE_COVERAGE "Enable code coverage with gcov" OFF)

if(ENABLE_COVERAGE)
    message(STATUS "Code coverage enabled (gcov)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -DENABLE_GCOV_FLUSH")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --coverage")
endif()

# Fuzzing options (requires Clang with libFuzzer)
option(ENABLE_FUZZING "Enable libFuzzer fuzzing harnesses (requires Clang)" OFF)

if(ENABLE_FUZZING)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "Fuzzing requires Clang compiler with libFuzzer support. "
                            "Use: CC=clang cmake .. -DENABLE_FUZZING=ON")
    endif()
    
    # Disable conflicting sanitizer options when fuzzing
    if(ENABLE_ASAN OR ENABLE_UBSAN OR ENABLE_SANITIZERS)
        message(WARNING "Sanitizers already configured - fuzzer will use its own sanitizer settings")
    endif()
    
    message(STATUS "Fuzzing enabled (libFuzzer)")
    
    # Base fuzzer flags (applied to all fuzzer targets)
    set(FUZZER_COMPILE_FLAGS "-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -g")
    set(FUZZER_LINK_FLAGS "-fsanitize=fuzzer,address,undefined")
endif()

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

# Detect OpenSSL/LibreSSL for TLS support (optional)
set(SOCKET_HAS_TLS OFF)
set(OPENSSL_LIBRARIES "")
option(ENABLE_TLS "Enable TLS/SSL support" ON)

if(ENABLE_TLS)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        set(SOCKET_HAS_TLS ON)
        set(OPENSSL_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
        add_definitions(-DSOCKET_HAS_TLS)
        message(STATUS "OpenSSL found - TLS support enabled")
    else()
        # Try LibreSSL as fallback
        find_library(CRYPTO_LIB crypto)
        find_library(SSL_LIB ssl)
        if(CRYPTO_LIB AND SSL_LIB)
            set(SOCKET_HAS_TLS ON)
            set(OPENSSL_LIBRARIES ${SSL_LIB} ${CRYPTO_LIB})
            add_definitions(-DSOCKET_HAS_TLS)
            message(STATUS "LibreSSL found - TLS support enabled")
        else()
            message(WARNING "TLS requested but no SSL library found (OpenSSL/LibreSSL)")
        endif()
    endif()
else()
    message(STATUS "TLS support disabled (use -DENABLE_TLS=ON to enable)")
endif()

# Collect all source files
set(LIB_SOURCES
    # Core foundation (consolidated)
    src/core/Arena.c
    src/core/Except.c
    src/core/SocketUtil.c
    src/core/SocketTimer.c
    src/core/SocketRateLimit.c
    src/core/SocketIPTracker.c
    src/core/SocketSYNProtect.c
    src/core/SocketCrypto.c
    src/core/SocketUTF8.c
    
    # Socket core (consolidated)
    src/socket/Socket.c
    src/socket/Socket-connect.c
    src/socket/Socket-iov.c
    src/socket/Socket-options.c
    src/socket/SocketDgram.c
    src/socket/SocketBuf.c
    src/socket/SocketCommon.c
    src/socket/SocketAsync.c
    src/socket/SocketIO.c
    src/socket/SocketHappyEyeballs.c
    src/socket/SocketReconnect.c
    
    # DNS module (consolidated)
    src/dns/SocketDNS.c
    src/dns/SocketDNS-internal.c

    # Poll module (consolidated)
    src/poll/SocketPoll.c
    ${POLL_BACKEND_SRC}
    
    # Pool module (consolidated)
    src/pool/SocketPool-core.c
    src/pool/SocketPool-connections.c
    src/pool/SocketPool-ops.c
    src/pool/SocketPool-ratelimit.c
    src/pool/SocketPool-drain.c
    
    # HTTP module (RFC 9110/3986)
    src/http/SocketHTTP-core.c
    src/http/SocketHTTP-headers.c
    src/http/SocketHTTP-uri.c
    src/http/SocketHTTP-date.c
)

# Add TLS sources if enabled (split for maintainability)
if(SOCKET_HAS_TLS)
    list(APPEND LIB_SOURCES
        src/tls/SocketTLS.c
        src/tls/SocketTLSContext-core.c
        src/tls/SocketTLSContext-certs.c
        src/tls/SocketTLSContext-alpn.c
        src/tls/SocketTLSContext-session.c
        src/tls/SocketTLSContext-verify.c
        src/tls/SocketTLSContext-pinning.c
        # DTLS (Datagram TLS) support
        src/tls/SocketDTLS.c
        src/tls/SocketDTLSContext.c
        src/tls/SocketDTLS-cookie.c
    )
endif()

# Object library for reuse in tests (avoids static library constructor issues)
add_library(socket_objects OBJECT ${LIB_SOURCES})
target_include_directories(socket_objects PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add OpenSSL include directories to object library when TLS is enabled
if(SOCKET_HAS_TLS AND OpenSSL_FOUND)
    target_include_directories(socket_objects PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

# Static library
add_library(socket_static STATIC $<TARGET_OBJECTS:socket_objects>)
set_target_properties(socket_static PROPERTIES OUTPUT_NAME socket)
if(SOCKET_HAS_TLS)
    target_link_libraries(socket_static pthread m ${LIBURING_LIBRARIES} ${OPENSSL_LIBRARIES})
else()
    target_link_libraries(socket_static pthread m ${LIBURING_LIBRARIES})
endif()

# Shared library
add_library(socket_shared SHARED $<TARGET_OBJECTS:socket_objects>)
set_target_properties(socket_shared PROPERTIES OUTPUT_NAME socket)
if(SOCKET_HAS_TLS)
    target_link_libraries(socket_shared pthread m ${LIBURING_LIBRARIES} ${OPENSSL_LIBRARIES})
else()
    target_link_libraries(socket_shared pthread m ${LIBURING_LIBRARIES})
endif()

# Custom target to build both libraries (default)
add_custom_target(lib ALL DEPENDS socket_static socket_shared)

# Generate pkg-config file
set(PC_LIBS_PRIVATE "")
if(SOCKET_HAS_TLS)
    set(PC_LIBS_PRIVATE "-lssl -lcrypto")
endif()

configure_file(
    ${CMAKE_SOURCE_DIR}/libsocket.pc.in
    ${CMAKE_BINARY_DIR}/libsocket.pc
    @ONLY
)

install(FILES ${CMAKE_BINARY_DIR}/libsocket.pc
    DESTINATION lib/pkgconfig
)

# Installation targets (optional)

# Header files for installation
set(CORE_HEADERS
    include/core/Arena.h
    include/core/Except.h
    include/core/SocketConfig.h
    include/core/SocketUtil.h
    include/core/SocketTimer.h
    include/core/SocketTimer-private.h
    include/core/SocketRateLimit.h
    include/core/SocketRateLimit-private.h
    include/core/SocketIPTracker.h
    include/core/SocketSYNProtect.h
    include/core/SocketSYNProtect-private.h
    include/core/SocketCrypto.h
    include/core/SocketUTF8.h
)

set(SOCKET_HEADERS
    include/socket/Socket.h
    include/socket/Socket-private.h
    include/socket/SocketAsync.h
    include/socket/SocketBuf.h
    include/socket/SocketCommon.h
    include/socket/SocketDgram.h
    include/socket/SocketIO.h
    include/socket/SocketHappyEyeballs.h
    include/socket/SocketHappyEyeballs-private.h
    include/socket/SocketReconnect.h
    include/socket/SocketReconnect-private.h
)

set(DNS_HEADERS
    include/dns/SocketDNS.h
)

set(POLL_HEADERS
    include/poll/SocketPoll.h
    include/poll/SocketPoll-private.h
    include/poll/SocketPoll_backend.h
)

set(POOL_HEADERS
    include/pool/SocketPool.h
    include/pool/SocketPool-private.h
    include/pool/SocketPool-core.h
)

set(TLS_HEADERS
    include/tls/SocketTLS.h
    include/tls/SocketTLSConfig.h
    include/tls/SocketTLSContext.h
    include/tls/SocketDTLS.h
    include/tls/SocketDTLSConfig.h
    include/tls/SocketDTLSContext.h
    include/tls/SocketDTLS-private.h
)

set(HTTP_HEADERS
    include/http/SocketHTTP.h
    include/http/SocketHTTP-private.h
)

set(TEST_HEADERS
    include/test/Test.h
)

install(TARGETS socket_static socket_shared
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${CORE_HEADERS} DESTINATION include/core)
install(FILES ${SOCKET_HEADERS} DESTINATION include/socket)
install(FILES ${DNS_HEADERS} DESTINATION include/dns)
install(FILES ${POLL_HEADERS} DESTINATION include/poll)
install(FILES ${POOL_HEADERS} DESTINATION include/pool)
install(FILES ${TLS_HEADERS} DESTINATION include/tls)
install(FILES ${HTTP_HEADERS} DESTINATION include/http)
install(FILES ${TEST_HEADERS} DESTINATION include/test)

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
if(SOCKET_HAS_TLS)
    message(STATUS "  TLS Support: Enabled (${OPENSSL_LIBRARIES})")
else()
    message(STATUS "  TLS Support: Disabled")
endif()
if(ENABLE_ASAN)
    message(STATUS "  AddressSanitizer: Enabled")
endif()
if(ENABLE_UBSAN)
    message(STATUS "  UBSanitizer: Enabled")
endif()
if(ENABLE_COVERAGE)
    message(STATUS "  Code Coverage: Enabled")
endif()

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
    test_tls_integration
    test_tls_phase4
    test_tls_pinning
    test_dtls_integration
    test_threadsafety
    test_socketpool_tls
    test_happy_eyeballs
    test_reconnect
    test_ratelimit
    test_async
    test_coverage
    test_synprotect
    test_crypto
    test_utf8
    test_http_core
)

# Create test executables (link against object files to preserve constructor attributes)
foreach(test_name ${TEST_SOURCES})
    add_executable(${test_name} src/test/${test_name}.c $<TARGET_OBJECTS:socket_objects> $<TARGET_OBJECTS:test_framework>)
    if(SOCKET_HAS_TLS)
        target_link_libraries(${test_name} pthread m ${OPENSSL_LIBRARIES})
    else()
        target_link_libraries(${test_name} pthread m)
    endif()
    target_include_directories(${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Custom target to build all tests
add_custom_target(build_tests ALL DEPENDS ${TEST_SOURCES})

# Print test configuration
message(STATUS "Test Suite Configuration:")
message(STATUS "  Test files: 21")
message(STATUS "  Total tests: 300+")
message(STATUS "  Run with: make test (or ctest)")

# Documentation generation (Doxygen)
find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_SOURCE_DIR}/Doxyfile)
    set(DOXYGEN_OUT ${CMAKE_BINARY_DIR}/docs)
    
    # Copy CSS file to HTML output directory (Doxygen will include it)
    add_custom_command(
        OUTPUT ${CMAKE_SOURCE_DIR}/docs/html/doxygen-awesome.css
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/docs/html
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/docs/doxygen-awesome.css
            ${CMAKE_SOURCE_DIR}/docs/html/doxygen-awesome.css
        COMMENT "Preparing Doxygen CSS"
        VERBATIM
    )
    
    add_custom_target(doc
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/docs/html
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/docs/doxygen-awesome.css
            ${CMAKE_SOURCE_DIR}/docs/html/doxygen-awesome.css
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_IN}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
    
    message(STATUS "Documentation: Doxygen found - use 'make doc' to generate API docs")
else()
    message(STATUS "Documentation: Doxygen not found - install doxygen to generate API docs")
endif()

add_executable(benchmark_server src/test/benchmark_server.c)
target_link_libraries(benchmark_server socket_static pthread)

add_executable(benchmark_client src/test/benchmark_client.c)
target_link_libraries(benchmark_client socket_static pthread)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(benchmark_raw src/test/benchmark_raw.c)
    target_link_libraries(benchmark_raw pthread)
endif()

# LibEvent benchmark is optional - only build if library AND headers are available
set(LIBEVENT_FOUND FALSE)

# Try to find libevent library and headers
find_library(LIBEVENT_LIB event)
find_path(LIBEVENT_INCLUDE_DIR event2/event.h)

if(LIBEVENT_LIB AND LIBEVENT_INCLUDE_DIR)
    set(LIBEVENT_FOUND TRUE)
    message(STATUS "LibEvent found: ${LIBEVENT_LIB}")
    message(STATUS "LibEvent include: ${LIBEVENT_INCLUDE_DIR}")
endif()

if(LIBEVENT_FOUND)
    add_executable(benchmark_libevent src/test/benchmark_libevent.c)
    target_include_directories(benchmark_libevent PRIVATE ${LIBEVENT_INCLUDE_DIR})
    target_link_libraries(benchmark_libevent ${LIBEVENT_LIB} pthread)
    message(STATUS "LibEvent found - building benchmark_libevent")
else()
    message(STATUS "LibEvent not found - skipping benchmark_libevent (install libevent-dev)")
endif()

# =============================================================================
# Fuzzing Targets (libFuzzer)
# =============================================================================
# Build with: CC=clang cmake .. -DENABLE_FUZZING=ON -DCMAKE_BUILD_TYPE=Debug
# Run with: ./fuzz_socketbuf corpus/socketbuf/ -fork=16 -max_len=4096
# =============================================================================

if(ENABLE_FUZZING)
    # Fuzz harness source files (non-TLS)
    set(FUZZ_SOURCES
        fuzz_socketbuf
        fuzz_arena
        fuzz_ip_parse
        fuzz_dns_validate
        fuzz_socketbuf_stress
        fuzz_ratelimit
        fuzz_timer
        fuzz_iptracker
        fuzz_happy_eyeballs
        fuzz_reconnect
        fuzz_socketio
        fuzz_address_parse
        fuzz_cidr_parse
        fuzz_unix_path
        fuzz_socketpool
        fuzz_socketpoll
        fuzz_socketdgram
        fuzz_exception
        fuzz_async
        fuzz_connect
        fuzz_synprotect
        fuzz_base64_decode
        fuzz_hex_decode
        fuzz_utf8_validate
        fuzz_utf8_incremental
        fuzz_uri_parse
        fuzz_http_date
    )
    
    # TLS fuzz harnesses (require SOCKET_HAS_TLS)
    if(SOCKET_HAS_TLS)
        list(APPEND FUZZ_SOURCES
            fuzz_tls_alpn
            fuzz_tls_session
            fuzz_tls_certs
            fuzz_tls_verify
            fuzz_tls_sni
            fuzz_tls_io
            fuzz_cert_pinning
            # DTLS fuzz harnesses
            fuzz_dtls_context
            fuzz_dtls_io
            fuzz_dtls_cookie
            fuzz_dtls_handshake
        )
    endif()
    
    # Create fuzz executable for each harness
    foreach(fuzz_name ${FUZZ_SOURCES})
        if(EXISTS "${CMAKE_SOURCE_DIR}/src/fuzz/${fuzz_name}.c")
            add_executable(${fuzz_name} 
                src/fuzz/${fuzz_name}.c 
                $<TARGET_OBJECTS:socket_objects>
            )
            
            # Apply fuzzer compile flags
            target_compile_options(${fuzz_name} PRIVATE 
                -fsanitize=fuzzer-no-link,address,undefined 
                -fno-omit-frame-pointer 
                -g
            )
            
            # Apply fuzzer link flags
            target_link_options(${fuzz_name} PRIVATE 
                -fsanitize=fuzzer,address,undefined
            )
            
            # Link libraries
            if(SOCKET_HAS_TLS)
                target_link_libraries(${fuzz_name} pthread m ${OPENSSL_LIBRARIES})
            else()
                target_link_libraries(${fuzz_name} pthread m)
            endif()
            
            target_include_directories(${fuzz_name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
            
            message(STATUS "  Fuzzer: ${fuzz_name}")
        else()
            message(STATUS "  Fuzzer: ${fuzz_name} (source not found - skipping)")
        endif()
    endforeach()
    
    # Custom target to build all fuzzers
    add_custom_target(fuzzers)
    foreach(fuzz_name ${FUZZ_SOURCES})
        if(EXISTS "${CMAKE_SOURCE_DIR}/src/fuzz/${fuzz_name}.c")
            add_dependencies(fuzzers ${fuzz_name})
        endif()
    endforeach()
    
    message(STATUS "Fuzzing Configuration:")
    message(STATUS "  Harnesses: ${FUZZ_SOURCES}")
    message(STATUS "  Build fuzzers: make fuzzers")
    message(STATUS "  Run example: ./fuzz_socketbuf corpus/socketbuf/ -fork=16")
endif()

