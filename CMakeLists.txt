cmake_minimum_required(VERSION 3.10)
project(socket VERSION 1.0.0 LANGUAGES C)

# Generate compile_commands.json for IDE integration (clangd)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # Enable GNU extensions (_GNU_SOURCE)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-variable -Wno-comment -Wno-implicit-int -Wno-ignored-qualifiers -Wno-return-type -Wno-error=return-type -D_GNU_SOURCE -pthread -fno-strict-aliasing -fPIC")

# Executable stack warning is expected and harmless:
# - Caused by setjmp/longjmp in TRY/EXCEPT/FINALLY exception handling
# - Modern Linux kernels enforce NX protection regardless of this flag
# - This is a legacy warning from early 2000s security implementations
# - The code is completely safe despite the warning
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

# ThreadSanitizer option (incompatible with ASan)
option(ENABLE_TSAN "Enable ThreadSanitizer (TSan) - incompatible with ASan" OFF)

if(ENABLE_TSAN)
    if(ENABLE_ASAN)
        message(FATAL_ERROR "ThreadSanitizer (TSan) is incompatible with AddressSanitizer (ASan). "
                            "Use only one at a time.")
    endif()
    message(STATUS "ThreadSanitizer (TSan) enabled")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -fno-omit-frame-pointer -g")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=thread")
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
    add_definitions(-DSOCKET_HAS_TLS=0)
    message(STATUS "TLS support disabled (use -DENABLE_TLS=ON to enable)")
endif()

# io_uring support (Linux only - requires liburing and kernel 5.1+)
set(SOCKET_HAS_IO_URING OFF)
set(LIBURING_LIBRARIES "")
option(ENABLE_IO_URING "Enable io_uring async I/O backend (Linux only)" OFF)
option(PREFER_IO_URING_POLL "Use io_uring instead of epoll for poll backend (Linux only)" OFF)

if(ENABLE_IO_URING)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(WARNING "io_uring is only available on Linux - ignoring ENABLE_IO_URING")
    else()
        # Try pkg-config first (preferred)
        find_package(PkgConfig QUIET)
        if(PKG_CONFIG_FOUND)
            pkg_check_modules(LIBURING QUIET liburing)
        endif()

        if(LIBURING_FOUND)
            set(SOCKET_HAS_IO_URING ON)
            add_definitions(-DSOCKET_HAS_IO_URING=1)
            include_directories(${LIBURING_INCLUDE_DIRS})
            set(LIBURING_LIBRARIES ${LIBURING_LIBRARIES})
            message(STATUS "io_uring found via pkg-config - async I/O enabled")
        else()
            # Fallback: direct library/header search
            find_library(URING_LIB uring)
            find_path(URING_INCLUDE_DIR liburing.h)

            if(URING_LIB AND URING_INCLUDE_DIR)
                set(SOCKET_HAS_IO_URING ON)
                add_definitions(-DSOCKET_HAS_IO_URING=1)
                include_directories(${URING_INCLUDE_DIR})
                set(LIBURING_LIBRARIES ${URING_LIB})
                message(STATUS "io_uring found - async I/O enabled (${URING_LIB})")
            else()
                message(WARNING "io_uring requested but liburing not found")
                message(STATUS "  Install with: apt install liburing-dev")
            endif()
        endif()
    endif()
else()
    message(STATUS "io_uring disabled (use -DENABLE_IO_URING=ON on Linux to enable)")
endif()

# Update poll backend to io_uring if preferred and available
if(PREFER_IO_URING_POLL)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(WARNING "io_uring poll backend only available on Linux - using default backend")
    elseif(NOT SOCKET_HAS_IO_URING)
        message(WARNING "io_uring poll backend requested but liburing not found - using epoll")
        message(STATUS "  Enable with: cmake -DENABLE_IO_URING=ON -DPREFER_IO_URING_POLL=ON")
    else()
        set(POLL_BACKEND "io_uring")
        set(POLL_BACKEND_SRC "src/poll/SocketPoll_uring.c")
        message(STATUS "Switching to io_uring poll backend (preferred over epoll)")
    endif()
endif()

# HTTP Compression support (optional - requires zlib and/or brotli)
option(ENABLE_HTTP_COMPRESSION "Enable HTTP gzip/deflate/brotli compression" OFF)

set(SOCKETHTTP1_HAS_COMPRESSION OFF)
set(HTTP_COMPRESSION_LIBS "")

# Always search for zlib (needed for WebSocket permessage-deflate even without HTTP compression)
find_package(ZLIB QUIET)

# WebSocket deflate requires zlib - we'll set this after HTTP compression logic
# to avoid linking zlib twice when both WS deflate and HTTP compression use it
set(WS_DEFLATE_LIBS "")

if(ENABLE_HTTP_COMPRESSION)
    # Use zlib for HTTP compression if found
    if(ZLIB_FOUND)
        add_definitions(-DSOCKETHTTP1_HAS_ZLIB)
        list(APPEND HTTP_COMPRESSION_LIBS ZLIB::ZLIB)
        message(STATUS "zlib found - gzip/deflate compression enabled")
        # zlib already in HTTP_COMPRESSION_LIBS, no need to duplicate in WS_DEFLATE_LIBS
    else()
        message(STATUS "zlib not found - gzip/deflate compression disabled")
    endif()
    
    # Find Brotli (optional)
    find_library(BROTLI_DEC_LIB brotlidec)
    find_library(BROTLI_ENC_LIB brotlienc)
    find_path(BROTLI_INCLUDE_DIR brotli/decode.h)
    
    if(BROTLI_DEC_LIB AND BROTLI_ENC_LIB AND BROTLI_INCLUDE_DIR)
        add_definitions(-DSOCKETHTTP1_HAS_BROTLI)
        list(APPEND HTTP_COMPRESSION_LIBS ${BROTLI_DEC_LIB} ${BROTLI_ENC_LIB})
        include_directories(${BROTLI_INCLUDE_DIR})
        message(STATUS "Brotli found - brotli compression enabled")
    else()
        message(STATUS "Brotli not found - brotli compression disabled")
    endif()
    
    # Enable compression module if any compression library found
    if(ZLIB_FOUND OR (BROTLI_DEC_LIB AND BROTLI_ENC_LIB))
        set(SOCKETHTTP1_HAS_COMPRESSION ON)
        message(STATUS "HTTP compression support enabled")
    else()
        message(WARNING "HTTP compression requested but no compression libraries found")
    endif()
else()
    message(STATUS "HTTP compression disabled (use -DENABLE_HTTP_COMPRESSION=ON to enable)")
    # HTTP compression disabled, so WS deflate needs its own zlib link
    if(ZLIB_FOUND)
        set(WS_DEFLATE_LIBS ZLIB::ZLIB)
    endif()
endif()

if(SOCKETHTTP1_HAS_COMPRESSION)
    add_definitions(-DSOCKETHTTP1_HAS_COMPRESSION=1)
else()
    add_definitions(-DSOCKETHTTP1_HAS_COMPRESSION=0)
endif()

# Collect all source files
set(LIB_SOURCES
    # Core foundation (consolidated)
    src/core/Arena.c
    src/core/Except.c
    src/core/SocketError.c
    src/core/SocketLog.c
    src/core/SocketEvent.c
    src/core/SocketUtil.c
    src/core/SocketTimer.c
    src/core/SocketRateLimit.c
    src/core/HashTable.c
    src/core/TimeWindow.c
    src/core/SocketIPTracker.c
    src/core/SocketSYNProtect.c
    src/core/SocketSYNProtect-list.c
    src/core/SocketSYNProtect-ip.c
    src/core/SocketCrypto.c
    src/core/SocketUTF8.c
    src/core/SocketSecurity.c
    src/core/SocketMetrics.c
    src/core/SocketRetry.c
    
    # Socket core (consolidated)
    src/socket/Socket.c
    src/socket/Socket-connect.c
    src/socket/Socket-convenience.c
    src/socket/Socket-fd.c
    src/socket/Socket-iov.c
    src/socket/Socket-options.c
    src/socket/SocketDgram.c
    src/socket/SocketBuf.c
    src/socket/SocketCommon.c
    src/socket/SocketAsync.c
    src/socket/SocketIO.c
    src/socket/SocketHappyEyeballs.c
    src/socket/SocketReconnect.c
    
    # Proxy module (Phase 8)
    src/socket/SocketProxy.c
    src/socket/SocketProxy-http.c
    src/socket/SocketProxy-socks4.c
    src/socket/SocketProxy-socks5.c
    
    # WebSocket module (Phase 9 - RFC 6455)
    src/socket/SocketWS.c
    src/socket/SocketWS-handshake.c
    src/socket/SocketWS-frame.c
    src/socket/SocketWS-transport.c

    # WebSocket over HTTP/2 (RFC 8441)
    src/socket/SocketWSH2.c
    
    # DNS module (consolidated)
    src/dns/SocketDNS.c
    src/dns/SocketDNSWire.c
    src/dns/SocketDNSTransport.c
    src/dns/SocketDNSConfig.c
    src/dns/SocketDNSResolver.c
    src/dns/SocketDNSSEC.c
    src/dns/SocketDNSCookie.c
    src/dns/SocketDNSError.c
    src/dns/SocketDNSNegCache.c
    src/dns/SocketDNSServfailCache.c
    src/dns/SocketDNSDeadServer.c

    # Poll module (consolidated)
    src/poll/SocketPoll.c
    ${POLL_BACKEND_SRC}
    
    # Pool module (consolidated)
    src/pool/SocketPool-core.c
    src/pool/SocketPool-connections.c
    src/pool/SocketPool-ops.c
    src/pool/SocketPool-ratelimit.c
    src/pool/SocketPool-drain.c
    src/pool/SocketPool-health.c
    
    # HTTP module (RFC 9110/3986)
    src/http/SocketHTTP-core.c
    src/http/SocketHTTP-headers.c
    src/http/SocketHTTP-uri.c
    src/http/SocketHTTP-date.c
    
    # HTTP/1.1 module (RFC 9112)
    src/http/SocketHTTP1-parser.c
    src/http/SocketHTTP1-serialize.c
    src/http/SocketHTTP1-chunked.c
    
    # HPACK Header Compression (RFC 7541)
    src/http/hpack/SocketHPACK.c
    src/http/hpack/SocketHPACK-huffman.c
    src/http/hpack/SocketHPACK-table.c

    # QPACK Header Compression (RFC 9204)
    src/http/qpack/SocketQPACK-prefix.c

    # HTTP/2 Protocol (RFC 9113)
    src/http/h2/SocketHTTP2-frame.c
    src/http/h2/SocketHTTP2-connection.c
    src/http/h2/SocketHTTP2-stream.c
    src/http/h2/SocketHTTP2-flow.c
    src/http/h2/SocketHTTP2-validate.c
    src/http/h2/SocketHTTP2-priority.c

    # HTTP Client API
    src/http/SocketHTTPClient.c
    src/http/client/SocketHTTPClient-pool.c
    src/http/client/SocketHTTPClient-auth.c
    src/http/client/SocketHTTPClient-cookie.c
    src/http/client/SocketHTTPClient-retry.c
    src/http/client/SocketHTTPClient-arena.c
    src/http/client/SocketHTTPClient-async.c
    src/http/client/SocketHTTPClient-io.c
    src/http/client/SocketHTTPClient-body.c
    src/http/client/SocketHTTPClient-headers.c
    src/http/client/SocketHTTPClient-http1.c
    src/http/client/SocketHTTPClient-http2.c

    # HTTP Server API
    src/http/SocketHTTPServer.c
    src/http/server/SocketHTTPServer-connections.c
    src/http/server/SocketHTTPServer-core.c
    src/http/server/SocketHTTPServer-http1.c
    src/http/server/SocketHTTPServer-static.c
    src/http/server/SocketHTTPServer-h2.c
    src/http/server/SocketHTTPServer-metrics.c

    # QUIC foundational module (RFC 9000)
    src/quic/SocketQUICVarInt.c
    src/quic/SocketQUICError.c
    src/quic/SocketQUICVersion.c
    src/quic/SocketQUICError-handling.c
    src/quic/SocketQUICConnectionID.c
    src/quic/SocketQUICConnectionID-pool.c
    src/quic/SocketQUICStream.c
    src/quic/SocketQUICStream-state.c
    src/quic/SocketQUICPacket.c
    src/quic/SocketQUICPacket-initial.c
    src/quic/SocketQUICPacket-receive.c
    src/quic/SocketQUICCrypto.c
    src/quic/SocketQUICWire.c
    src/quic/SocketQUICFrame.c
    src/quic/SocketQUICFrame-flow.c
    src/quic/SocketQUICFrame-close.c
    src/quic/SocketQUICFrame-connid.c
    src/quic/SocketQUICFrame-path.c
    src/quic/SocketQUICFrame-stream.c
    src/quic/SocketQUICFrame-handshake.c
    src/quic/SocketQUICFrame-token.c
    src/quic/SocketQUICFrame-crypto.c
    src/quic/SocketQUICConnection-demux.c
    src/quic/SocketQUICConnection-termination.c
    src/quic/SocketQUICTransportParams.c
    src/quic/SocketQUICPMTU.c
    src/quic/SocketQUICAddrValidation.c
    src/quic/SocketQUICMigration.c
    src/quic/SocketQUICHandshake.c
    src/quic/SocketQUICFlow.c
    src/quic/SocketQUICAck.c
    src/quic/SocketQUICLoss.c
    src/quic/SocketQUICTLS.c

)

# Add TLS sources if enabled (split for maintainability)
if(SOCKET_HAS_TLS)
    list(APPEND LIB_SOURCES
        src/tls/SocketTLS.c
        src/tls/SocketTLS-ktls.c
        src/tls/SocketTLS-performance.c
        src/tls/SocketTLSContext-core.c
        src/tls/SocketTLSContext-certs.c
        src/tls/SocketTLSContext-alpn.c
        src/tls/SocketTLSContext-session.c
        src/tls/SocketTLSContext-verify.c
        src/tls/SocketTLSContext-pinning.c
        src/tls/SocketTLSConfig.c
        src/tls/SocketTLSContext-ct.c
        src/tls/SocketTLSContext-crl.c
        # DTLS (Datagram TLS) support
        src/tls/SocketDTLS.c
        src/tls/SocketDTLSContext.c
        src/tls/SocketDTLS-cookie.c
        # DNS-over-TLS (RFC 7858)
        src/dns/SocketDNSoverTLS.c
        # DNS-over-HTTPS (RFC 8484)
        src/dns/SocketDNSoverHTTPS.c
    )
endif()

# Add HTTP compression source if compression enabled
if(ENABLE_HTTP_COMPRESSION AND (ZLIB_FOUND OR (BROTLI_DEC_LIB AND BROTLI_ENC_LIB)))
    list(APPEND LIB_SOURCES
        src/http/SocketHTTP1-compress.c
    )
endif()

# Add WebSocket compression source if zlib available
if(ZLIB_FOUND)
    list(APPEND LIB_SOURCES
        src/socket/SocketWS-deflate.c
    )
    add_definitions(-DSOCKETWS_HAS_DEFLATE)
    message(STATUS "WebSocket permessage-deflate compression enabled")
endif()

# Object library for reuse in tests (avoids static library constructor issues)
add_library(socket_objects OBJECT ${LIB_SOURCES})
target_include_directories(socket_objects PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(socket_objects PRIVATE TESTING)

# Add OpenSSL include directories to object library when TLS is enabled
if(SOCKET_HAS_TLS AND OpenSSL_FOUND)
    target_include_directories(socket_objects PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

# For fuzzing, build a SEPARATE instrumented object library
# CRITICAL: Objects must be compiled with -fsanitize flags for coverage instrumentation
if(ENABLE_FUZZING)
    # Create instrumented OBJECT library (recompiles sources with fuzzer flags)
    add_library(socket_fuzz_objects OBJECT ${LIB_SOURCES})
    target_include_directories(socket_fuzz_objects PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_compile_options(socket_fuzz_objects PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined
        -fno-omit-frame-pointer
        -g
    )
    if(SOCKET_HAS_TLS AND OpenSSL_FOUND)
        target_include_directories(socket_fuzz_objects PRIVATE ${OPENSSL_INCLUDE_DIR})
    endif()

    # Create static library from instrumented objects
    add_library(socket_fuzz STATIC $<TARGET_OBJECTS:socket_fuzz_objects>)
    set_target_properties(socket_fuzz PROPERTIES OUTPUT_NAME socket_fuzz)
    target_link_options(socket_fuzz PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined
    )
    if(SOCKET_HAS_TLS)
        target_link_libraries(socket_fuzz pthread m dl ${LIBURING_LIBRARIES} ${OPENSSL_LIBRARIES} ${HTTP_COMPRESSION_LIBS} ${WS_DEFLATE_LIBS})
    else()
        target_link_libraries(socket_fuzz pthread m ${LIBURING_LIBRARIES} ${HTTP_COMPRESSION_LIBS} ${WS_DEFLATE_LIBS})
    endif()
    message(STATUS "Instrumented fuzzing library created (with coverage)")
endif()

# Static library
add_library(socket_static STATIC $<TARGET_OBJECTS:socket_objects>)
set_target_properties(socket_static PROPERTIES OUTPUT_NAME socket)
if(SOCKET_HAS_TLS)
    target_link_libraries(socket_static pthread m dl ${LIBURING_LIBRARIES} ${OPENSSL_LIBRARIES} ${HTTP_COMPRESSION_LIBS} ${WS_DEFLATE_LIBS})
else()
    target_link_libraries(socket_static pthread m ${LIBURING_LIBRARIES} ${HTTP_COMPRESSION_LIBS} ${WS_DEFLATE_LIBS})
endif()

# Shared library
add_library(socket_shared SHARED $<TARGET_OBJECTS:socket_objects>)
set_target_properties(socket_shared PROPERTIES OUTPUT_NAME socket)
if(SOCKET_HAS_TLS)
    target_link_libraries(socket_shared pthread m dl ${LIBURING_LIBRARIES} ${OPENSSL_LIBRARIES} ${HTTP_COMPRESSION_LIBS} ${WS_DEFLATE_LIBS})
else()
    target_link_libraries(socket_shared pthread m ${LIBURING_LIBRARIES} ${HTTP_COMPRESSION_LIBS} ${WS_DEFLATE_LIBS})
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
    include/core/SocketSecurity.h
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
    include/socket/SocketProxy.h
    include/socket/SocketProxy-private.h
)

set(DNS_HEADERS
    include/dns/SocketDNS.h
    include/dns/SocketDNSWire.h
    include/dns/SocketDNSTransport.h
    include/dns/SocketDNSConfig.h
    include/dns/SocketDNSResolver.h
    include/dns/SocketDNSoverTLS.h
    include/dns/SocketDNSoverHTTPS.h
    include/dns/SocketDNSSEC.h
    include/dns/SocketDNSCookie.h
    include/dns/SocketDNSError.h
    include/dns/SocketDNSNegCache.h
    include/dns/SocketDNSServfailCache.h
    include/dns/SocketDNSDeadServer.h
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
    include/http/SocketHTTP1.h
    include/http/SocketHTTP1-private.h
    include/http/SocketHPACK.h
    include/http/SocketHPACK-private.h
    include/http/SocketHTTP2.h
    include/http/SocketHTTP2-private.h
    include/http/SocketHTTPClient.h
    include/http/SocketHTTPClient-private.h
    include/http/SocketHTTPServer.h
    include/http/qpack/SocketQPACK-private.h
)

set(TEST_HEADERS
    include/test/Test.h
)

set(QUIC_HEADERS
    include/quic/SocketQUICVarInt.h
    include/quic/SocketQUICError.h
    include/quic/SocketQUICVersion.h
    include/quic/SocketQUICConnectionID.h
    include/quic/SocketQUICConnectionID-pool.h
    include/quic/SocketQUICStream.h
    include/quic/SocketQUICPacket.h
    include/quic/SocketQUICCrypto.h
    include/quic/SocketQUICFrame.h
    include/quic/SocketQUICConnection.h
    include/quic/SocketQUICTransportParams.h
    include/quic/SocketQUICHandshake.h
    include/quic/SocketQUICAck.h
    include/quic/SocketQUICLoss.h
    include/quic/SocketQUICTLS.h
)

set(SIMPLE_HEADERS
    include/simple/SocketSimple.h
    include/simple/SocketSimple-tcp.h
    include/simple/SocketSimple-tls.h
    include/simple/SocketSimple-http.h
    include/simple/SocketSimple-ws.h
    include/simple/SocketSimple-dns.h
    include/simple/SocketSimple-pool.h
    include/simple/SocketSimple-poll.h
    include/simple/SocketSimple-proxy.h
    include/simple/SocketSimple-http-server.h
    include/simple/SocketSimple-ratelimit.h
    include/simple/SocketSimple-security.h
    include/simple/SocketSimple-buf.h
    include/simple/SocketSimple-timer.h
    include/simple/SocketSimple-happyeyeballs.h
    include/simple/SocketSimple-reconnect.h
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
install(FILES ${QUIC_HEADERS} DESTINATION include/quic)
install(FILES ${SIMPLE_HEADERS} DESTINATION include/simple)

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
if(SOCKET_HAS_IO_URING)
    message(STATUS "  io_uring: Enabled (${LIBURING_LIBRARIES})")
else()
    message(STATUS "  io_uring: Disabled")
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

# Test source files (core - always built)
set(TEST_SOURCES
    test_new_features
    test_arena
    test_except
    test_hashtable
    test_timewindow
    test_socketerror
    test_socketevent
    test_socketlog
    test_safe_arithmetic
    test_socketutil_time
    test_url_utils
    test_socket
    test_socketbuf
    test_socketdgram
    test_socketpoll
    test_socketpool
    test_pool_health
    test_iptracker
    test_socketdns
    test_dns_wire
    test_dns_transport
    test_dns_config
    test_dns_cache
    test_dns_resolver
    test_dns_queue_limit
    test_dnssec
    test_dnscookie
    test_dnserror
    test_dns_negcache
    test_dns_servfailcache
    test_dns_deadserver
    test_integration
    test_threadsafety
    test_happy_eyeballs
    test_reconnect
    test_ratelimit
    test_async
    test_coverage
    test_synprotect
    test_synprotect_ip_parsing
    test_synprotect_ip
    test_ipv4_parse
    test_ipv6_parse
    test_ip_equality
    test_crypto
    test_utf8
    test_utf8_integration
    test_http_core
    test_http1_parser
    test_hpack
    test_qpack_prefix
    test_http2
    test_http2_priority
    test_http2_rate_limit
    test_http_client
    test_proxy
    test_websocket
    test_security
    test_http_integration
    test_ws_integration
    test_http2_integration
    test_proxy_integration
    test_httpserver_load
    test_signals
    test_cross_module_integration
    test_load_integration
    test_connection_resilience
    test_platform_integration
    test_multi_protocol_integration
    test_socketretry
    test_socketio
    test_sendfile_bounds
    test_timer
    test_timer_oneshot
    test_timer_heap
    test_metrics
    test_metrics_percentile
    test_httpserver
    test_httpserver_websocket
    # QUIC tests (RFC 9000)
    test_quic_varint
    test_quic_error
    test_quic_version
    test_quic_connid
    test_quic_connid_pool
    test_quic_stream
    test_quic_stream_state
    test_quic_packet
    test_quic_packet_receive
    test_quic_wire
    test_quic_frame
    test_quic_stream_frame_encode
    test_quic_new_token_frame
    test_quic_path_frame
    test_quic_frame_close
    test_quic_connection
    test_quic_transport_params
    test_quic_pmtu
    test_quic_addr_validation
    test_quic_migration
    test_quic_handshake
    test_quic_termination
    test_quic_flow
    test_quic_crypto_frame_encode
    test_quic_ack
    test_quic_loss
    test_quic_key_discard
    test_quic_0rtt
)

# TLS tests (only built when TLS is enabled)
if(SOCKET_HAS_TLS)
    list(APPEND TEST_SOURCES
        # QUIC Initial packet tests (requires TLS for crypto)
        test_quic_crypto
        test_quic_initial
        test_quic_tls
        test_quic_key_update
        test_quic_retry
        test_quic_rfc9001_vectors
        test_tls_ct
        test_tls_integration
        test_tls_ocsp
        test_tls_phase4
        test_tls_pinning
        test_tls_performance
        test_dtls_integration
        test_socketpool_tls
        # Additional TLS tests
        test_dtls_basic
        test_dtls_cookie
        test_dtls_mtu
        test_mtls
        test_tls_context
        test_tls_enable_disable
        test_tls_handshake
        test_tls_http2
        test_tls_io
        test_tls_security
        test_tls_session
        # CRL and advanced TLS tests
        test_tls_crl
        test_tls_crl_integration
        test_tls_ktls
        test_tls_reconnect
        # HTTP/2 and WebSocket-over-HTTP/2 tests
        test_http2_server_push
        test_websocket_h2
        # DNS-over-TLS (RFC 7858)
        test_dns_over_tls
        # DNS-over-HTTPS (RFC 8484)
        test_dns_over_https
    )
endif()

# Create test executables (link against object files to preserve constructor attributes)
foreach(test_name ${TEST_SOURCES})
    add_executable(${test_name} src/test/${test_name}.c $<TARGET_OBJECTS:socket_objects> $<TARGET_OBJECTS:test_framework>)
    if(SOCKET_HAS_TLS)
        target_link_libraries(${test_name} pthread m ${LIBURING_LIBRARIES} ${OPENSSL_LIBRARIES} ${HTTP_COMPRESSION_LIBS} ${WS_DEFLATE_LIBS})
    else()
        target_link_libraries(${test_name} pthread m ${LIBURING_LIBRARIES} ${HTTP_COMPRESSION_LIBS} ${WS_DEFLATE_LIBS})
    endif()
    target_include_directories(${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_compile_definitions(${test_name} PRIVATE TESTING)
    add_test(NAME ${test_name} COMMAND ${test_name})
    # Set 60 second timeout to prevent test hangs (TLS tests may need more time)
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 60)
endforeach()

# Custom target to build all tests
add_custom_target(build_tests ALL DEPENDS ${TEST_SOURCES})

# Print test configuration
message(STATUS "Test Suite Configuration:")
message(STATUS "  Test files: 24")
message(STATUS "  Total tests: 400+")
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

# =============================================================================
# Examples (optional)
# =============================================================================
# Build with: cmake -DBUILD_EXAMPLES=ON ..
# =============================================================================

option(BUILD_EXAMPLES "Build example programs" OFF)

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
    message(STATUS "Examples: Building example programs")
else()
    message(STATUS "Examples: Disabled (use -DBUILD_EXAMPLES=ON to enable)")
endif()

# =============================================================================
# Benchmarks
# =============================================================================

add_executable(benchmark_server src/test/benchmark_server.c)
target_link_libraries(benchmark_server socket_static pthread)

add_executable(benchmark_synprotect src/test/benchmark_synprotect.c)
target_link_libraries(benchmark_synprotect socket_static pthread)

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
# HTTP Client Benchmarks (tetsuo-socket vs libcurl)
# =============================================================================
# Build with: cmake -B build -DBUILD_HTTP_BENCHMARKS=ON
# Run with: ./run_http_benchmarks.sh
# =============================================================================

option(BUILD_HTTP_BENCHMARKS "Build HTTP client benchmark suite (tetsuo-socket vs libcurl)" OFF)

if(BUILD_HTTP_BENCHMARKS)
    # tetsuo-socket HTTP client benchmark (always builds)
    add_executable(benchmark_http_tetsuo src/test/benchmark_http_tetsuo.c)
    target_link_libraries(benchmark_http_tetsuo socket_static pthread)
    message(STATUS "HTTP Benchmarks: Building tetsuo-socket benchmark")

    # libcurl HTTP client benchmark (optional, requires libcurl)
    find_package(CURL QUIET)
    if(CURL_FOUND)
        add_executable(benchmark_http_curl src/test/benchmark_http_curl.c)
        target_link_libraries(benchmark_http_curl CURL::libcurl pthread)
        message(STATUS "HTTP Benchmarks: Building libcurl benchmark (curl ${CURL_VERSION_STRING})")
    else()
        message(STATUS "HTTP Benchmarks: libcurl not found - skipping curl benchmark")
        message(STATUS "  Install libcurl-dev to enable: apt install libcurl4-openssl-dev")
    endif()

    # libevent HTTP client benchmark (optional, requires libevent)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBEVENT QUIET libevent)
    endif()
    if(LIBEVENT_FOUND)
        add_executable(benchmark_http_libevent src/test/benchmark_http_libevent.c)
        target_include_directories(benchmark_http_libevent PRIVATE ${LIBEVENT_INCLUDE_DIRS})
        target_link_libraries(benchmark_http_libevent ${LIBEVENT_LIBRARIES} pthread)
        message(STATUS "HTTP Benchmarks: Building libevent benchmark (libevent ${LIBEVENT_VERSION})")
    else()
        message(STATUS "HTTP Benchmarks: libevent not found - skipping libevent benchmark")
        message(STATUS "  Install libevent-dev to enable: apt install libevent-dev")
    endif()

    # Boost.Beast HTTP client benchmark (optional, requires Boost)
    # Enable C++ for Beast benchmark
    enable_language(CXX)
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    find_package(Boost QUIET COMPONENTS system)
    if(Boost_FOUND)
        # Check if Beast headers exist (Beast is header-only since Boost 1.66)
        if(EXISTS "${Boost_INCLUDE_DIRS}/boost/beast.hpp" OR EXISTS "/usr/include/boost/beast.hpp")
            add_executable(benchmark_http_beast src/test/benchmark_http_beast.cpp)
            target_include_directories(benchmark_http_beast PRIVATE ${Boost_INCLUDE_DIRS})
            target_link_libraries(benchmark_http_beast Boost::system pthread)
            set_target_properties(benchmark_http_beast PROPERTIES CXX_STANDARD 11)
            message(STATUS "HTTP Benchmarks: Building Boost.Beast benchmark (Boost ${Boost_VERSION})")
        else()
            message(STATUS "HTTP Benchmarks: Boost.Beast headers not found - skipping Beast benchmark")
            message(STATUS "  Install libboost-all-dev to enable: apt install libboost-all-dev")
        endif()
    else()
        message(STATUS "HTTP Benchmarks: Boost not found - skipping Beast benchmark")
        message(STATUS "  Install libboost-all-dev to enable: apt install libboost-all-dev")
    endif()
else()
    message(STATUS "HTTP Benchmarks: Disabled (use -DBUILD_HTTP_BENCHMARKS=ON to enable)")
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
        # fuzz_new_features  # TODO: Fix compilation errors
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
        fuzz_http_core
        fuzz_http_headers_collection
        fuzz_http_cookies
        fuzz_http_cookies_simple
        fuzz_http_auth
        fuzz_http_content_type
        fuzz_http_smuggling
        fuzz_http_client
        fuzz_http1_request
        fuzz_http1_response
        fuzz_http1_chunked
        fuzz_http1_headers
        fuzz_http1_serialize
        fuzz_http1_compression
        fuzz_hpack_decode
        fuzz_hpack_huffman
        fuzz_hpack_integer
        fuzz_hpack_encode
        fuzz_http2_frames
        fuzz_http2_frames_full
        fuzz_http2_headers
        fuzz_http2_settings
        fuzz_http2_stream
        fuzz_http2_flow
        fuzz_proxy_socks5
        fuzz_proxy_socks4
        fuzz_proxy_http
        fuzz_proxy_url
        fuzz_dns_inj
        # DNS wire format fuzzing harnesses (issue #141)
        fuzz_dns_header
        fuzz_dns_name
        fuzz_dns_response
        fuzz_dns_edns0
        fuzz_dns_cookie
        fuzz_dns_soa
        fuzz_dns_cache
        fuzz_pool_dos
        fuzz_ws_frame
        fuzz_ws_handshake
        fuzz_websocket_handshake
        fuzz_utf8
        fuzz_ws_deflate
        fuzz_http_server
        fuzz_http2_connection
        fuzz_metrics
        fuzz_security
        # fuzz_new_features  # TODO: Fix compilation errors - references removed APIs
        # DNS advanced fuzzers
        fuzz_dns_config
        fuzz_dns_cookie_client
        fuzz_dns_deadserver
        fuzz_dns_encode
        fuzz_dns_resolver
        fuzz_dns_transport
        fuzz_dnssec
        # Exception/Core fuzzers
        fuzz_except_unwind
        # HTTP client advanced fuzzers
        fuzz_http_client_async
        fuzz_http_client_pool
        fuzz_http_client_retry
        # SYN protection fuzzers
        fuzz_synprotect_ip
        fuzz_synprotect_list
        # QUIC fuzzers (RFC 9000)
        fuzz_quic_varint
        fuzz_quic_error
        fuzz_quic_version
        fuzz_quic_connid
    )
    
    # TLS fuzz harnesses (require SOCKET_HAS_TLS)
    if(SOCKET_HAS_TLS)
        list(APPEND FUZZ_SOURCES
            fuzz_tls_alpn       # ALPN Protocol Negotiation (Section 2.10)
            fuzz_tls_cipher     # Cipher Suite Configuration (Section 2.9)
            fuzz_tls_session
            fuzz_tls_shutdown
            fuzz_tls_certs
            fuzz_tls_verify
            fuzz_tls_verify_callback  # Custom Verification Callbacks (Section 2.4)
            fuzz_tls_sni
            fuzz_tls_io
            fuzz_tls_ocsp
            fuzz_tls_context  # TLS Context Management (Section 2.1-2.3)
            fuzz_tls_protocol_version  # Protocol Version Configuration (Section 2.8)
            fuzz_cert_pinning
            fuzz_tls_crl  # CRL Management (Section 2.5)
            fuzz_tls_error  # OpenSSL Error Formatting (Section 7.2)
            fuzz_tls_record  # TLS Record Layer Parsing (Issue #275)
            fuzz_tls_alert   # TLS Alert Message Processing (Issue #275)
            # DTLS fuzz harnesses
            fuzz_dtls_context
            fuzz_dtls_io
            fuzz_dtls_cookie
            fuzz_dtls_config  # DTLS Configuration (Section 6)
            fuzz_ws_frames
            fuzz_hpack
            fuzz_tls_ct
            fuzz_dtls_handshake
            fuzz_dtls_replay  # DTLS Anti-Replay Window (Issue #275)
            fuzz_dtls_enable_config  # DTLS Enable Configuration
            # TLS internal fuzzers (Issue #275, #277)
            fuzz_tls_handshake
            fuzz_tls_records
            fuzz_tls_config
            fuzz_tls_ktls
            fuzz_tls_key_update
            fuzz_tls_buffer_pool
            fuzz_tls_cert_lookup
            fuzz_ssl_path_validation
            fuzz_certificate_parsing
            fuzz_pin_hex_parsing
            # DNS-over-TLS/HTTPS fuzzers
            fuzz_dns_doh
            fuzz_dns_dot
        )
    endif()
    
    # Create fuzz executable for each harness
    foreach(fuzz_name ${FUZZ_SOURCES})
        if(EXISTS "${CMAKE_SOURCE_DIR}/src/fuzz/${fuzz_name}.c")
            add_executable(${fuzz_name}
                src/fuzz/${fuzz_name}.c
            )

            # Apply fuzzer compile flags
            target_compile_options(${fuzz_name} PRIVATE
                -fsanitize=fuzzer-no-link,address,undefined
                -fno-omit-frame-pointer
                -g
            )

            # Link against instrumented library and apply sanitizer flags
            target_link_libraries(${fuzz_name} socket_fuzz)
            target_link_options(${fuzz_name} PRIVATE
                -fsanitize=fuzzer,address,undefined
            )
            
            target_include_directories(${fuzz_name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
            
            # Pass through necessary compile definitions to fuzzer targets
            if(ZLIB_FOUND)
                target_compile_definitions(${fuzz_name} PRIVATE SOCKETWS_HAS_DEFLATE)
            endif()
            if(SOCKET_HAS_TLS)
                target_compile_definitions(${fuzz_name} PRIVATE SOCKET_HAS_TLS=1)
                target_include_directories(${fuzz_name} PRIVATE ${OPENSSL_INCLUDE_DIR})
            endif()
            
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

# ============================================================================
# Protocol Fuzz Harnesses (for external fuzzers like http2fuzz, tlsfuzzer)
# ============================================================================
option(BUILD_PROTOCOL_FUZZ_HARNESSES "Build protocol-level fuzzing harnesses" OFF)

if(BUILD_PROTOCOL_FUZZ_HARNESSES)
    message(STATUS "Building protocol fuzz harnesses")

    # HTTP/2 server harness (requires TLS)
    if(SOCKET_HAS_TLS)
        add_executable(http2_server_harness
            tests/protocol-fuzz/http2/server_harness.c
        )
        target_link_libraries(http2_server_harness socket_static)
        target_include_directories(http2_server_harness PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${OPENSSL_INCLUDE_DIR}
        )
        target_compile_definitions(http2_server_harness PRIVATE SOCKET_HAS_TLS=1)
        message(STATUS "  http2_server_harness: enabled")

        # TLS server harness
        add_executable(tls_server_harness
            tests/protocol-fuzz/tls/server_harness.c
        )
        target_link_libraries(tls_server_harness socket_static)
        target_include_directories(tls_server_harness PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${OPENSSL_INCLUDE_DIR}
        )
        target_compile_definitions(tls_server_harness PRIVATE SOCKET_HAS_TLS=1)
        message(STATUS "  tls_server_harness: enabled")
    else()
        message(STATUS "  http2_server_harness: disabled (requires TLS)")
        message(STATUS "  tls_server_harness: disabled (requires TLS)")
    endif()

    # DNS resolver harness (no TLS required)
    add_executable(dns_resolver_harness
        tests/protocol-fuzz/dns/resolver_harness.c
    )
    target_link_libraries(dns_resolver_harness socket_static)
    target_include_directories(dns_resolver_harness PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )
    if(SOCKET_HAS_TLS)
        target_compile_definitions(dns_resolver_harness PRIVATE SOCKET_HAS_TLS=1)
        target_include_directories(dns_resolver_harness PRIVATE ${OPENSSL_INCLUDE_DIR})
    endif()
    message(STATUS "  dns_resolver_harness: enabled")

    message(STATUS "Protocol Fuzz Harnesses:")
    message(STATUS "  See tests/protocol-fuzz/README.md for usage")
endif()

# ============================================================================
# Example Programs
# ============================================================================
option(BUILD_EXAMPLES "Build example programs" OFF)

if(BUILD_EXAMPLES)
    find_package(CURL REQUIRED)

    # AI Chat Demo - WebSocket chat with Grok API
    add_executable(ai_chat
        examples/ai_chat/main.c
        examples/ai_chat/grok_client.c
        examples/ai_chat/agents.c
        examples/ai_chat/websocket_hub.c
        examples/ai_chat/async_worker.c
    )
    target_link_libraries(ai_chat socket_static ${CURL_LIBRARIES})
    target_include_directories(ai_chat PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/examples/ai_chat
        ${CURL_INCLUDE_DIRS}
    )
    if(SOCKET_HAS_TLS)
        target_compile_definitions(ai_chat PRIVATE SOCKET_HAS_TLS=1)
        target_include_directories(ai_chat PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(ai_chat ${OPENSSL_LIBRARIES})
    endif()

    message(STATUS "Example programs: enabled")
    message(STATUS "  ai_chat: WebSocket chat with Grok API")
endif()
