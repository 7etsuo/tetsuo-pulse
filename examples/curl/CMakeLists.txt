cmake_minimum_required(VERSION 3.14)
project(tcurl VERSION 1.0.0 LANGUAGES C)

# Generate compile_commands.json for IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C11 with GNU extensions (required by tetsuo-socket)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -D_GNU_SOURCE -pthread -fno-strict-aliasing")
set(CMAKE_C_FLAGS_DEBUG "-g -Og")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Default to Release build
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Option to enable sanitizers for development
option(ENABLE_SANITIZERS "Enable ASan + UBSan" OFF)

if(ENABLE_SANITIZERS)
    message(STATUS "Sanitizers enabled (ASan + UBSan)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address,undefined -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

#==============================================================================
# Find tetsuo-socket library
#==============================================================================

# Check if we're building from within the tetsuo-socket repo
set(SOCKET_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(SOCKET_BUILD_DIR "${SOCKET_SOURCE_DIR}/build")

if(EXISTS "${SOCKET_SOURCE_DIR}/include/socket/Socket.h" AND EXISTS "${SOCKET_BUILD_DIR}/libsocket.a")
    # We're in examples/curl/ within the main repo and library is built
    message(STATUS "Using local tetsuo-socket build")
    message(STATUS "  Source:  ${SOCKET_SOURCE_DIR}")
    message(STATUS "  Build:   ${SOCKET_BUILD_DIR}")

    set(SOCKET_INCLUDE_DIRS "${SOCKET_SOURCE_DIR}/include")
    set(SOCKET_LIBRARIES "${SOCKET_BUILD_DIR}/libsocket.a")
    set(SOCKET_FOUND TRUE)

elseif(EXISTS "${SOCKET_SOURCE_DIR}/include/socket/Socket.h")
    # Source exists but not built - tell user to build first
    message(FATAL_ERROR
        "tetsuo-socket library not built.\n"
        "Please build the library first:\n"
        "  cd ${SOCKET_SOURCE_DIR}\n"
        "  cmake -S . -B build -DENABLE_TLS=ON\n"
        "  cmake --build build -j$(nproc)\n"
        "Then return here and run cmake again.")

else()
    # Not in repo - try pkg-config
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SOCKET libsocket)
    endif()

    if(SOCKET_FOUND)
        message(STATUS "Using system tetsuo-socket via pkg-config")
        message(STATUS "  Include dirs: ${SOCKET_INCLUDE_DIRS}")
        message(STATUS "  Libraries: ${SOCKET_LIBRARIES}")
    else()
        # Try FetchContent as last resort
        message(STATUS "Fetching tetsuo-socket from GitHub...")
        include(FetchContent)

        FetchContent_Declare(
            tetsuo_socket
            GIT_REPOSITORY https://github.com/7etsuo/tetsuo-pulse.git
            GIT_TAG        main
            GIT_SHALLOW    TRUE
        )

        # Configure tetsuo-socket options before fetching
        set(ENABLE_TLS ON CACHE BOOL "Enable TLS support" FORCE)
        set(BUILD_TESTING OFF CACHE BOOL "Disable tests for subdirectory build" FORCE)

        FetchContent_MakeAvailable(tetsuo_socket)

        set(SOCKET_INCLUDE_DIRS "${tetsuo_socket_SOURCE_DIR}/include")
        set(SOCKET_LIBRARIES socket_static)
        set(SOCKET_FOUND TRUE)
    endif()
endif()

#==============================================================================
# Dependencies
#==============================================================================

# Find OpenSSL for TLS support
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    message(STATUS "TLS support enabled (OpenSSL ${OPENSSL_VERSION})")
    add_compile_definitions(SOCKET_HAS_TLS=1)
else()
    message(STATUS "TLS support disabled (OpenSSL not found)")
    add_compile_definitions(SOCKET_HAS_TLS=0)
endif()

# Find zlib for compression
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
    message(STATUS "Compression support enabled (zlib)")
    add_compile_definitions(SOCKETHTTP1_HAS_ZLIB=1)
else()
    add_compile_definitions(SOCKETHTTP1_HAS_ZLIB=0)
endif()

#==============================================================================
# tcurl executable
#==============================================================================

set(TCURL_SOURCES
    src/curl_main.c
    src/curl_args.c
    src/StreamingCurl.c
    src/StreamingCurl_auth.c
    src/StreamingCurl_connect.c
    src/StreamingCurl_cookie.c
    src/StreamingCurl_decomp.c
    src/StreamingCurl_h1.c
    src/StreamingCurl_h2.c
    src/StreamingCurl_redirect.c
    src/StreamingCurl_request.c
    src/StreamingCurl_url.c
)

add_executable(tcurl ${TCURL_SOURCES})

# Include directories:
# - Local headers: include/ contains curl/ subdirectory
#   So "curl/StreamingCurl.h" resolves to include/curl/StreamingCurl.h
# - tetsuo-socket library headers (core/, http/, socket/, tls/, etc.)
target_include_directories(tcurl PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SOCKET_INCLUDE_DIRS}
)

# Link against tetsuo-socket and system libraries
target_link_libraries(tcurl PRIVATE
    ${SOCKET_LIBRARIES}
    pthread
    m
)

# Platform-specific libraries
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(tcurl PRIVATE dl)
endif()

# Optional dependencies
if(OpenSSL_FOUND)
    target_link_libraries(tcurl PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

if(ZLIB_FOUND)
    target_link_libraries(tcurl PRIVATE ZLIB::ZLIB)
endif()

#==============================================================================
# Installation
#==============================================================================

install(TARGETS tcurl DESTINATION bin)

#==============================================================================
# Summary
#==============================================================================

message(STATUS "")
message(STATUS "tcurl configuration:")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  TLS support:    ${OpenSSL_FOUND}")
message(STATUS "  Compression:    ${ZLIB_FOUND}")
message(STATUS "  Sanitizers:     ${ENABLE_SANITIZERS}")
message(STATUS "")
message(STATUS "Build with: cmake --build build -j$(nproc)")
message(STATUS "")
