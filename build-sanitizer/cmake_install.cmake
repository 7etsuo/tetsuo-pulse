# Install script for directory: /home/tetsuo/git/tetsuo-socket

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/tetsuo/git/tetsuo-socket/build-sanitizer/libsocket.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsocket.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsocket.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsocket.so"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/home/tetsuo/git/tetsuo-socket/build-sanitizer/libsocket.so")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsocket.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsocket.so")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libsocket.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/core" TYPE FILE FILES
    "/home/tetsuo/git/tetsuo-socket/include/core/Arena.h"
    "/home/tetsuo/git/tetsuo-socket/include/core/Except.h"
    "/home/tetsuo/git/tetsuo-socket/include/core/SocketConfig.h"
    "/home/tetsuo/git/tetsuo-socket/include/core/SocketUtil.h"
    "/home/tetsuo/git/tetsuo-socket/include/core/SocketTimer.h"
    "/home/tetsuo/git/tetsuo-socket/include/core/SocketTimer-private.h"
    "/home/tetsuo/git/tetsuo-socket/include/core/SocketRateLimit.h"
    "/home/tetsuo/git/tetsuo-socket/include/core/SocketRateLimit-private.h"
    "/home/tetsuo/git/tetsuo-socket/include/core/SocketIPTracker.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/socket" TYPE FILE FILES
    "/home/tetsuo/git/tetsuo-socket/include/socket/Socket.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/Socket-private.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketAsync.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketBuf.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketCommon.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketDgram.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketIO.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketHappyEyeballs.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketHappyEyeballs-private.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketReconnect.h"
    "/home/tetsuo/git/tetsuo-socket/include/socket/SocketReconnect-private.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/dns" TYPE FILE FILES "/home/tetsuo/git/tetsuo-socket/include/dns/SocketDNS.h")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/poll" TYPE FILE FILES
    "/home/tetsuo/git/tetsuo-socket/include/poll/SocketPoll.h"
    "/home/tetsuo/git/tetsuo-socket/include/poll/SocketPoll-private.h"
    "/home/tetsuo/git/tetsuo-socket/include/poll/SocketPoll_backend.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/pool" TYPE FILE FILES
    "/home/tetsuo/git/tetsuo-socket/include/pool/SocketPool.h"
    "/home/tetsuo/git/tetsuo-socket/include/pool/SocketPool-private.h"
    "/home/tetsuo/git/tetsuo-socket/include/pool/SocketPool-core.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/tls" TYPE FILE FILES
    "/home/tetsuo/git/tetsuo-socket/include/tls/SocketTLS.h"
    "/home/tetsuo/git/tetsuo-socket/include/tls/SocketTLSConfig.h"
    "/home/tetsuo/git/tetsuo-socket/include/tls/SocketTLSContext.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/test" TYPE FILE FILES "/home/tetsuo/git/tetsuo-socket/include/test/Test.h")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/tetsuo/git/tetsuo-socket/build-sanitizer/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
