#ifndef SOCKETCONFIG_INCLUDED
#define SOCKETCONFIG_INCLUDED

/**
 * SocketConfig.h - Socket Library Configuration
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header provides compile-time configuration for the socket library.
 * Limit constants are defined in SocketConfig-limits.h.
 * Platform detection and socket option mappings are defined here.
 */

/* Standard includes required for configuration macros */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* Include limit constants - single source of truth */
#include "SocketConfig-limits.h"

/* Forward declaration */
extern const char *Socket_safe_strerror (int errnum);

/* ============================================================================
 * Platform Detection
 * ============================================================================ */

#ifdef __APPLE__
#define SOCKET_PLATFORM_MACOS 1
#else
#define SOCKET_PLATFORM_MACOS 0
#endif

/* IOV_MAX fallback if not defined */
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

/* sendmsg/recvmsg are standard POSIX - always available */
#define SOCKET_HAS_SENDMSG 1
#define SOCKET_HAS_RECVMSG 1

/* ============================================================================
 * Timeout Configuration
 * ============================================================================ */

#ifndef SOCKET_DEFAULT_CONNECT_TIMEOUT_MS
#define SOCKET_DEFAULT_CONNECT_TIMEOUT_MS 30000 /* 30 seconds */
#endif

#ifndef SOCKET_DEFAULT_DNS_TIMEOUT_MS
#define SOCKET_DEFAULT_DNS_TIMEOUT_MS 5000 /* 5 seconds */
#endif

#ifndef SOCKET_DEFAULT_OPERATION_TIMEOUT_MS
#define SOCKET_DEFAULT_OPERATION_TIMEOUT_MS 0 /* Infinite */
#endif

#ifndef SOCKET_DEFAULT_IDLE_TIMEOUT
#define SOCKET_DEFAULT_IDLE_TIMEOUT 300 /* 5 minutes */
#endif

#ifndef SOCKET_DEFAULT_POLL_TIMEOUT
#define SOCKET_DEFAULT_POLL_TIMEOUT 1000 /* 1 second */
#endif

/**
 * SocketTimeouts_T - Timeout configuration structure
 */
typedef struct SocketTimeouts
{
  int connect_timeout_ms;   /**< Connect timeout in ms (0 = infinite) */
  int dns_timeout_ms;       /**< DNS resolution timeout in ms (0 = infinite) */
  int operation_timeout_ms; /**< General operation timeout in ms (0 = infinite) */
} SocketTimeouts_T;

/* ============================================================================
 * Pool Configuration
 * ============================================================================ */

#ifndef SOCKET_DEFAULT_POOL_SIZE
#define SOCKET_DEFAULT_POOL_SIZE 1000
#endif

#ifndef SOCKET_DEFAULT_POOL_BUFSIZE
#define SOCKET_DEFAULT_POOL_BUFSIZE 8192
#endif

#ifndef SOCKET_POOL_DEFAULT_PREWARM_PCT
#define SOCKET_POOL_DEFAULT_PREWARM_PCT 20
#endif

#ifndef SOCKET_POOL_MAX_BATCH_ACCEPTS
#define SOCKET_POOL_MAX_BATCH_ACCEPTS 1000
#endif

/* ============================================================================
 * Hash and Algorithm Constants
 * ============================================================================ */

/* Golden ratio constant for multiplicative hashing (2^32 * (sqrt(5)-1)/2) */
#ifndef HASH_GOLDEN_RATIO
#define HASH_GOLDEN_RATIO 2654435761u
#endif

/* ============================================================================
 * Arena Memory Alignment
 * ============================================================================ */

/* Alignment union - ensures proper alignment for all data types */
union align
{
  int i;
  long l;
  long *lp;
  void *p;
  void (*fp) (void);
  float f;
  double d;
  long double ld;
};

#ifndef ARENA_ALIGNMENT_SIZE
#define ARENA_ALIGNMENT_SIZE sizeof (union align)
#endif

/* Arena validation and return codes */
#ifndef ARENA_VALIDATION_SUCCESS
#define ARENA_VALIDATION_SUCCESS 1
#endif

#ifndef ARENA_VALIDATION_FAILURE
#define ARENA_VALIDATION_FAILURE 0
#endif

#ifndef ARENA_SUCCESS
#define ARENA_SUCCESS 0
#endif

#ifndef ARENA_FAILURE
#define ARENA_FAILURE -1
#endif

#ifndef ARENA_CHUNK_REUSED
#define ARENA_CHUNK_REUSED 1
#endif

#ifndef ARENA_CHUNK_NOT_REUSED
#define ARENA_CHUNK_NOT_REUSED 0
#endif

#ifndef ARENA_SIZE_VALID
#define ARENA_SIZE_VALID 1
#endif

#ifndef ARENA_SIZE_INVALID
#define ARENA_SIZE_INVALID 0
#endif

#ifndef ARENA_ENOMEM
#define ARENA_ENOMEM "Out of memory"
#endif

/* ============================================================================
 * DNS Configuration
 * ============================================================================ */

#ifndef SOCKET_DNS_THREAD_COUNT
#define SOCKET_DNS_THREAD_COUNT 4
#endif

#ifndef SOCKET_DNS_MAX_PENDING
#define SOCKET_DNS_MAX_PENDING 1000
#endif

#ifndef SOCKET_DNS_MAX_LABEL_LENGTH
#define SOCKET_DNS_MAX_LABEL_LENGTH 63
#endif

#ifndef SOCKET_DNS_WORKER_STACK_SIZE
#define SOCKET_DNS_WORKER_STACK_SIZE (128 * 1024)
#endif

/* ============================================================================
 * Time Conversion Constants
 * ============================================================================ */

#define SOCKET_MS_PER_SECOND 1000
#define SOCKET_NS_PER_MS 1000000LL

/* ============================================================================
 * Async I/O Configuration
 * ============================================================================ */

#define SOCKET_DEFAULT_IO_URING_ENTRIES 1024
#define SOCKET_MAX_EVENT_BATCH 100

/* ============================================================================
 * String Conversion Macros
 * ============================================================================ */

#define SOCKET_STRINGIFY(x) #x
#define SOCKET_TO_STRING(x) SOCKET_STRINGIFY (x)

#define SOCKET_PORT_VALID_RANGE "1-" SOCKET_TO_STRING (SOCKET_MAX_PORT)
#define SOCKET_TTL_VALID_RANGE "1-" SOCKET_TO_STRING (SOCKET_MAX_TTL)
#define SOCKET_IPV4_PREFIX_RANGE "0-" SOCKET_TO_STRING (SOCKET_IPV4_MAX_PREFIX)
#define SOCKET_IPV6_PREFIX_RANGE "0-" SOCKET_TO_STRING (SOCKET_IPV6_MAX_PREFIX)

/* ============================================================================
 * Socket Type and Family Constants
 * ============================================================================ */

#define SOCKET_STREAM_TYPE SOCK_STREAM
#define SOCKET_DGRAM_TYPE SOCK_DGRAM

#define SOCKET_AF_UNSPEC AF_UNSPEC
#define SOCKET_AF_INET AF_INET
#define SOCKET_AF_INET6 AF_INET6
#define SOCKET_AF_UNIX AF_UNIX

#define SOCKET_IPPROTO_TCP IPPROTO_TCP
#define SOCKET_IPPROTO_UDP IPPROTO_UDP
#define SOCKET_IPPROTO_IP IPPROTO_IP
#define SOCKET_IPPROTO_IPV6 IPPROTO_IPV6

/* ============================================================================
 * Socket Options
 * ============================================================================ */

#define SOCKET_SOL_SOCKET SOL_SOCKET
#define SOCKET_SO_REUSEADDR SO_REUSEADDR

#ifdef SO_REUSEPORT
#define SOCKET_SO_REUSEPORT SO_REUSEPORT
#define SOCKET_HAS_SO_REUSEPORT 1
#else
#define SOCKET_SO_REUSEPORT 0
#define SOCKET_HAS_SO_REUSEPORT 0
#endif

#ifdef SOCK_CLOEXEC
#define SOCKET_SOCK_CLOEXEC SOCK_CLOEXEC
#define SOCKET_HAS_SOCK_CLOEXEC 1
#else
#define SOCKET_SOCK_CLOEXEC 0
#define SOCKET_HAS_SOCK_CLOEXEC 0
#endif

#ifdef __linux__
#define SOCKET_HAS_ACCEPT4 1
#define SOCKET_SO_DOMAIN SO_DOMAIN
#define SOCKET_HAS_SO_DOMAIN 1
#else
#define SOCKET_HAS_ACCEPT4 0
#define SOCKET_HAS_SO_DOMAIN 0
#endif

#define SOCKET_FD_CLOEXEC FD_CLOEXEC
#define SOCKET_SO_BROADCAST SO_BROADCAST
#define SOCKET_SO_KEEPALIVE SO_KEEPALIVE
#define SOCKET_SO_RCVTIMEO SO_RCVTIMEO
#define SOCKET_SO_SNDTIMEO SO_SNDTIMEO
#define SOCKET_SO_RCVBUF SO_RCVBUF
#define SOCKET_SO_SNDBUF SO_SNDBUF
#define SOCKET_SO_PEERCRED SO_PEERCRED

/* ============================================================================
 * TCP Options
 * ============================================================================ */

#define SOCKET_TCP_NODELAY TCP_NODELAY
#define SOCKET_TCP_KEEPIDLE TCP_KEEPIDLE
#define SOCKET_TCP_KEEPINTVL TCP_KEEPINTVL
#define SOCKET_TCP_KEEPCNT TCP_KEEPCNT

#ifdef TCP_CONGESTION
#define SOCKET_TCP_CONGESTION TCP_CONGESTION
#define SOCKET_HAS_TCP_CONGESTION 1
#else
#define SOCKET_HAS_TCP_CONGESTION 0
#endif

#ifdef TCP_FASTOPEN
#define SOCKET_TCP_FASTOPEN TCP_FASTOPEN
#define SOCKET_HAS_TCP_FASTOPEN 1
#elif defined(TCP_FASTOPEN_CONNECT)
#define SOCKET_TCP_FASTOPEN TCP_FASTOPEN_CONNECT
#define SOCKET_HAS_TCP_FASTOPEN 1
#else
#define SOCKET_HAS_TCP_FASTOPEN 0
#endif

#ifdef TCP_USER_TIMEOUT
#define SOCKET_TCP_USER_TIMEOUT TCP_USER_TIMEOUT
#define SOCKET_HAS_TCP_USER_TIMEOUT 1
#else
#define SOCKET_HAS_TCP_USER_TIMEOUT 0
#endif

/* ============================================================================
 * IPv6 Options
 * ============================================================================ */

#define SOCKET_IPV6_V6ONLY IPV6_V6ONLY

#ifdef IPV6_ADD_MEMBERSHIP
#define SOCKET_IPV6_ADD_MEMBERSHIP IPV6_ADD_MEMBERSHIP
#elif defined(IPV6_JOIN_GROUP)
#define SOCKET_IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#else
#error "IPv6 multicast add membership not supported on this platform"
#endif

#ifdef IPV6_DROP_MEMBERSHIP
#define SOCKET_IPV6_DROP_MEMBERSHIP IPV6_DROP_MEMBERSHIP
#elif defined(IPV6_LEAVE_GROUP)
#define SOCKET_IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#else
#error "IPv6 multicast drop membership not supported on this platform"
#endif

#define SOCKET_IPV6_UNICAST_HOPS IPV6_UNICAST_HOPS

/* ============================================================================
 * IP Options
 * ============================================================================ */

#define SOCKET_IP_TTL IP_TTL
#define SOCKET_IP_ADD_MEMBERSHIP IP_ADD_MEMBERSHIP
#define SOCKET_IP_DROP_MEMBERSHIP IP_DROP_MEMBERSHIP

/* ============================================================================
 * Address and Name Info Flags
 * ============================================================================ */

#define SOCKET_AI_PASSIVE AI_PASSIVE
#define SOCKET_AI_NUMERICHOST AI_NUMERICHOST
#define SOCKET_AI_NUMERICSERV AI_NUMERICSERV
#define SOCKET_NI_NUMERICHOST NI_NUMERICHOST
#define SOCKET_NI_NUMERICSERV NI_NUMERICSERV
#define SOCKET_NI_MAXHOST NI_MAXHOST
#define SOCKET_NI_MAXSERV NI_MAXSERV

/* ============================================================================
 * Shutdown and Message Flags
 * ============================================================================ */

#define SOCKET_SHUT_RD SHUT_RD
#define SOCKET_SHUT_WR SHUT_WR
#define SOCKET_SHUT_RDWR SHUT_RDWR
#define SOCKET_MSG_NOSIGNAL MSG_NOSIGNAL

/* ============================================================================
 * Default Parameters
 * ============================================================================ */

#define SOCKET_DEFAULT_KEEPALIVE_IDLE 60
#define SOCKET_DEFAULT_KEEPALIVE_INTERVAL 10
#define SOCKET_DEFAULT_KEEPALIVE_COUNT 3
#define SOCKET_DEFAULT_DATAGRAM_TTL 64
#define SOCKET_MULTICAST_DEFAULT_INTERFACE 0

/* Validation macros */
#define SOCKET_VALID_PORT(p) ((int)(p) >= 0 && (int)(p) <= 65535)
#define SOCKET_VALID_BUFFER_SIZE(s)                                           \
  ((size_t)(s) >= SOCKET_MIN_BUFFER_SIZE && (size_t)(s) <= SOCKET_MAX_BUFFER_SIZE)
#define SOCKET_VALID_CONNECTION_COUNT(c)                                      \
  ((size_t)(c) > 0 && (size_t)(c) <= SOCKET_MAX_CONNECTIONS)
#define SOCKET_VALID_POLL_EVENTS(e)                                           \
  ((int)(e) > 0 && (int)(e) <= SOCKET_MAX_POLL_EVENTS)

/* SAFE_CLOSE - Close fd with POSIX.1-2008 EINTR handling (no retry) */
#define SAFE_CLOSE(fd)                                                        \
  do                                                                          \
    {                                                                         \
      if ((fd) >= 0)                                                          \
        {                                                                     \
          int _r = close (fd);                                                \
          if (_r < 0 && errno != EINTR)                                       \
            fprintf (stderr, "close failed: %s\n", Socket_safe_strerror (errno)); \
        }                                                                     \
    }                                                                         \
  while (0)

#endif /* SOCKETCONFIG_INCLUDED */
