#ifndef SOCKETCONFIG_INCLUDED
#define SOCKETCONFIG_INCLUDED

/**
 * SocketConfig.h - Socket Library Configuration
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header provides compile-time configuration for the socket library
 * including all size limits, platform detection, and socket option mappings.
 */

/* Standard includes required for configuration macros */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* Forward declaration */
extern const char *Socket_safe_strerror (int errnum);

/* ============================================================================
 * Size Limits and Capacity Configuration
 * ============================================================================ */

/* Maximum number of connections in pool (can be overridden at compile time) */
#ifndef SOCKET_MAX_CONNECTIONS
#define SOCKET_MAX_CONNECTIONS 10000UL
#endif

/* Maximum buffer size per connection (can be overridden at compile time) */
#ifndef SOCKET_MAX_BUFFER_SIZE
#define SOCKET_MAX_BUFFER_SIZE (1024 * 1024) /* 1MB */
#endif

/* Minimum buffer size per connection */
#ifndef SOCKET_MIN_BUFFER_SIZE
#define SOCKET_MIN_BUFFER_SIZE 512
#endif

/* UDP limits to avoid fragmentation and respect protocol max */
#ifndef UDP_MAX_PAYLOAD
#define UDP_MAX_PAYLOAD 65507UL /* IPv4/6 max UDP payload excluding headers */
#endif

#ifndef SAFE_UDP_SIZE
#define SAFE_UDP_SIZE 1472UL /* Safe for Ethernet MTU (1500 - IP/UDP ~28) */
#endif

#ifndef SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE
#define SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE 8192
#endif

#ifndef SOCKET_MAX_TTL
#define SOCKET_MAX_TTL 255 /* Standard IP TTL max */
#endif

#ifndef SOCKET_IPV6_MAX_PREFIX
#define SOCKET_IPV6_MAX_PREFIX 128 /* IPv6 address bits */
#endif

#ifndef SOCKET_IPV4_MAX_PREFIX
#define SOCKET_IPV4_MAX_PREFIX 32 /* IPv4 address bits */
#endif

#ifndef SOCKET_MAX_PORT
#define SOCKET_MAX_PORT 65535 /* Standard TCP/UDP port max */
#endif

/* Maximum events per poll */
#ifndef SOCKET_MAX_POLL_EVENTS
#define SOCKET_MAX_POLL_EVENTS 10000
#endif

/* Maximum backlog for listen() */
#ifndef SOCKET_MAX_LISTEN_BACKLOG
#define SOCKET_MAX_LISTEN_BACKLOG 1024
#endif

/* Hash table size for socket data mapping - prime number */
#ifndef SOCKET_HASH_TABLE_SIZE
#define SOCKET_HASH_TABLE_SIZE 1021
#endif

/* ============================================================================
 * Arena Memory Configuration
 * ============================================================================ */

/* Arena chunk size */
#ifndef ARENA_CHUNK_SIZE
#define ARENA_CHUNK_SIZE (10 * 1024) /* 10KB */
#endif

/* Maximum allocation size for arena */
#ifndef ARENA_MAX_ALLOC_SIZE
#define ARENA_MAX_ALLOC_SIZE (100 * 1024 * 1024) /* 100MB */
#endif

/* Maximum number of free chunks to cache for reuse */
#ifndef ARENA_MAX_FREE_CHUNKS
#define ARENA_MAX_FREE_CHUNKS 10
#endif

/* Arena error buffer size for detailed error messages */
#ifndef ARENA_ERROR_BUFSIZE
#define ARENA_ERROR_BUFSIZE 256
#endif

/* ============================================================================
 * Buffer Configuration
 * ============================================================================ */

/* Minimum capacity for circular buffers */
#ifndef SOCKETBUF_MIN_CAPACITY
#define SOCKETBUF_MIN_CAPACITY 512
#endif

/* Initial capacity when buffer reserve grows from zero */
#ifndef SOCKETBUF_INITIAL_CAPACITY
#define SOCKETBUF_INITIAL_CAPACITY 1024
#endif

/* Allocation overhead for arena bookkeeping during buffer resize */
#ifndef SOCKETBUF_ALLOC_OVERHEAD
#define SOCKETBUF_ALLOC_OVERHEAD 64
#endif

/**
 * SOCKETBUF_MAX_CAPACITY - Maximum buffer capacity (SIZE_MAX/2)
 *
 * Conservative limit providing guaranteed safety:
 * - 32-bit systems: max ~2GB (sufficient for network buffers)
 * - 64-bit systems: max ~9 exabytes (effectively unlimited)
 *
 * Prevents integer overflow when calculating buffer sizes.
 */
#ifndef SOCKETBUF_MAX_CAPACITY
#define SOCKETBUF_MAX_CAPACITY (SIZE_MAX / 2)
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

/* DNS request hash table size - prime number */
#ifndef SOCKET_DNS_REQUEST_HASH_SIZE
#define SOCKET_DNS_REQUEST_HASH_SIZE 1021
#endif

/* Completion pipe read buffer size */
#ifndef SOCKET_DNS_PIPE_BUFFER_SIZE
#define SOCKET_DNS_PIPE_BUFFER_SIZE 256
#endif

/* Completion signal byte value for DNS pipe signaling */
#ifndef SOCKET_DNS_COMPLETION_SIGNAL_BYTE
#define SOCKET_DNS_COMPLETION_SIGNAL_BYTE 1
#endif

/* Port number string buffer size */
#ifndef SOCKET_DNS_PORT_STR_SIZE
#define SOCKET_DNS_PORT_STR_SIZE 16
#endif

/* Thread name buffer size (POSIX max 16 chars including null) */
#ifndef SOCKET_DNS_THREAD_NAME_SIZE
#define SOCKET_DNS_THREAD_NAME_SIZE 16
#endif

/* ============================================================================
 * Poll Backend Configuration
 * ============================================================================ */

#ifndef POLL_INITIAL_FDS
#define POLL_INITIAL_FDS 64
#endif

#ifndef POLL_INITIAL_FD_MAP_SIZE
#define POLL_INITIAL_FD_MAP_SIZE 1024
#endif

#ifndef POLL_FD_MAP_EXPAND_INCREMENT
#define POLL_FD_MAP_EXPAND_INCREMENT 1024
#endif

/* ============================================================================
 * Timer Subsystem Configuration
 * ============================================================================ */

/* Maximum timer timeout to prevent indefinite blocking (5 minutes) */
#ifndef SOCKET_MAX_TIMER_TIMEOUT_MS
#define SOCKET_MAX_TIMER_TIMEOUT_MS 300000
#endif

/* Timer error buffer size for detailed error messages */
#ifndef SOCKET_TIMER_ERROR_BUFSIZE
#define SOCKET_TIMER_ERROR_BUFSIZE 256
#endif

/* Initial capacity for timer heap array */
#ifndef SOCKET_TIMER_HEAP_INITIAL_CAPACITY
#define SOCKET_TIMER_HEAP_INITIAL_CAPACITY 16
#endif

/* Growth factor when resizing timer heap (must be > 1) */
#ifndef SOCKET_TIMER_HEAP_GROWTH_FACTOR
#define SOCKET_TIMER_HEAP_GROWTH_FACTOR 2
#endif

/* ============================================================================
 * Event Subsystem Configuration
 * ============================================================================ */

/* Maximum number of event handlers that can be registered */
#ifndef SOCKET_EVENT_MAX_HANDLERS
#define SOCKET_EVENT_MAX_HANDLERS 8
#endif

/* ============================================================================
 * Logging Configuration
 * ============================================================================ */

/* Buffer size for formatted log messages */
#ifndef SOCKET_LOG_BUFFER_SIZE
#define SOCKET_LOG_BUFFER_SIZE 1024
#endif

/* ============================================================================
 * Error Handling Configuration
 * ============================================================================ */

/* Error buffer size */
#ifndef SOCKET_ERROR_BUFSIZE
#define SOCKET_ERROR_BUFSIZE 1024
#endif

/* Maximum field sizes for error messages */
#ifndef SOCKET_ERROR_MAX_HOSTNAME
#define SOCKET_ERROR_MAX_HOSTNAME 255
#endif

#ifndef SOCKET_ERROR_MAX_MESSAGE
#define SOCKET_ERROR_MAX_MESSAGE 512
#endif

/* Truncation marker for error messages */
#ifndef SOCKET_ERROR_TRUNCATION_MARKER
#define SOCKET_ERROR_TRUNCATION_MARKER "... (truncated)"
#endif

#ifndef SOCKET_ERROR_TRUNCATION_SIZE
#define SOCKET_ERROR_TRUNCATION_SIZE (sizeof (SOCKET_ERROR_TRUNCATION_MARKER))
#endif

/* Socket port string buffer size */
#ifndef SOCKET_PORT_STR_BUFSIZE
#define SOCKET_PORT_STR_BUFSIZE 16
#endif

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

#ifndef SOCKET_PERCENTAGE_DIVISOR
#define SOCKET_PERCENTAGE_DIVISOR 100
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
