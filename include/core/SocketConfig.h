#ifndef SOCKETCONFIG_INCLUDED
#define SOCKETCONFIG_INCLUDED

/* Standard includes required for SAFE_CLOSE macro */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

/* Socket library configuration limits */

/* Maximum number of connections in pool (can be overridden at compile time) */
#ifndef SOCKET_MAX_CONNECTIONS
#define SOCKET_MAX_CONNECTIONS 10000
#endif

/* Maximum buffer size per connection (can be overridden at compile time) */
#ifndef SOCKET_MAX_BUFFER_SIZE
#define SOCKET_MAX_BUFFER_SIZE (1024 * 1024) /* 1MB */
#endif

/* Minimum buffer size per connection */
#ifndef SOCKET_MIN_BUFFER_SIZE
#define SOCKET_MIN_BUFFER_SIZE 512
#endif

/* Maximum events per poll */
#ifndef SOCKET_MAX_POLL_EVENTS
#define SOCKET_MAX_POLL_EVENTS 10000
#endif

/* Default idle timeout in seconds */
#ifndef SOCKET_DEFAULT_IDLE_TIMEOUT
#define SOCKET_DEFAULT_IDLE_TIMEOUT 300 /* 5 minutes */
#endif

/* Default poll timeout in milliseconds */
#ifndef SOCKET_DEFAULT_POLL_TIMEOUT
#define SOCKET_DEFAULT_POLL_TIMEOUT 1000 /* 1 second */
#endif

/* Default connection pool settings */
#ifndef SOCKET_DEFAULT_POOL_SIZE
#define SOCKET_DEFAULT_POOL_SIZE 1000
#endif

#ifndef SOCKET_DEFAULT_POOL_BUFSIZE
#define SOCKET_DEFAULT_POOL_BUFSIZE 8192
#endif

/* Maximum backlog for listen() */
#ifndef SOCKET_MAX_LISTEN_BACKLOG
#define SOCKET_MAX_LISTEN_BACKLOG 1024
#endif

/* Hash table size for socket data mapping - prime number for better distribution */
#ifndef SOCKET_HASH_TABLE_SIZE
#define SOCKET_HASH_TABLE_SIZE 1021
#endif

/* Golden ratio constant for multiplicative hashing (2^32 * (sqrt(5)-1)/2) */
#ifndef HASH_GOLDEN_RATIO
#define HASH_GOLDEN_RATIO 2654435761u
#endif

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

/* Arena alignment size - size of union align for proper alignment */
#ifndef ARENA_ALIGNMENT_SIZE
#define ARENA_ALIGNMENT_SIZE sizeof(union align)
#endif

/* Arena validation constants */
#ifndef ARENA_VALIDATION_SUCCESS
#define ARENA_VALIDATION_SUCCESS 1
#endif

#ifndef ARENA_VALIDATION_FAILURE
#define ARENA_VALIDATION_FAILURE 0
#endif

/* Arena operation return codes */
#ifndef ARENA_SUCCESS
#define ARENA_SUCCESS 0
#endif

#ifndef ARENA_FAILURE
#define ARENA_FAILURE -1
#endif

/* Arena reuse chunk return codes */
#ifndef ARENA_CHUNK_REUSED
#define ARENA_CHUNK_REUSED 1
#endif

#ifndef ARENA_CHUNK_NOT_REUSED
#define ARENA_CHUNK_NOT_REUSED 0
#endif

/* Arena size validation return codes */
#ifndef ARENA_SIZE_VALID
#define ARENA_SIZE_VALID 1
#endif

#ifndef ARENA_SIZE_INVALID
#define ARENA_SIZE_INVALID 0
#endif

/* Arena error message constants */
#ifndef ARENA_ENOMEM
#define ARENA_ENOMEM "Out of memory"
#endif

/* Async DNS resolution configuration */
#ifndef SOCKET_DNS_THREAD_COUNT
#define SOCKET_DNS_THREAD_COUNT 4
#endif

#ifndef SOCKET_DNS_MAX_PENDING
#define SOCKET_DNS_MAX_PENDING 1000
#endif

#ifndef SOCKET_DNS_TIMEOUT_SEC
#define SOCKET_DNS_TIMEOUT_SEC 5
#endif

/* DNS request hash table size - prime number for better distribution */
#ifndef SOCKET_DNS_REQUEST_HASH_SIZE
#define SOCKET_DNS_REQUEST_HASH_SIZE 1021
#endif

/* Port number string buffer size (sufficient for "65535" + null terminator) */
#ifndef SOCKET_DNS_PORT_STR_SIZE
#define SOCKET_DNS_PORT_STR_SIZE 16
#endif

/* Socket port string buffer size for general use */
#ifndef SOCKET_PORT_STR_BUFSIZE
#define SOCKET_PORT_STR_BUFSIZE 16
#endif

/* Minimum capacity for circular buffers */
#ifndef SOCKETBUF_MIN_CAPACITY
#define SOCKETBUF_MIN_CAPACITY 512
#endif

/* Socket types */
#define SOCKET_STREAM_TYPE SOCK_STREAM
#define SOCKET_DGRAM_TYPE SOCK_DGRAM

/* Address family constants */
#define SOCKET_AF_UNSPEC AF_UNSPEC
#define SOCKET_AF_INET AF_INET
#define SOCKET_AF_INET6 AF_INET6
#define SOCKET_AF_UNIX AF_UNIX

/* Protocol constants */
#define SOCKET_IPPROTO_TCP IPPROTO_TCP
#define SOCKET_IPPROTO_UDP IPPROTO_UDP
#define SOCKET_IPPROTO_IP IPPROTO_IP
#define SOCKET_IPPROTO_IPV6 IPPROTO_IPV6

/* Socket options */
#define SOCKET_SOL_SOCKET SOL_SOCKET
#define SOCKET_SO_REUSEADDR SO_REUSEADDR
#define SOCKET_SO_BROADCAST SO_BROADCAST
#define SOCKET_SO_KEEPALIVE SO_KEEPALIVE
#define SOCKET_SO_RCVTIMEO SO_RCVTIMEO
#define SOCKET_SO_SNDTIMEO SO_SNDTIMEO
#define SOCKET_SO_DOMAIN SO_DOMAIN
#define SOCKET_SO_PEERCRED SO_PEERCRED

/* TCP options */
#define SOCKET_TCP_NODELAY TCP_NODELAY
#define SOCKET_TCP_KEEPIDLE TCP_KEEPIDLE
#define SOCKET_TCP_KEEPINTVL TCP_KEEPINTVL
#define SOCKET_TCP_KEEPCNT TCP_KEEPCNT

/* IPv6 options */
#define SOCKET_IPV6_V6ONLY IPV6_V6ONLY
#define SOCKET_IPV6_ADD_MEMBERSHIP IPV6_ADD_MEMBERSHIP
#define SOCKET_IPV6_DROP_MEMBERSHIP IPV6_DROP_MEMBERSHIP
#define SOCKET_IPV6_UNICAST_HOPS IPV6_UNICAST_HOPS

/* IP options */
#define SOCKET_IP_TTL IP_TTL
#define SOCKET_IP_ADD_MEMBERSHIP IP_ADD_MEMBERSHIP
#define SOCKET_IP_DROP_MEMBERSHIP IP_DROP_MEMBERSHIP

/* Address info flags */
#define SOCKET_AI_PASSIVE AI_PASSIVE
#define SOCKET_AI_NUMERICHOST AI_NUMERICHOST
#define SOCKET_AI_NUMERICSERV AI_NUMERICSERV

/* Name info flags */
#define SOCKET_NI_NUMERICHOST NI_NUMERICHOST
#define SOCKET_NI_NUMERICSERV NI_NUMERICSERV

/* Maximum lengths for name info */
#define SOCKET_NI_MAXHOST NI_MAXHOST
#define SOCKET_NI_MAXSERV NI_MAXSERV

/* Message flags */
#define SOCKET_MSG_NOSIGNAL MSG_NOSIGNAL

/* Default keepalive parameters */
#define SOCKET_DEFAULT_KEEPALIVE_IDLE 60
#define SOCKET_DEFAULT_KEEPALIVE_INTERVAL 10
#define SOCKET_DEFAULT_KEEPALIVE_COUNT 3

/* Default TTL for datagrams */
#define SOCKET_DEFAULT_DATAGRAM_TTL 64

/* Multicast interface index */
#define SOCKET_MULTICAST_DEFAULT_INTERFACE 0

/* Completion pipe read buffer size */
#ifndef SOCKET_DNS_PIPE_BUFFER_SIZE
#define SOCKET_DNS_PIPE_BUFFER_SIZE 256
#endif

/* Poll backend configuration */

/* Initial pollfd array size for poll(2) backend */
#ifndef POLL_INITIAL_FDS
#define POLL_INITIAL_FDS 64
#endif

/* Initial file descriptor mapping table size for poll backend */
#ifndef POLL_INITIAL_FD_MAP_SIZE
#define POLL_INITIAL_FD_MAP_SIZE 1024
#endif

/* File descriptor mapping table expansion increment */
#ifndef POLL_FD_MAP_EXPAND_INCREMENT
#define POLL_FD_MAP_EXPAND_INCREMENT 1024
#endif

/* Validation macros with proper parentheses and overflow protection */
#define SOCKET_VALID_PORT(p) ((int)(p) > 0 && (int)(p) <= 65535)
#define SOCKET_VALID_BUFFER_SIZE(s) ((size_t)(s) >= SOCKET_MIN_BUFFER_SIZE && (size_t)(s) <= SOCKET_MAX_BUFFER_SIZE)
#define SOCKET_VALID_CONNECTION_COUNT(c) ((size_t)(c) > 0 && (size_t)(c) <= SOCKET_MAX_CONNECTIONS)
#define SOCKET_VALID_POLL_EVENTS(e) ((int)(e) > 0 && (int)(e) <= SOCKET_MAX_POLL_EVENTS)

/* Safe system call wrappers
 *
 * SAFE_CLOSE: Close file descriptor with proper EINTR handling
 *
 * Per POSIX.1-2008: Do NOT retry close() on EINTR. The file descriptor
 * state is unspecified after close() returns with EINTR - it may or may
 * not be closed. Retrying could close a different FD if the descriptor
 * was reused by another thread. We treat EINTR as success (don't log error)
 * since the FD is likely closed anyway.
 *
 * Reference: POSIX.1-2008, close() specification, Application Usage
 */
#define SAFE_CLOSE(fd)                                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((fd) >= 0)                                                                                                 \
        {                                                                                                              \
            int _safe_close_result = close(fd);                                                                        \
            if (_safe_close_result < 0 && errno != EINTR)                                                              \
            {                                                                                                          \
                /* Log error but don't fail - fd is closed anyway */                                                   \
                perror("close");                                                                                       \
            }                                                                                                          \
            /* EINTR is silently treated as success - FD is likely closed */                                           \
        }                                                                                                              \
    } while (0)

#endif /* SOCKETCONFIG_INCLUDED */
