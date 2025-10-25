#ifndef SOCKETCONFIG_H
#define SOCKETCONFIG_H

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

/* Arena chunk size */
#ifndef ARENA_CHUNK_SIZE
#define ARENA_CHUNK_SIZE (10 * 1024) /* 10KB */
#endif

/* Maximum allocation size for arena */
#ifndef ARENA_MAX_ALLOC_SIZE
#define ARENA_MAX_ALLOC_SIZE (100 * 1024 * 1024) /* 100MB */
#endif

/* Validation macros with proper parentheses and overflow protection */
#define SOCKET_VALID_PORT(p) ((int)(p) > 0 && (int)(p) <= 65535)
#define SOCKET_VALID_BUFFER_SIZE(s) ((size_t)(s) >= SOCKET_MIN_BUFFER_SIZE && (size_t)(s) <= SOCKET_MAX_BUFFER_SIZE)
#define SOCKET_VALID_CONNECTION_COUNT(c) ((size_t)(c) > 0 && (size_t)(c) <= SOCKET_MAX_CONNECTIONS)
#define SOCKET_VALID_POLL_EVENTS(e) ((int)(e) > 0 && (int)(e) <= SOCKET_MAX_POLL_EVENTS)

/* Safe system call wrappers */
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
        }                                                                                                              \
    } while (0)

#endif /* SOCKETCONFIG_H */
