#ifndef SOCKETCONFIG_LIMITS_INCLUDED
#define SOCKETCONFIG_LIMITS_INCLUDED

/**
 * Socket library configuration limits
 */

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

/* Maximum events per poll */
#ifndef SOCKET_MAX_POLL_EVENTS
#define SOCKET_MAX_POLL_EVENTS 10000
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

/* Maximum number of free chunks to cache for reuse */
#ifndef ARENA_MAX_FREE_CHUNKS
#define ARENA_MAX_FREE_CHUNKS 10
#endif

/* Arena error buffer size for detailed error messages */
#ifndef ARENA_ERROR_BUFSIZE
#define ARENA_ERROR_BUFSIZE 256
#endif

/* Minimum capacity for circular buffers */
#ifndef SOCKETBUF_MIN_CAPACITY
#define SOCKETBUF_MIN_CAPACITY 512
#endif

/* Socket port string buffer size for general use */
#ifndef SOCKET_PORT_STR_BUFSIZE
#define SOCKET_PORT_STR_BUFSIZE 16
#endif

/* Completion pipe read buffer size */
#ifndef SOCKET_DNS_PIPE_BUFFER_SIZE
#define SOCKET_DNS_PIPE_BUFFER_SIZE 256
#endif

/* Poll backend configuration */
#ifndef POLL_INITIAL_FDS
#define POLL_INITIAL_FDS 64
#endif

#ifndef POLL_INITIAL_FD_MAP_SIZE
#define POLL_INITIAL_FD_MAP_SIZE 1024
#endif

#ifndef POLL_FD_MAP_EXPAND_INCREMENT
#define POLL_FD_MAP_EXPAND_INCREMENT 1024
#endif

/* DNS request hash table size - prime number for better distribution */
#ifndef SOCKET_DNS_REQUEST_HASH_SIZE
#define SOCKET_DNS_REQUEST_HASH_SIZE 1021
#endif

/* Port number string buffer size */
#ifndef SOCKET_DNS_PORT_STR_SIZE
#define SOCKET_DNS_PORT_STR_SIZE 16
#endif

/* Error buffer size - increased for safety */
#ifndef SOCKET_ERROR_BUFSIZE
#define SOCKET_ERROR_BUFSIZE 1024
#endif

/* Maximum field sizes for error messages to prevent truncation */
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
#define SOCKET_ERROR_TRUNCATION_SIZE (sizeof(SOCKET_ERROR_TRUNCATION_MARKER))
#endif

#endif /* SOCKETCONFIG_LIMITS_INCLUDED */
