#ifndef SOCKETCOMMON_PRIVATE_INCLUDED
#define SOCKETCOMMON_PRIVATE_INCLUDED

/**
 * SocketCommon-private.h - Private declarations for SocketCommon module
 * 
 * Includes internal structure definitions and static helper functions.
 * Include only from SocketCommon.c and related module .c files (Socket.c, SocketDgram.c, etc.).
 * Do NOT include from public headers or user code.
 * 
 * Coding Standards Compliance:
 * - Opaque types defined in public .h, structs here.
 * - GNU C style: Doxygen comments, return types separate.
 * - Thread-local variables and exceptions per module rules.
 */

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/SocketCommon.h"
#include <stdbool.h>
#include "socket/Socket.h"  /* For SocketTimeouts_T if not in config */

/* Private structure for SocketBase_T */
struct SocketBase_T
{
  int fd;                              /**< Socket file descriptor (-1 if closed) */
  Arena_T arena;                       /**< Per-socket memory arena for lifecycle */
  int domain;                          /**< Address domain (AF_INET, AF_INET6, AF_UNIX) */
  int type;                            /**< Socket type (SOCK_STREAM, SOCK_DGRAM) */
  int protocol;                        /**< Protocol (0 for default) */
  pthread_mutex_t mutex;               /**< Mutex for thread-safe base access (options, endpoints) */
  
  /* Endpoint information */
  struct sockaddr_storage local_addr;  /**< Local bound address */
  socklen_t local_addrlen;             /**< Length of local_addr */
  char *localaddr;                     /**< String representation of local address (allocated in arena) */
  int localport;                       /**< Local port number */
  
  struct sockaddr_storage remote_addr; /**< Remote peer address */
  socklen_t remote_addrlen;            /**< Length of remote_addr */
  char *remoteaddr;                    /**< String representation of remote address (allocated in arena) */
  int remoteport;                      /**< Remote port number */
  
  SocketTimeouts_T timeouts;           /**< Timeout configuration */
  
  SocketMetricsSnapshot metrics;       /**< Per-socket metrics snapshot */
  
  /* Additional common fields can be added here */
  /* e.g., bool is_nonblock; int refcount; etc. */
};

/* Accessors for private fields - defined in SocketCommon.c */
extern int SocketBase_fd (SocketBase_T base);
extern Arena_T SocketBase_arena (SocketBase_T base);
extern int SocketBase_domain (SocketBase_T base);

static inline char *
SocketBase_remoteaddr (SocketBase_T base)
{
  return base ? base->remoteaddr : NULL;
}

static inline int
SocketBase_remoteport (SocketBase_T base)
{
  return base ? base->remoteport : 0;
}

static inline char *
SocketBase_localaddr (SocketBase_T base)
{
  return base ? base->localaddr : NULL;
}

static inline int
SocketBase_localport (SocketBase_T base)
{
  return base ? base->localport : 0;
}

static inline SocketTimeouts_T *
SocketBase_timeouts (SocketBase_T base)
{
  return base ? &base->timeouts : NULL;
}

/* Add more as needed for endpoint fields */
extern void SocketBase_set_timeouts (SocketBase_T base, const SocketTimeouts_T *timeouts);

/* ... add more extern decls for getters/setters as needed */

/* Private functions for base management */
extern int SocketCommon_create_fd (int domain, int type, int protocol, Except_T exc_type);
extern void SocketCommon_init_base (SocketBase_T base, int fd, int domain, int type, int protocol, Except_T exc_type);

extern int SocketCommon_get_family (SocketBase_T base, bool raise_on_fail, Except_T exc_type); /* Unifies family detection, raises or returns AF_UNSPEC */

/* Shared socket option functions - consolidate duplicate implementations */
extern void SocketCommon_setreuseaddr (SocketBase_T base, Except_T exc_type);
extern void SocketCommon_setreuseport (SocketBase_T base, Except_T exc_type);
extern void SocketCommon_settimeout (SocketBase_T base, int timeout_sec, Except_T exc_type);
extern void SocketCommon_setcloexec_with_error (SocketBase_T base, int enable, Except_T exc_type);
extern void SocketCommon_disable_sigpipe (int fd); /* Suppress SIGPIPE via SO_NOSIGPIPE (BSD/macOS) */

extern struct addrinfo *SocketCommon_copy_addrinfo (const struct addrinfo *src); /* Implementation of public deep copy function - see SocketCommon.h */

/* Internal helper functions shared between SocketCommon-resolve.c and SocketCommon-utils.c */
extern const char *socketcommon_get_safe_host (const char *host);
extern int socketcommon_validate_hostname_internal (const char *host, int use_exceptions, Except_T exception_type);
extern void socketcommon_convert_port_to_string (int port, char *port_str, size_t bufsize);

/* Forward declarations of module exceptions - avoids duplicating in each .c file */
extern const Except_T Socket_Failed;
extern const Except_T SocketDgram_Failed;
extern const Except_T SocketCommon_Failed;

/* Shared timeout sanitization function */
extern int socketcommon_sanitize_timeout (int timeout_ms);

#endif /* SOCKETCOMMON_PRIVATE_INCLUDED */
