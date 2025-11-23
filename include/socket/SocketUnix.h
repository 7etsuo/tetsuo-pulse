#ifndef SOCKETUNIX_INCLUDED
#define SOCKETUNIX_INCLUDED

#include "core/Except.h"
#include "socket/SocketCommon.h"  /* For SocketBase_T */

/**
 * SocketUnix - Unix Domain Socket Operations
 * Specialized module for AF_UNIX socket handling (streams and datagrams).
 * Supports regular and abstract namespace sockets.
 * Follows rules: unlink stale files before bind, validate paths, use arenas.
 * Public API: bind_unix, connect_unix on Socket_T / SocketDgram_T
 * Internal: Helpers for path validation, setup, stale unlink.
 */

typedef struct SocketUnix *SocketUnix_T;

extern const Except_T SocketUnix_Failed; /**< Unix socket operation failure */

/* Public functions - called from Socket.c / SocketDgram.c */
extern void SocketUnix_bind (SocketBase_T base, const char *path, Except_T exc_type); /* Unlink stale, bind */
extern void SocketUnix_connect (SocketBase_T base, const char *path, Except_T exc_type); /* Connect to path */

/* Public helpers */
extern int SocketUnix_validate_unix_path (const char *path, size_t path_len); /* Validate path length/security */

/* Private helpers - for internal use */
 /* Decl in private.h */

#endif /* SOCKETUNIX_INCLUDED */