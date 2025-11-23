#include <sys/stat.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>

#include "core/Arena.h"
#include "core/SocketError.h"
#include "socket/SocketCommon.h"
#include "socket/SocketUnix.h"
#include "socket/SocketUnix-private.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketUnix"

const Except_T SocketUnix_Failed = { &SocketUnix_Failed, "Unix socket operation failed" };

/* Thread-local exception */
#ifdef _WIN32
static __declspec (thread) Except_T SocketUnix_DetailedException;
#else
static __thread Except_T SocketUnix_DetailedException;
#endif

#define RAISE_MODULE_ERROR(e) do { \
  SocketUnix_DetailedException = (e); \
  SocketUnix_DetailedException.reason = socket_error_buf; \
  RAISE(SocketUnix_DetailedException); \
} while(0)

/**
 * SocketUnix_validate_unix_path - Validate Unix socket path length and security
 * @path: Path string
 * @path_len: Length
 * Returns: 0 on valid, -1 on invalid
 * Moved from Socket.c
 */
int
SocketUnix_validate_unix_path (const char *path, size_t path_len)
{
  if (path_len > sizeof (struct sockaddr_un)
                     - offsetof (struct sockaddr_un, sun_path) - 1)
    {
      SOCKET_ERROR_MSG ("Unix socket path too long (max %zu characters)",
                        sizeof (struct sockaddr_un)
                            - offsetof (struct sockaddr_un, sun_path) - 1);
      return -1;
    }

  /* Check for directory traversal */
  if (strstr (path, "/../") || strcmp (path, "..") == 0
      || strncmp (path, "../", 3) == 0
      || (path_len >= 3 && strcmp (path + path_len - 3, "/..") == 0))
    {
      SOCKET_ERROR_MSG (
          "Invalid Unix socket path: directory traversal detected");
      return -1;
    }

  return 0;
}

/* More functions to move: setup_abstract_unix_socket, setup_regular_unix_socket, bind_unix, connect_unix etc. */

/* Example public impl */
void
SocketUnix_bind (SocketBase_T base, const char *path, Except_T exc_type)
{
  struct sockaddr_un addr;
  size_t path_len = strlen (path);

  if (SocketUnix_validate_unix_path (path, path_len) < 0)
    RAISE_MODULE_ERROR (exc_type);

  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;

  if (SocketUnix_is_abstract_path (path))
    {
      setup_abstract_unix_socket (&addr, path, path_len);
    }
  else
    {
      SocketUnix_unlink_stale (path, exc_type); /* Per rules */
      setup_regular_unix_socket (&addr, path, path_len);
    }

  if (bind (SocketBase_fd (base), (struct sockaddr *)&addr, sizeof (addr)) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to bind Unix socket to %s", path);
      RAISE_MODULE_ERROR (exc_type);
    }

  /* Update local endpoint */
  SocketCommon_update_local_endpoint (base);
}

/* Similar for SocketUnix_connect */

 /* TODO: Move remaining Unix ops from Socket.c to here, update calls in Socket.c / Dgram.c to SocketUnix_* (base, ...) */