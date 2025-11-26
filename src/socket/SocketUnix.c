#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "core/Arena.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"
#include "socket/SocketUnix-private.h"
#include "socket/SocketUnix.h"

#ifdef SOCKET_HAS_TLS
#include <openssl/ssl.h>
#endif


#define T Socket_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketUnix"

const Except_T SocketUnix_Failed
    = { &SocketUnix_Failed, "Unix socket operation failed" };

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketUnix);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketUnix, e)

/**
 * SocketUnix_validate_unix_path - Validate Unix socket path length and
 * security
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

/* More functions to move: setup_abstract_unix_socket,
 * setup_regular_unix_socket, bind_unix, connect_unix etc. */

/* ==================== Unix Socket Setup ==================== */

/**
 * setup_unix_sockaddr - Initialize sockaddr_un from path
 * @addr: Output sockaddr_un structure
 * @path: Unix socket path (@ prefix for abstract)
 *
 * Returns: 0 on success
 * Thread-safe: Yes (stateless)
 */
static int
setup_unix_sockaddr (struct sockaddr_un *addr, const char *path)
{
  size_t path_len;

  assert (addr);
  assert (path);

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;
  path_len = strlen (path);

  if (path[0] == '@')
    setup_abstract_unix_socket (addr, path, path_len);
  else
    setup_regular_unix_socket (addr, path, path_len);

  return 0;
}

/* ==================== Bind Operation ==================== */

void
SocketUnix_bind (SocketBase_T base, const char *path, Except_T exc_type)
{
  struct sockaddr_un addr;
  size_t path_len = strlen (path);

  if (SocketUnix_validate_unix_path (path, path_len) < 0)
    RAISE_MODULE_ERROR (exc_type);

  /* Unlink stale socket file for regular (non-abstract) paths */
  if (!SocketUnix_is_abstract_path (path))
    SocketUnix_unlink_stale (path, exc_type);

  setup_unix_sockaddr (&addr, path);

  if (bind (SocketBase_fd (base), (struct sockaddr *)&addr, sizeof (addr)) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to bind Unix socket to %s", path);
      RAISE_MODULE_ERROR (exc_type);
    }

  SocketCommon_update_local_endpoint (base);
}

/* ==================== Unix Socket Operations ==================== */

void
SocketUnix_connect (SocketBase_T base, const char *path, Except_T exc_type)
{
  struct sockaddr_un addr;
  size_t path_len = strlen (path);

  /* Validate path before use (same as SocketUnix_bind) */
  if (SocketUnix_validate_unix_path (path, path_len) < 0)
    RAISE_MODULE_ERROR (exc_type);

  if (setup_unix_sockaddr (&addr, path) != 0)
    RAISE_MODULE_ERROR (exc_type);

  if (connect (SocketBase_fd (base), (struct sockaddr *)&addr, sizeof (addr))
      < 0)
    {
      if (errno == ENOENT)
        SOCKET_ERROR_FMT ("Unix socket does not exist: %s", path);
      else if (errno == ECONNREFUSED)
        SOCKET_ERROR_FMT (SOCKET_ECONNREFUSED ": %s", path);
      else
        SOCKET_ERROR_FMT ("Failed to connect to Unix socket %s", path);
      RAISE_MODULE_ERROR (exc_type);
    }

  /* Update remote endpoint */
  memcpy (&base->remote_addr, &addr, sizeof (addr));
  base->remote_addrlen = sizeof (addr);
  SocketCommon_update_local_endpoint (base);
}

/* ==================== Socket Pair Operations ==================== */

