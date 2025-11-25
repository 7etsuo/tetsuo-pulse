#ifndef SOCKETUNIX_PRIVATE_INCLUDED
#define SOCKETUNIX_PRIVATE_INCLUDED

#include "core/Arena.h"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"  /* For SocketBase_T */
#include "socket/SocketUnix.h"

/* Private struct if needed, or use base directly */
 /* For now, no additional struct, use base */

static inline bool
SocketUnix_is_abstract_path (const char *path)
{
  return path && path[0] == '@';
}

static void
SocketUnix_unlink_stale (const char *path, Except_T exc_type)
{
  struct stat st;
  if (stat (path, &st) == 0)
    {
      if (S_ISSOCK (st.st_mode))
        {
          if (unlink (path) < 0)
            {
              SOCKET_ERROR_MSG ("Failed to unlink stale socket %s", path);
              RAISE (exc_type);
            }
        }
    }
}

static inline void
setup_abstract_unix_socket (struct sockaddr_un *addr, const char *path, size_t path_len)
{
  /* Calculate the actual name length (excluding the '@' prefix) */
  size_t name_len = path_len > 0 ? path_len - 1 : 0;
  /* Ensure name fits in sun_path after the leading null byte */
  size_t max_name_len = sizeof (addr->sun_path) - 1;
  if (name_len > max_name_len)
    name_len = max_name_len;

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;
  addr->sun_path[0] = '\0'; /* Abstract namespace marker */
  /* Skip the '@' prefix when copying to sun_path */
  if (name_len > 0)
    memcpy (addr->sun_path + 1, path + 1, name_len);
}

static inline void
setup_regular_unix_socket (struct sockaddr_un *addr, const char *path, size_t path_len)
{
  /* Ensure path fits in sun_path with null terminator */
  size_t max_path_len = sizeof (addr->sun_path) - 1;
  if (path_len > max_path_len)
    path_len = max_path_len;

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;
  memcpy (addr->sun_path, path, path_len);
  addr->sun_path[path_len] = '\0';
}

/* Other private helpers */

#endif /* SOCKETUNIX_PRIVATE_INCLUDED */