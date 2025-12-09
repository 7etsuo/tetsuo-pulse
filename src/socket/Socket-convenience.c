/**
 * Socket-convenience.c - Convenience wrapper functions
 *
 * Part of the Socket Library
 *
 * Implements high-level convenience functions that combine multiple
 * socket operations into single calls for common use cases:
 *
 * - Socket_listen_tcp() - One-call TCP server setup
 * - Socket_connect_tcp() - One-call TCP client with timeout
 * - Socket_accept_timeout() - Accept with explicit timeout
 * - Socket_connect_nonblocking() - Non-blocking connect initiation
 * - Socket_listen_unix() - One-call Unix domain server setup
 * - Socket_connect_unix_timeout() - Unix domain connect with timeout
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketConvenience);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketConvenience, e)

/* ============================================================================
 * TCP Convenience Functions
 * ============================================================================
 */

/**
 * Socket_listen_tcp - Create a listening TCP server socket in one call
 * @host: Local address to bind (NULL or "" for INADDR_ANY)
 * @port: Local port to bind (1-65535)
 * @backlog: Maximum pending connections
 *
 * Returns: New listening socket ready for Socket_accept()
 * Raises: Socket_Failed on error
 * Thread-safe: Yes
 */
T
Socket_listen_tcp (const char *host, int port, int backlog)
{
  T server = NULL;

  assert (port > 0 && port <= SOCKET_MAX_PORT);
  assert (backlog > 0);

  TRY
  {
    /* Create IPv4 TCP socket (use AF_INET6 for dual-stack if needed) */
    server = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Enable address reuse for quick restart */
    Socket_setreuseaddr (server);

    /* Bind to address/port */
    Socket_bind (server, host, port);

    /* Start listening */
    Socket_listen (server, backlog);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    RERAISE;
  }
  END_TRY;

  return server;
}

/**
 * Socket_connect_tcp - Create a connected TCP client socket in one call
 * @host: Remote address (IP or hostname)
 * @port: Remote port (1-65535)
 * @timeout_ms: Connection timeout in milliseconds (0 = no timeout)
 *
 * Returns: New connected socket
 * Raises: Socket_Failed on error
 * Thread-safe: Yes
 */
T
Socket_connect_tcp (const char *host, int port, int timeout_ms)
{
  T client = NULL;

  assert (host != NULL);
  assert (port > 0 && port <= SOCKET_MAX_PORT);
  assert (timeout_ms >= 0);

  TRY
  {
    /* Create IPv4 TCP socket */
    client = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Set connect timeout if specified */
    if (timeout_ms > 0)
      {
        SocketTimeouts_T timeouts = { 0 };
        Socket_timeouts_get (client, &timeouts);
        timeouts.connect_timeout_ms = timeout_ms;
        Socket_timeouts_set (client, &timeouts);
      }

    /* Connect to remote host */
    Socket_connect (client, host, port);
  }
  EXCEPT (Socket_Failed)
  {
    if (client)
      Socket_free (&client);
    RERAISE;
  }
  END_TRY;

  return client;
}

/**
 * Socket_accept_timeout - Accept incoming connection with explicit timeout
 * @socket: Listening socket
 * @timeout_ms: Timeout in milliseconds (0 = immediate, -1 = block forever)
 *
 * Returns: New client socket, or NULL if timeout expired
 * Raises: Socket_Failed on accept error
 * Thread-safe: Yes
 */
T
Socket_accept_timeout (T socket, int timeout_ms)
{
  int fd;
  int original_flags;
  volatile int need_restore = 0;
  volatile T client = NULL;

  assert (socket);

  fd = Socket_fd (socket);

  /* Get current flags */
  original_flags = fcntl (fd, F_GETFL);
  if (original_flags < 0)
    {
      SOCKET_ERROR_FMT ("Failed to get socket flags");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Set non-blocking if needed for timeout handling */
  if ((original_flags & O_NONBLOCK) == 0)
    {
      if (fcntl (fd, F_SETFL, original_flags | O_NONBLOCK) < 0)
        {
          SOCKET_ERROR_FMT ("Failed to set non-blocking mode");
          RAISE_MODULE_ERROR (Socket_Failed);
        }
      need_restore = 1;
    }

  TRY
  {
    /* Wait for incoming connection with timeout */
    if (timeout_ms != 0)
      {
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int poll_result;

        while ((poll_result = poll (&pfd, 1, timeout_ms)) < 0 && errno == EINTR)
          ; /* Retry on EINTR */

        if (poll_result < 0)
          {
            SOCKET_ERROR_FMT ("poll() failed in accept_timeout");
            RAISE_MODULE_ERROR (Socket_Failed);
          }

        if (poll_result == 0)
          {
            /* Timeout - return NULL (not an error) */
            client = NULL;
          }
        else
          {
            /* Ready to accept */
            client = Socket_accept (socket);
          }
      }
    else
      {
        /* Immediate check (non-blocking) */
        client = Socket_accept (socket);
      }
  }
  FINALLY
  {
    /* Restore original blocking mode */
    if (need_restore)
      {
        if (fcntl (fd, F_SETFL, original_flags) < 0)
          {
            SocketLog_emitf (SOCKET_LOG_WARN, "SocketConvenience",
                             "Failed to restore blocking mode after "
                             "accept_timeout (fd=%d, errno=%d): %s",
                             fd, errno, Socket_safe_strerror (errno));
          }
      }
  }
  END_TRY;

  return client;
}

/**
 * Socket_connect_nonblocking - Initiate non-blocking connect (IP only)
 * @socket: Socket (will be set to non-blocking)
 * @ip_address: Remote IP address (no hostnames)
 * @port: Remote port (1-65535)
 *
 * Returns: 0 if connected immediately, 1 if in progress
 * Raises: Socket_Failed on invalid IP or immediate failure
 * Thread-safe: Yes
 */
int
Socket_connect_nonblocking (T socket, const char *ip_address, int port)
{
  struct sockaddr_storage addr;
  socklen_t addrlen = 0;
  int fd;
  int result;

  assert (socket);
  assert (ip_address != NULL);
  assert (port > 0 && port <= SOCKET_MAX_PORT);

  fd = Socket_fd (socket);

  /* Parse IP address - try IPv4 first, then IPv6 */
  memset (&addr, 0, sizeof (addr));

  /* Try IPv4 */
  struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
  if (inet_pton (AF_INET, ip_address, &addr4->sin_addr) == 1)
    {
      addr4->sin_family = AF_INET;
      addr4->sin_port = htons ((uint16_t)port);
      addrlen = sizeof (struct sockaddr_in);
    }
  else
    {
      /* Try IPv6 */
      struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
      if (inet_pton (AF_INET6, ip_address, &addr6->sin6_addr) == 1)
        {
          addr6->sin6_family = AF_INET6;
          addr6->sin6_port = htons ((uint16_t)port);
          addrlen = sizeof (struct sockaddr_in6);
        }
      else
        {
          SOCKET_ERROR_MSG ("Invalid IP address (not IPv4 or IPv6): %.*s",
                            SOCKET_ERROR_MAX_HOSTNAME, ip_address);
          RAISE_MODULE_ERROR (Socket_Failed);
        }
    }

  /* Set socket to non-blocking mode */
  Socket_setnonblocking (socket);

  /* Initiate connect */
  result = connect (fd, (struct sockaddr *)&addr, addrlen);

  if (result == 0)
    {
      /* Connected immediately (rare for TCP, common for Unix domain) */
      return 0;
    }

  if (errno == EINPROGRESS || errno == EINTR)
    {
      /* Connection in progress - caller should poll */
      return 1;
    }

  /* Immediate failure */
  SOCKET_ERROR_FMT ("Connect to %.*s:%d failed", SOCKET_ERROR_MAX_HOSTNAME,
                    ip_address, port);
  RAISE_MODULE_ERROR (Socket_Failed);

  return -1; /* Unreachable */
}

/* ============================================================================
 * Unix Domain Socket Convenience Functions
 * ============================================================================
 */

/**
 * Socket_listen_unix - Create a listening Unix domain socket in one call
 * @path: Socket file path (or '@' prefix for abstract)
 * @backlog: Maximum pending connections
 *
 * Returns: New listening Unix domain socket
 * Raises: SocketUnix_Failed on error
 * Thread-safe: Yes
 */
T
Socket_listen_unix (const char *path, int backlog)
{
  T server = NULL;

  assert (path != NULL);
  assert (backlog > 0);

  TRY
  {
    /* Create Unix domain stream socket */
    server = Socket_new (AF_UNIX, SOCK_STREAM, 0);

    /* Bind to path */
    Socket_bind_unix (server, path);

    /* Start listening */
    Socket_listen (server, backlog);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    RERAISE;
  }
  END_TRY;

  return server;
}

/**
 * Socket_connect_unix_timeout - Connect to Unix domain socket with timeout
 * @socket: Unix domain socket (AF_UNIX)
 * @path: Server socket path
 * @timeout_ms: Connection timeout in milliseconds (0 = no timeout)
 *
 * Raises: SocketUnix_Failed on error or timeout
 * Thread-safe: Yes
 */
void
Socket_connect_unix_timeout (T socket, const char *path, int timeout_ms)
{
  struct sockaddr_un addr;
  size_t path_len;
  int fd;
  volatile int original_flags = 0;
  volatile int need_restore = 0;
  int result;

  assert (socket);
  assert (path != NULL);
  assert (timeout_ms >= 0);

  fd = Socket_fd (socket);
  path_len = strlen (path);

  /* Validate path length */
  if (path_len == 0 || path_len >= sizeof (addr.sun_path))
    {
      SOCKET_ERROR_MSG ("Invalid Unix socket path length: %zu", path_len);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Build address */
  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;

  /* Handle abstract sockets (Linux: '@' prefix becomes '\0') */
  if (path[0] == '@')
    {
      addr.sun_path[0] = '\0';
      memcpy (addr.sun_path + 1, path + 1, path_len - 1);
    }
  else
    {
      memcpy (addr.sun_path, path, path_len);
    }

  /* If timeout specified, use non-blocking connect */
  if (timeout_ms > 0)
    {
      original_flags = fcntl (fd, F_GETFL);
      if (original_flags < 0)
        {
          SOCKET_ERROR_FMT ("Failed to get socket flags");
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      if ((original_flags & O_NONBLOCK) == 0)
        {
          if (fcntl (fd, F_SETFL, original_flags | O_NONBLOCK) < 0)
            {
              SOCKET_ERROR_FMT ("Failed to set non-blocking mode");
              RAISE_MODULE_ERROR (Socket_Failed);
            }
          need_restore = 1;
        }
    }

  TRY
  {
    result = connect (fd, (struct sockaddr *)&addr, sizeof (addr));

    if (result == 0 || errno == EISCONN)
      {
        /* Connected immediately */
      }
    else if (timeout_ms > 0
             && (errno == EINPROGRESS || errno == EINTR || errno == EAGAIN))
      {
        /* Wait for connection with timeout */
        struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
        int poll_result;

        while ((poll_result = poll (&pfd, 1, timeout_ms)) < 0 && errno == EINTR)
          ; /* Retry on EINTR */

        if (poll_result < 0)
          {
            SOCKET_ERROR_FMT ("poll() failed during Unix connect");
            RAISE_MODULE_ERROR (Socket_Failed);
          }

        if (poll_result == 0)
          {
            errno = ETIMEDOUT;
            SOCKET_ERROR_MSG (SOCKET_ETIMEDOUT ": Unix connect to %.*s",
                              SOCKET_ERROR_MAX_HOSTNAME, path);
            RAISE_MODULE_ERROR (Socket_Failed);
          }

        /* Check if connect succeeded */
        int error = 0;
        socklen_t error_len = sizeof (error);
        if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
          {
            SOCKET_ERROR_FMT ("getsockopt(SO_ERROR) failed");
            RAISE_MODULE_ERROR (Socket_Failed);
          }

        if (error != 0)
          {
            errno = error;
            SOCKET_ERROR_FMT ("Unix connect to %.*s failed",
                              SOCKET_ERROR_MAX_HOSTNAME, path);
            RAISE_MODULE_ERROR (Socket_Failed);
          }
      }
    else
      {
        /* Connect failed immediately */
        SOCKET_ERROR_FMT ("Unix connect to %.*s failed",
                          SOCKET_ERROR_MAX_HOSTNAME, path);
        RAISE_MODULE_ERROR (Socket_Failed);
      }
  }
  FINALLY
  {
    /* Restore original blocking mode */
    if (need_restore)
      {
        if (fcntl (fd, F_SETFL, original_flags) < 0)
          {
            SocketLog_emitf (SOCKET_LOG_WARN, "SocketConvenience",
                             "Failed to restore blocking mode after "
                             "Unix connect (fd=%d, errno=%d): %s",
                             fd, errno, Socket_safe_strerror (errno));
          }
      }
  }
  END_TRY;
}

