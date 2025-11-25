/**
 * SocketDNS-sync.c - Synchronization primitives for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains mutex, condition variable, and pipe initialization functions.
 */

/* All includes before T macro definition to avoid redefinition warnings */
#include <errno.h>
#include <fcntl.h>

#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"

/* Redefine T after all includes (Arena.h and SocketDNS.h both undef T at end) */
#undef T
#define T SocketDNS_T
#undef Request_T
#define Request_T SocketDNS_Request_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-sync"

/**
 * initialize_mutex - Initialize mutex for DNS resolver
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_mutex (struct SocketDNS_T *dns)
{
  if (pthread_mutex_init (&dns->mutex, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_NONE);
      SOCKET_ERROR_MSG ("Failed to initialize DNS resolver mutex");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * initialize_queue_condition - Initialize queue condition variable
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_queue_condition (struct SocketDNS_T *dns)
{
  if (pthread_cond_init (&dns->queue_cond, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_MUTEX);
      SOCKET_ERROR_MSG (
          "Failed to initialize DNS resolver condition variable");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * initialize_result_condition - Initialize result condition variable
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_result_condition (struct SocketDNS_T *dns)
{
  if (pthread_cond_init (&dns->result_cond, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_ERROR_MSG (
          "Failed to initialize DNS resolver result condition variable");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * initialize_synchronization - Initialize mutex and condition variables
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_synchronization (struct SocketDNS_T *dns)
{
  initialize_mutex (dns);
  initialize_queue_condition (dns);
  initialize_result_condition (dns);
}

/**
 * create_completion_pipe - Create pipe for completion signaling
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on pipe creation failure
 * Note: Both pipe ends are created with close-on-exec flag set.
 */
void
create_completion_pipe (struct SocketDNS_T *dns)
{
  if (pipe (dns->pipefd) < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_ERROR_FMT ("Failed to create completion pipe");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  /* Set CLOEXEC on both pipe ends */
  if (SocketCommon_setcloexec (dns->pipefd[0], 1) < 0
      || SocketCommon_setcloexec (dns->pipefd[1], 1) < 0)
    {
      int saved_errno = errno;
      SAFE_CLOSE (dns->pipefd[0]);
      SAFE_CLOSE (dns->pipefd[1]);
      dns->pipefd[0] = -1;
      dns->pipefd[1] = -1;
      cleanup_on_init_failure (dns, DNS_CLEAN_PIPE);
      errno = saved_errno;
      SOCKET_ERROR_FMT ("Failed to set close-on-exec flag on pipe");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * set_pipe_nonblocking - Set pipe read end to non-blocking mode
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on fcntl failure
 */
void
set_pipe_nonblocking (struct SocketDNS_T *dns)
{
  int flags = fcntl (dns->pipefd[0], F_GETFL);
  if (flags < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_ERROR_FMT ("Failed to get pipe flags");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  if (fcntl (dns->pipefd[0], F_SETFL, flags | O_NONBLOCK) < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_ERROR_FMT ("Failed to set pipe to non-blocking");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * initialize_pipe - Create pipe for completion signaling
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on pipe creation failure
 */
void
initialize_pipe (struct SocketDNS_T *dns)
{
  create_completion_pipe (dns);
  set_pipe_nonblocking (dns);
}

#undef T
#undef Request_T

