/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-poll.c
 * @brief Simple event-driven I/O multiplexing implementation.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-poll.h"

#include "poll/SocketPoll.h"

/* ============================================================================
 * Internal Structure
 * ============================================================================
 */

struct SocketSimple_Poll
{
  SocketPoll_T poll;
  int max_events;
  int default_timeout_ms;
};

/* ============================================================================
 * Helper: Validate poll and socket arguments
 * ============================================================================
 */

static int
validate_poll_and_socket (SocketSimple_Poll_T poll,
                           SocketSimple_Socket_T sock)
{
  if (!poll || !sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid poll or socket");
      return -1;
    }
  return 0;
}

/* ============================================================================
 * Helper: Extract and validate core socket handle
 * ============================================================================
 */

static Socket_T
get_core_socket (SocketSimple_Socket_T sock)
{
  if (sock->socket)
    return sock->socket;

  if (sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                        "UDP sockets not supported in poll");
      return NULL;
    }

  simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket handle");
  return NULL;
}

/* ============================================================================
 * Helper: Map Simple events to core events
 * ============================================================================
 */

static unsigned
simple_to_core_events (int events)
{
  unsigned core = 0;
  if (events & SOCKET_SIMPLE_POLL_READ)
    core |= POLL_READ;
  if (events & SOCKET_SIMPLE_POLL_WRITE)
    core |= POLL_WRITE;
  if (events & SOCKET_SIMPLE_POLL_ERROR)
    core |= POLL_ERROR;
  if (events & SOCKET_SIMPLE_POLL_HANGUP)
    core |= POLL_HANGUP;
  return core;
}

static int
core_to_simple_events (unsigned events)
{
  int simple = 0;
  if (events & POLL_READ)
    simple |= SOCKET_SIMPLE_POLL_READ;
  if (events & POLL_WRITE)
    simple |= SOCKET_SIMPLE_POLL_WRITE;
  if (events & POLL_ERROR)
    simple |= SOCKET_SIMPLE_POLL_ERROR;
  if (events & POLL_HANGUP)
    simple |= SOCKET_SIMPLE_POLL_HANGUP;
  return simple;
}

/* ============================================================================
 * Poll Lifecycle
 * ============================================================================
 */

SocketSimple_Poll_T
Socket_simple_poll_new (int max_events_arg)
{
  volatile SocketPoll_T poll = NULL;
  volatile int max_events = max_events_arg;
  struct SocketSimple_Poll *volatile handle = NULL;

  Socket_simple_clear_error ();

  if (max_events <= 0)
    {
      max_events = SOCKET_SIMPLE_POLL_DEFAULT_MAX_EVENTS;
    }

  TRY
  {
    poll = SocketPoll_new (max_events);

    handle = calloc (1, sizeof (*handle));
    if (!handle)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                          "Memory allocation failed");
        RAISE (SocketPoll_Failed);
      }

    handle->poll = poll;
    handle->max_events = max_events;
    handle->default_timeout_ms = -1; /* Infinite by default */
  }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL,
                      "Failed to create poll instance");
  }
  FINALLY
  {
    /* Clean up poll object if allocation succeeded but handle didn't */
    if (poll && !handle)
      {
        SocketPoll_free ((SocketPoll_T *)&poll);
      }
  }
  END_TRY;

  return (struct SocketSimple_Poll *)handle;
}

void
Socket_simple_poll_free (SocketSimple_Poll_T *poll)
{
  if (!poll || !*poll)
    return;

  struct SocketSimple_Poll *p = *poll;

  if (p->poll)
    {
      SocketPoll_free (&p->poll);
    }

  free (p);
  *poll = NULL;
}

/* ============================================================================
 * Socket Registration
 * ============================================================================
 */

int
Socket_simple_poll_add (SocketSimple_Poll_T poll, SocketSimple_Socket_T sock,
                        int events, void *data)
{
  Socket_simple_clear_error ();

  if (validate_poll_and_socket (poll, sock) != 0)
    return -1;

  /* Get underlying Socket_T with validation */
  Socket_T core_sock = get_core_socket (sock);
  if (!core_sock)
    return -1;

  unsigned core_events = simple_to_core_events (events);

  TRY { SocketPoll_add (poll->poll, core_sock, core_events, data); }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to add socket to poll");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_poll_mod (SocketSimple_Poll_T poll, SocketSimple_Socket_T sock,
                        int events, void *data)
{
  Socket_simple_clear_error ();

  if (validate_poll_and_socket (poll, sock) != 0)
    return -1;

  /* Get underlying Socket_T with validation */
  Socket_T core_sock = get_core_socket (sock);
  if (!core_sock)
    return -1;

  unsigned core_events = simple_to_core_events (events);

  TRY { SocketPoll_mod (poll->poll, core_sock, core_events, data); }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL,
                      "Failed to modify socket in poll");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_poll_del (SocketSimple_Poll_T poll, SocketSimple_Socket_T sock)
{
  Socket_simple_clear_error ();

  if (validate_poll_and_socket (poll, sock) != 0)
    return -1;

  /* Get underlying Socket_T with validation */
  Socket_T core_sock = get_core_socket (sock);
  if (!core_sock)
    return -1;

  TRY { SocketPoll_del (poll->poll, core_sock); }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL,
                      "Failed to remove socket from poll");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_poll_modify_events (SocketSimple_Poll_T poll,
                                  SocketSimple_Socket_T sock, int add_events,
                                  int remove_events)
{
  Socket_simple_clear_error ();

  if (validate_poll_and_socket (poll, sock) != 0)
    return -1;

  /* Get underlying Socket_T with validation */
  Socket_T core_sock = get_core_socket (sock);
  if (!core_sock)
    return -1;

  unsigned add = simple_to_core_events (add_events);
  unsigned remove = simple_to_core_events (remove_events);

  TRY { SocketPoll_modify_events (poll->poll, core_sock, add, remove); }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to modify poll events");
    return -1;
  }
  END_TRY;

  return 0;
}

/* ============================================================================
 * Event Waiting
 * ============================================================================
 */

int
Socket_simple_poll_wait (SocketSimple_Poll_T poll,
                         SocketSimple_PollEvent *events, int max_events_arg,
                         int timeout_ms_arg)
{
  volatile int timeout_ms = timeout_ms_arg;
  volatile int max_events = max_events_arg;

  Socket_simple_clear_error ();

  if (!poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return -1;
    }

  if (!events || max_events <= 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid events array or max_events");
      return -1;
    }

  /* Use default timeout if not specified */
  volatile int actual_timeout = timeout_ms;
  if (timeout_ms == SOCKET_POLL_TIMEOUT_USE_DEFAULT)
    {
      actual_timeout = poll->default_timeout_ms;
    }

  volatile int nev = 0;
  SocketEvent_T *core_events = NULL;

  TRY { nev = SocketPoll_wait (poll->poll, &core_events, actual_timeout); }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Poll wait failed");
    return -1;
  }
  END_TRY;

  /* Convert core events to simple events */
  int count = (nev < max_events) ? nev : max_events;
  for (int i = 0; i < count; i++)
    {
      /* Note: We store the Socket_T in the sock field, but the Simple API
       * expects SocketSimple_Socket_T. This is a limitation - the caller
       * needs to track the mapping themselves via the data pointer.
       * We set sock to NULL and rely on data for context. */
      events[i].sock
          = NULL; /* Caller must use data for socket identification */
      events[i].events = core_to_simple_events (core_events[i].events);
      events[i].data = core_events[i].data;
    }

  return count;
}

/* ============================================================================
 * Poll Information
 * ============================================================================
 */

const char *
Socket_simple_poll_backend (SocketSimple_Poll_T poll)
{
  if (!poll)
    return "unknown";

  return SocketPoll_get_backend_name (poll->poll);
}

int
Socket_simple_poll_count (SocketSimple_Poll_T poll)
{
  if (!poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return -1;
    }

  return SocketPoll_getregisteredcount (poll->poll);
}

int
Socket_simple_poll_max (SocketSimple_Poll_T poll)
{
  if (!poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return -1;
    }

  return SocketPoll_getmaxregistered (poll->poll);
}

int
Socket_simple_poll_set_timeout (SocketSimple_Poll_T poll, int timeout_ms)
{
  if (!poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return -1;
    }

  poll->default_timeout_ms = timeout_ms;
  SocketPoll_setdefaulttimeout (poll->poll, timeout_ms);

  return 0;
}

/* ============================================================================
 * Internal Helper: Access core poll handle (used by timer module)
 * ============================================================================
 */

SocketPoll_T
simple_poll_get_core (SocketSimple_Poll_T poll)
{
  if (!poll)
    return NULL;
  return poll->poll;
}
