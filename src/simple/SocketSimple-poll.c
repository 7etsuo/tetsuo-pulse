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

/**
 * @brief Socket mapping entry for tracking Socket_T -> SocketSimple_Socket_T.
 */
typedef struct SocketMapEntry
{
  Socket_T core_sock;
  SocketSimple_Socket_T simple_sock;
  struct SocketMapEntry *next;
} SocketMapEntry;

struct SocketSimple_Poll
{
  SocketPoll_T poll;
  int max_events;
  int default_timeout_ms;
  SocketMapEntry *socket_map; /**< Linked list mapping core to simple sockets */
};

static int
validate_poll_and_socket (SocketSimple_Poll_T poll, SocketSimple_Socket_T sock)
{
  if (!poll || !sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid poll or socket");
      return -1;
    }
  return 0;
}

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

/**
 * @brief Add or update a socket mapping.
 */
static int
socket_map_put (SocketSimple_Poll_T poll,
                Socket_T core_sock,
                SocketSimple_Socket_T simple_sock)
{
  /* Check if mapping already exists */
  for (SocketMapEntry *entry = poll->socket_map; entry; entry = entry->next)
    {
      if (entry->core_sock == core_sock)
        {
          entry->simple_sock = simple_sock;
          return 0;
        }
    }

  /* Create new entry */
  SocketMapEntry *new_entry = calloc (1, sizeof (*new_entry));
  if (!new_entry)
    return -1;

  new_entry->core_sock = core_sock;
  new_entry->simple_sock = simple_sock;
  new_entry->next = poll->socket_map;
  poll->socket_map = new_entry;
  return 0;
}

/**
 * @brief Lookup simple socket from core socket.
 */
static SocketSimple_Socket_T
socket_map_get (SocketSimple_Poll_T poll, Socket_T core_sock)
{
  for (SocketMapEntry *entry = poll->socket_map; entry; entry = entry->next)
    {
      if (entry->core_sock == core_sock)
        return entry->simple_sock;
    }
  return NULL;
}

/**
 * @brief Remove a socket mapping.
 */
static void
socket_map_remove (SocketSimple_Poll_T poll, Socket_T core_sock)
{
  SocketMapEntry **pp = &poll->socket_map;
  while (*pp)
    {
      if ((*pp)->core_sock == core_sock)
        {
          SocketMapEntry *to_free = *pp;
          *pp = to_free->next;
          free (to_free);
          return;
        }
      pp = &(*pp)->next;
    }
}

/**
 * @brief Free all socket map entries.
 */
static void
socket_map_free_all (SocketSimple_Poll_T poll)
{
  SocketMapEntry *entry = poll->socket_map;
  while (entry)
    {
      SocketMapEntry *next = entry->next;
      free (entry);
      entry = next;
    }
  poll->socket_map = NULL;
}

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
        simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
        RAISE (SocketPoll_Failed);
      }

    handle->poll = poll;
    handle->max_events = max_events;
    handle->default_timeout_ms = -1; /* Infinite by default */
  }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to create poll instance");
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

  /* Free socket map entries */
  socket_map_free_all (p);

  if (p->poll)
    {
      SocketPoll_free (&p->poll);
    }

  free (p);
  *poll = NULL;
}

int
Socket_simple_poll_add (SocketSimple_Poll_T poll,
                        SocketSimple_Socket_T sock,
                        int events,
                        void *data)
{
  Socket_simple_clear_error ();

  if (validate_poll_and_socket (poll, sock) != 0)
    return -1;

  /* Get underlying Socket_T with validation */
  Socket_T core_sock = get_core_socket (sock);
  if (!core_sock)
    return -1;

  unsigned core_events = simple_to_core_events (events);

  TRY
  {
    SocketPoll_add (poll->poll, core_sock, core_events, data);
  }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to add socket to poll");
    return -1;
  }
  END_TRY;

  /* Store socket mapping for event retrieval */
  if (socket_map_put (poll, core_sock, sock) != 0)
    {
      /* Rollback: remove from poll on mapping failure */
      TRY
      {
        SocketPoll_del (poll->poll, core_sock);
      }
      EXCEPT (SocketPoll_Failed)
      { /* Ignore cleanup failure */
      }
      END_TRY;
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                        "Failed to store socket mapping");
      return -1;
    }

  return 0;
}

int
Socket_simple_poll_mod (SocketSimple_Poll_T poll,
                        SocketSimple_Socket_T sock,
                        int events,
                        void *data)
{
  Socket_simple_clear_error ();

  if (validate_poll_and_socket (poll, sock) != 0)
    return -1;

  /* Get underlying Socket_T with validation */
  Socket_T core_sock = get_core_socket (sock);
  if (!core_sock)
    return -1;

  unsigned core_events = simple_to_core_events (events);

  TRY
  {
    SocketPoll_mod (poll->poll, core_sock, core_events, data);
  }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL,
                      "Failed to modify socket in poll");
    return -1;
  }
  END_TRY;

  /* Update socket mapping (in case socket handle changed) */
  if (socket_map_put (poll, core_sock, sock) != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                        "Failed to update socket mapping");
      return -1;
    }

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

  TRY
  {
    SocketPoll_del (poll->poll, core_sock);
  }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL,
                      "Failed to remove socket from poll");
    return -1;
  }
  END_TRY;

  /* Remove socket mapping */
  socket_map_remove (poll, core_sock);

  return 0;
}

int
Socket_simple_poll_modify_events (SocketSimple_Poll_T poll,
                                  SocketSimple_Socket_T sock,
                                  int add_events,
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

  TRY
  {
    SocketPoll_modify_events (poll->poll, core_sock, add, remove);
  }
  EXCEPT (SocketPoll_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to modify poll events");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_poll_wait (SocketSimple_Poll_T poll,
                         SocketSimple_PollEvent *events,
                         int max_events_arg,
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

  TRY
  {
    nev = SocketPoll_wait (poll->poll, &core_events, actual_timeout);
  }
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
      /* Look up the SocketSimple_Socket_T from our internal mapping */
      events[i].sock = socket_map_get (poll, core_events[i].socket);
      events[i].events = core_to_simple_events (core_events[i].events);
      events[i].data = core_events[i].data;
    }

  return count;
}

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

SocketPoll_T
simple_poll_get_core (SocketSimple_Poll_T poll)
{
  if (!poll)
    return NULL;
  return poll->poll;
}
