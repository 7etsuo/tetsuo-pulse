/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Event system: handler registration, connection/DNS/poll events */

#include <assert.h>
#include <pthread.h>
#include <string.h>

#include "core/SocketConfig.h"
#include "core/SocketEvent.h"
#include "core/SocketLog.h"
#include "core/SocketUtil.h"

typedef struct SocketEventHandler
{
  SocketEventCallback callback;
  void *userdata;
} SocketEventHandler;

static const Except_T SocketEvent_Failed
    = { &SocketEvent_Failed, "SocketEvent operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketEvent);

static pthread_mutex_t socketevent_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketEventHandler socketevent_handlers[SOCKET_EVENT_MAX_HANDLERS];
static size_t socketevent_handler_count = 0;

/* Caller must hold socketevent_mutex */
static size_t
socketevent_copy_handlers_unlocked (SocketEventHandler *local_handlers)
{
  memcpy (local_handlers, socketevent_handlers,
          sizeof (SocketEventHandler) * socketevent_handler_count);
  return socketevent_handler_count;
}

static void
socketevent_invoke_handlers (const SocketEventHandler *handlers, size_t count,
                             const SocketEventRecord *event)
{
  size_t i;

  for (i = 0; i < count; i++)
    {
      if (handlers[i].callback != NULL)
        handlers[i].callback (handlers[i].userdata, event);
    }
}

/* Copies handlers under mutex, then invokes callbacks outside mutex */
static void
socketevent_dispatch (const SocketEventRecord *event)
{
  SocketEventHandler local_handlers[SOCKET_EVENT_MAX_HANDLERS];
  size_t count;

  assert (event);

  SOCKET_MUTEX_LOCK_OR_RAISE (&socketevent_mutex, SocketEvent,
                              SocketEvent_Failed);
  count = socketevent_copy_handlers_unlocked (local_handlers);
  SOCKET_MUTEX_UNLOCK (&socketevent_mutex);

  socketevent_invoke_handlers (local_handlers, count, event);
}

/* Caller must hold socketevent_mutex */
static ssize_t
socketevent_find_handler_unlocked (const SocketEventCallback callback,
                                   const void *userdata)
{
  size_t i;

  for (i = 0; i < socketevent_handler_count; i++)
    {
      if (socketevent_handlers[i].callback == callback
          && socketevent_handlers[i].userdata == userdata)
        return (ssize_t)i;
    }
  return -1;
}

/* Caller must hold socketevent_mutex */
static void
socketevent_add_handler_unlocked (SocketEventCallback callback, void *userdata)
{
  socketevent_handlers[socketevent_handler_count].callback = callback;
  socketevent_handlers[socketevent_handler_count].userdata = userdata;
  socketevent_handler_count++;
}

/* Caller must hold socketevent_mutex */
static int
socketevent_can_register_unlocked (SocketEventCallback callback,
                                   const void *userdata)
{
  if (socketevent_find_handler_unlocked (callback, userdata) >= 0)
    return 0;

  if (socketevent_handler_count >= SOCKET_EVENT_MAX_HANDLERS)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "Handler limit reached; ignoring registration");
      return 0;
    }

  return 1;
}

void
SocketEvent_register (SocketEventCallback callback, void *userdata)
{
  if (callback == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "NULL callback in register ignored");
      return;
    }

  SOCKET_MUTEX_LOCK_OR_RAISE (&socketevent_mutex, SocketEvent,
                              SocketEvent_Failed);

  if (socketevent_can_register_unlocked (callback, userdata))
    socketevent_add_handler_unlocked (callback, userdata);

  SOCKET_MUTEX_UNLOCK (&socketevent_mutex);
}

/* Caller must hold socketevent_mutex */
static void
socketevent_remove_at_index_unlocked (size_t index)
{
  size_t remaining = socketevent_handler_count - index - 1;

  if (remaining > 0)
    {
      memmove (&socketevent_handlers[index], &socketevent_handlers[index + 1],
               remaining * sizeof (SocketEventHandler));
    }
  socketevent_handler_count--;
}

void
SocketEvent_unregister (SocketEventCallback callback, const void *userdata)
{
  ssize_t idx;

  if (callback == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "NULL callback in unregister ignored");
      return;
    }

  SOCKET_MUTEX_LOCK_OR_RAISE (&socketevent_mutex, SocketEvent,
                              SocketEvent_Failed);

  idx = socketevent_find_handler_unlocked (callback, userdata);
  if (idx >= 0)
    socketevent_remove_at_index_unlocked ((size_t)idx);

  SOCKET_MUTEX_UNLOCK (&socketevent_mutex);
}

static void
socketevent_init_connection (SocketEventRecord *event, SocketEventType type,
                             const char *component, int fd,
                             const char *peer_addr, int peer_port,
                             const char *local_addr, int local_port)
{
  event->type = type;
  event->component = component;
  event->data.connection.fd = fd;
  event->data.connection.peer_addr = peer_addr;
  event->data.connection.peer_port = peer_port;
  event->data.connection.local_addr = local_addr;
  event->data.connection.local_port = local_port;
}

void
SocketEvent_emit_accept (int fd, const char *peer_addr, int peer_port,
                         const char *local_addr, int local_port)
{
  SocketEventRecord event;

  socketevent_init_connection (&event, SOCKET_EVENT_ACCEPTED, "Socket", fd,
                               peer_addr, peer_port, local_addr, local_port);
  socketevent_dispatch (&event);
}

void
SocketEvent_emit_connect (int fd, const char *peer_addr, int peer_port,
                          const char *local_addr, int local_port)
{
  SocketEventRecord event;

  socketevent_init_connection (&event, SOCKET_EVENT_CONNECTED, "Socket", fd,
                               peer_addr, peer_port, local_addr, local_port);
  socketevent_dispatch (&event);
}

void
SocketEvent_emit_dns_timeout (const char *host, int port)
{
  SocketEventRecord event;

  event.type = SOCKET_EVENT_DNS_TIMEOUT;
  event.component = "SocketDNS";
  event.data.dns.host = host;
  event.data.dns.port = port;

  socketevent_dispatch (&event);
}

void
SocketEvent_emit_poll_wakeup (int nfds, int timeout_ms)
{
  SocketEventRecord event;

  event.type = SOCKET_EVENT_POLL_WAKEUP;
  event.component = "SocketPoll";
  event.data.poll.nfds = nfds;
  event.data.poll.timeout_ms = timeout_ms;

  socketevent_dispatch (&event);
}
