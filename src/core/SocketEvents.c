/**
 * SocketEvents.c - Event dispatching subsystem
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides event notification mechanism for socket library operations.
 * Applications can register callbacks to receive events like connection
 * accepted, connection established, DNS timeout, and poll wakeups.
 *
 * FEATURES:
 * - Multiple handler registration
 * - Event-specific data structures
 * - Thread-safe handler management
 * - Duplicate registration prevention
 *
 * THREAD SAFETY:
 * - Handler registration/unregistration is mutex protected
 * - Event dispatch copies handlers to avoid holding mutex during callbacks
 *
 * LIMITATIONS:
 * - Maximum SOCKET_EVENT_MAX_HANDLERS handlers
 */

#include <assert.h>
#include <pthread.h>
#include <string.h>

#include "core/SocketConfig.h"
#include "core/SocketEvents.h"
#include "core/SocketLog.h"

/**
 * SocketEventHandler - Internal handler registration structure
 */
typedef struct SocketEventHandler
{
  SocketEventCallback callback;
  void *userdata;
} SocketEventHandler;

/* Mutex protecting handler array */
static pthread_mutex_t socketevent_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Registered handlers */
static SocketEventHandler socketevent_handlers[SOCKET_EVENT_MAX_HANDLERS];
static size_t socketevent_handler_count = 0;

/**
 * socketevent_dispatch - Dispatch event to all registered handlers
 * @event: Event record to dispatch
 *
 * Thread-safe: Yes
 *
 * Copies handlers under mutex, then invokes each callback outside mutex
 * to prevent deadlocks. Callbacks must not block indefinitely.
 */
static void
socketevent_dispatch (const SocketEventRecord *event)
{
  SocketEventHandler local_handlers[SOCKET_EVENT_MAX_HANDLERS];
  size_t count;
  size_t i;

  assert (event);

  pthread_mutex_lock (&socketevent_mutex);
  count = socketevent_handler_count;
  memcpy (local_handlers, socketevent_handlers,
          sizeof (SocketEventHandler) * count);
  pthread_mutex_unlock (&socketevent_mutex);

  for (i = 0; i < count; i++)
    {
      if (local_handlers[i].callback)
        local_handlers[i].callback (local_handlers[i].userdata, event);
    }
}

/**
 * SocketEvent_register - Register an event handler
 * @callback: Callback function to register
 * @userdata: User data passed to callback
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Registers a callback to receive socket events. Duplicate registrations
 * (same callback and userdata) are silently ignored. If the handler limit
 * is reached, the registration is logged and ignored.
 */
void
SocketEvent_register (SocketEventCallback callback, void *userdata)
{
  size_t i;

  if (callback == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "NULL callback in register ignored");
      return;
    }

  pthread_mutex_lock (&socketevent_mutex);

  /* Check for duplicate */
  for (i = 0; i < socketevent_handler_count; i++)
    {
      if (socketevent_handlers[i].callback == callback
          && socketevent_handlers[i].userdata == userdata)
        {
          pthread_mutex_unlock (&socketevent_mutex);
          return;
        }
    }

  /* Check capacity */
  if (socketevent_handler_count >= SOCKET_EVENT_MAX_HANDLERS)
    {
      pthread_mutex_unlock (&socketevent_mutex);
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "Handler limit reached; ignoring registration");
      return;
    }

  /* Add handler */
  socketevent_handlers[socketevent_handler_count].callback = callback;
  socketevent_handlers[socketevent_handler_count].userdata = userdata;
  socketevent_handler_count++;

  pthread_mutex_unlock (&socketevent_mutex);
}

/**
 * SocketEvent_unregister - Unregister an event handler
 * @callback: Callback function to unregister
 * @userdata: User data that was passed to register
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Removes a previously registered handler. Both callback and userdata
 * must match. If not found, the call is silently ignored.
 */
void
SocketEvent_unregister (SocketEventCallback callback, void *userdata)
{
  size_t i;

  if (callback == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "NULL callback in unregister ignored");
      return;
    }

  pthread_mutex_lock (&socketevent_mutex);

  for (i = 0; i < socketevent_handler_count; i++)
    {
      if (socketevent_handlers[i].callback == callback
          && socketevent_handlers[i].userdata == userdata)
        {
          size_t remaining = socketevent_handler_count - i - 1;
          if (remaining > 0)
            {
              memmove (&socketevent_handlers[i], &socketevent_handlers[i + 1],
                       remaining * sizeof (SocketEventHandler));
            }
          socketevent_handler_count--;
          break;
        }
    }

  pthread_mutex_unlock (&socketevent_mutex);
}

/**
 * socketevent_init_connection - Initialize connection event record
 * @event: Event record to initialize
 * @type: Event type (ACCEPTED or CONNECTED)
 * @component: Component name
 * @fd: File descriptor
 * @peer_addr: Peer IP address string
 * @peer_port: Peer port number
 * @local_addr: Local IP address string
 * @local_port: Local port number
 *
 * Thread-safe: Yes
 *
 * Helper to eliminate duplication in emit_accept and emit_connect.
 */
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

/**
 * SocketEvent_emit_accept - Emit connection accepted event
 * @fd: File descriptor of accepted socket
 * @peer_addr: Peer IP address string
 * @peer_port: Peer port number
 * @local_addr: Local IP address string
 * @local_port: Local port number
 *
 * Thread-safe: Yes
 */
void
SocketEvent_emit_accept (int fd, const char *peer_addr, int peer_port,
                         const char *local_addr, int local_port)
{
  SocketEventRecord event;

  socketevent_init_connection (&event, SOCKET_EVENT_ACCEPTED, "Socket", fd,
                               peer_addr, peer_port, local_addr, local_port);
  socketevent_dispatch (&event);
}

/**
 * SocketEvent_emit_connect - Emit connection established event
 * @fd: File descriptor of connected socket
 * @peer_addr: Peer IP address string
 * @peer_port: Peer port number
 * @local_addr: Local IP address string
 * @local_port: Local port number
 *
 * Thread-safe: Yes
 */
void
SocketEvent_emit_connect (int fd, const char *peer_addr, int peer_port,
                          const char *local_addr, int local_port)
{
  SocketEventRecord event;

  socketevent_init_connection (&event, SOCKET_EVENT_CONNECTED, "Socket", fd,
                               peer_addr, peer_port, local_addr, local_port);
  socketevent_dispatch (&event);
}

/**
 * SocketEvent_emit_dns_timeout - Emit DNS resolution timeout event
 * @host: Hostname that timed out
 * @port: Port number being resolved
 *
 * Thread-safe: Yes
 */
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

/**
 * SocketEvent_emit_poll_wakeup - Emit poll wakeup event
 * @nfds: Number of file descriptors with events
 * @timeout_ms: Timeout that was used for poll
 *
 * Thread-safe: Yes
 */
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
