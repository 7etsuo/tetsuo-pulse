/**
 * SocketPoll-tls.c - TLS event handling for SocketPoll
 *
 * This file contains TLS-specific event handling for updating poll events
 * based on TLS handshake state. Only compiled when SOCKET_HAS_TLS is defined.
 *
 * Thread-safe: Uses poll mutex for data lookups.
 */

#include <assert.h>
#include <pthread.h>

#include "core/SocketConfig.h"
#include "poll/SocketPoll-private.h"

#ifdef SOCKET_HAS_TLS

#include "socket/Socket-private.h"
#include "socket/SocketIO.h"
#include "tls/SocketTLS.h"

#define T SocketPoll_T

/**
 * socketpoll_update_tls_events - Update poll events based on TLS state
 * @poll: Poll instance
 * @socket: Socket with TLS enabled
 *
 * Updates the poll event mask for a TLS-enabled socket based on its
 * current handshake state. Called during event processing to ensure
 * the socket is monitored for the correct I/O direction.
 *
 * Thread-safe: Yes - uses poll mutex for data lookup.
 */
void
socketpoll_update_tls_events (T poll, Socket_T socket)
{
  unsigned events = 0;
  void *user_data;

  assert (poll);
  assert (socket);

  /* Only process TLS-enabled sockets */
  if (!socket_is_tls_enabled (socket))
    return;

  /* Only update if handshake is in progress */
  if (!socket->tls_handshake_done)
    {
      if (socket_tls_want_read (socket))
        events |= POLL_READ;
      if (socket_tls_want_write (socket))
        events |= POLL_WRITE;

      if (events != 0)
        {
          pthread_mutex_lock (&poll->mutex);
          user_data = socket_data_lookup_unlocked (poll, socket);
          pthread_mutex_unlock (&poll->mutex);

          SocketPoll_mod (poll, socket, events, user_data);
        }
    }
}

/**
 * socketpoll_process_tls_handshakes - Process TLS handshakes for ready events
 * @poll: Poll instance
 * @nfds: Number of events to process
 *
 * Iterates through ready events and updates poll registration for any
 * TLS sockets that are still completing their handshake.
 *
 * Thread-safe: Yes - internal locking handled by socketpoll_update_tls_events.
 */
void
socketpoll_process_tls_handshakes (T poll, int nfds)
{
  int i;
  Socket_T socket;

  assert (poll);

  if (!poll->socketevents || nfds <= 0)
    return;

  for (i = 0; i < nfds; i++)
    {
      socket = poll->socketevents[i].socket;
      if (socket && socket_is_tls_enabled (socket))
        {
          if (!socket->tls_handshake_done)
            socketpoll_update_tls_events (poll, socket);
        }
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */

