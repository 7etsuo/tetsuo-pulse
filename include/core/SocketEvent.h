/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETEVENT_INCLUDED
#define SOCKETEVENT_INCLUDED

/**
 * @file SocketEvent.h
 * @ingroup foundation
 * @brief Event dispatching subsystem for connection and DNS events.
 *
 * Provides:
 * - Event handler registration/unregistration
 * - Connection events (accept, connect)
 * - DNS timeout events
 * - Poll wakeup events
 *
 * @see SocketEventType for event types
 * @see SocketEventCallback for event handlers
 * @see @ref foundation for other core utilities
 */

#include "core/SocketConfig.h"

/**
 * @brief SocketEventType - Event type enumeration
 *
 */
typedef enum SocketEventType
{
  SOCKET_EVENT_ACCEPTED = 0,
  SOCKET_EVENT_CONNECTED,
  SOCKET_EVENT_DNS_TIMEOUT,
  SOCKET_EVENT_POLL_WAKEUP
} SocketEventType;

/**
 * @brief SocketEventRecord - Event data structure
 *
 */
typedef struct SocketEventRecord
{
  SocketEventType type;
  const char *component;
  union
  {
    struct
    {
      int fd;
      const char *peer_addr;
      int peer_port;
      const char *local_addr;
      int local_port;
    } connection;
    struct
    {
      const char *host;
      int port;
    } dns;
    struct
    {
      int nfds;
      int timeout_ms;
    } poll;
  } data;
} SocketEventRecord;

/**
 * @brief SocketEventCallback - Event handler callback type
 *
 * @userdata: User-provided context
 * @event: Event record
 */
typedef void (*SocketEventCallback) (void *userdata,
                                     const SocketEventRecord *event);

/**
 * @brief SocketEvent_register - Register an event handler
 * @ingroup foundation
 * @param callback Callback function to register
 * @param userdata User data passed to callback
 * @return 0 on success, -1 on failure (NULL callback, duplicate, or limit
 * reached)
 * @threadsafe Yes
 */
int SocketEvent_register (SocketEventCallback callback, void *userdata);

/**
 * @brief SocketEvent_unregister - Unregister an event handler
 * @ingroup foundation
 * @param callback Callback function to unregister
 * @param userdata User data that was passed to register
 * @return 0 on success, -1 on failure (NULL callback or handler not found)
 * @threadsafe Yes
 */
int SocketEvent_unregister (SocketEventCallback callback, const void *userdata);

/**
 * @brief Emit connection accept event.
 * @ingroup foundation
 *
 * @param fd Client file descriptor.
 * @param peer_addr Peer IP address.
 * @param peer_port Peer port.
 * @param local_addr Local IP address.
 * @param local_port Local port.
 *
 * @threadsafe Yes
 */
void SocketEvent_emit_accept (int fd,
                              const char *peer_addr,
                              int peer_port,
                              const char *local_addr,
                              int local_port);

/**
 * @brief Emit outbound connection event.
 * @ingroup foundation
 *
 * @param fd Socket file descriptor.
 * @param peer_addr Peer IP address.
 * @param peer_port Peer port.
 * @param local_addr Local IP address.
 * @param local_port Local port.
 *
 * @threadsafe Yes
 */
void SocketEvent_emit_connect (int fd,
                               const char *peer_addr,
                               int peer_port,
                               const char *local_addr,
                               int local_port);

/**
 * @brief Emit DNS resolution timeout event.
 * @ingroup foundation
 *
 * @param host Hostname that timed out.
 * @param port Destination port.
 *
 * @threadsafe Yes
 */
void SocketEvent_emit_dns_timeout (const char *host, int port);

/**
 * @brief Emit poll wakeup event.
 * @ingroup foundation
 *
 * @param nfds Number of monitored file descriptors.
 * @param timeout_ms Poll timeout (-1 = infinite).
 *
 * @threadsafe Yes
 */
void SocketEvent_emit_poll_wakeup (int nfds, int timeout_ms);

#endif /* SOCKETEVENT_INCLUDED */
