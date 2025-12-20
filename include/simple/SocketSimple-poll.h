/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_POLL_INCLUDED
#define SOCKETSIMPLE_POLL_INCLUDED

/**
 * @file SocketSimple-poll.h
 * @brief Simple event-driven I/O multiplexing.
 *
 * Cross-platform wrapper for epoll (Linux), kqueue (BSD/macOS), or poll.
 * The backend is automatically selected at build time.
 *
 * Example:
 * @code
 * // Create poll instance
 * SocketSimple_Poll_T poll = Socket_simple_poll_new(64);
 * if (!poll) {
 *     fprintf(stderr, "Poll error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // Register sockets
 * Socket_simple_poll_add(poll, server, SOCKET_SIMPLE_POLL_READ, NULL);
 * Socket_simple_poll_add(poll, client, SOCKET_SIMPLE_POLL_READ, client_data);
 *
 * // Event loop
 * SocketSimple_PollEvent events[64];
 * while (running) {
 *     int n = Socket_simple_poll_wait(poll, events, 64, 1000);
 *     for (int i = 0; i < n; i++) {
 *         if (events[i].events & SOCKET_SIMPLE_POLL_READ) {
 *             // Handle read...
 *         }
 *     }
 * }
 *
 * Socket_simple_poll_free(&poll);
 * @endcode
 */

#include "SocketSimple-tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Opaque Handle Types
 *============================================================================*/

/**
 * @brief Opaque poll instance handle.
 */
typedef struct SocketSimple_Poll *SocketSimple_Poll_T;

/*============================================================================
 * Event Flags
 *============================================================================*/

/**
 * @brief Poll event flags.
 */
typedef enum {
    SOCKET_SIMPLE_POLL_READ   = 0x01,  /**< Socket is readable */
    SOCKET_SIMPLE_POLL_WRITE  = 0x02,  /**< Socket is writable */
    SOCKET_SIMPLE_POLL_ERROR  = 0x04,  /**< Socket has error */
    SOCKET_SIMPLE_POLL_HANGUP = 0x08   /**< Peer disconnected */
} SocketSimple_PollEvents;

/*============================================================================
 * Event Structure
 *============================================================================*/

/**
 * @brief Event notification from poll_wait.
 */
typedef struct SocketSimple_PollEvent {
    SocketSimple_Socket_T sock;  /**< Socket that triggered event */
    int events;                   /**< Bitmask of SocketSimple_PollEvents */
    void *data;                   /**< User data from poll_add */
} SocketSimple_PollEvent;

/*============================================================================
 * Poll Lifecycle
 *============================================================================*/

/**
 * @brief Create a new poll instance.
 *
 * @param max_events Maximum events to handle per wait call.
 * @return Poll handle on success, NULL on error.
 */
extern SocketSimple_Poll_T Socket_simple_poll_new(int max_events);

/**
 * @brief Free poll instance.
 *
 * Sets *poll to NULL after freeing.
 *
 * @param poll Pointer to poll handle.
 */
extern void Socket_simple_poll_free(SocketSimple_Poll_T *poll);

/*============================================================================
 * Socket Registration
 *============================================================================*/

/**
 * @brief Register a socket for monitoring.
 *
 * @param poll Poll handle.
 * @param sock Socket to monitor.
 * @param events Events to watch (bitmask of SocketSimple_PollEvents).
 * @param data User data to associate with socket.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_poll_add(SocketSimple_Poll_T poll,
                                   SocketSimple_Socket_T sock,
                                   int events,
                                   void *data);

/**
 * @brief Modify events/data for a registered socket.
 *
 * @param poll Poll handle.
 * @param sock Socket to modify.
 * @param events New event mask.
 * @param data New user data (or NULL to keep existing).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_poll_mod(SocketSimple_Poll_T poll,
                                   SocketSimple_Socket_T sock,
                                   int events,
                                   void *data);

/**
 * @brief Deregister a socket.
 *
 * @param poll Poll handle.
 * @param sock Socket to remove.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_poll_del(SocketSimple_Poll_T poll,
                                   SocketSimple_Socket_T sock);

/**
 * @brief Add or remove event flags for a socket.
 *
 * @param poll Poll handle.
 * @param sock Socket to modify.
 * @param add_events Events to add (0 to skip).
 * @param remove_events Events to remove (0 to skip).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_poll_modify_events(SocketSimple_Poll_T poll,
                                             SocketSimple_Socket_T sock,
                                             int add_events,
                                             int remove_events);

/*============================================================================
 * Event Waiting
 *============================================================================*/

/**
 * @brief Wait for events.
 *
 * @param poll Poll handle.
 * @param events Output array for events.
 * @param max_events Maximum events to return.
 * @param timeout_ms Timeout in milliseconds (-1 for infinite, 0 for non-blocking).
 * @return Number of events (>=0), or -1 on error.
 */
extern int Socket_simple_poll_wait(SocketSimple_Poll_T poll,
                                    SocketSimple_PollEvent *events,
                                    int max_events,
                                    int timeout_ms);

/*============================================================================
 * Poll Information
 *============================================================================*/

/**
 * @brief Get the poll backend name.
 *
 * @param poll Poll handle.
 * @return "epoll", "kqueue", or "poll".
 */
extern const char *Socket_simple_poll_backend(SocketSimple_Poll_T poll);

/**
 * @brief Get number of registered sockets.
 *
 * @param poll Poll handle.
 * @return Number of sockets, or -1 on error.
 */
extern int Socket_simple_poll_count(SocketSimple_Poll_T poll);

/**
 * @brief Get maximum registered sockets.
 *
 * @param poll Poll handle.
 * @return Maximum sockets, or -1 on error.
 */
extern int Socket_simple_poll_max(SocketSimple_Poll_T poll);

/**
 * @brief Set default timeout for wait calls.
 *
 * @param poll Poll handle.
 * @param timeout_ms Default timeout in milliseconds.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_poll_set_timeout(SocketSimple_Poll_T poll,
                                           int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_POLL_INCLUDED */
