#ifndef SOCKETPOLL_PRIVATE_INCLUDED
#define SOCKETPOLL_PRIVATE_INCLUDED

#include "core/Arena.h" /* For memory */
#include "core/SocketTimer-private.h" /* For timer heap integration */
#include "poll/SocketPoll.h"
#include "poll/SocketPoll_backend.h"

#include "core/SocketConfig.h"

/**
 * Private internal functions for SocketPoll module - not public API.
 * Used by SocketPoll implementation and backends.
 * Thread-safe where noted.
 */

/* Hash and mapping private functions */
extern unsigned socket_hash (const Socket_T socket);
extern SocketData *find_socket_data (T poll, Socket_T socket);
extern void update_socket_map (T poll, Socket_T socket, void *data);
extern void remove_socket_map (T poll, Socket_T socket);
extern FdSocketEntry *find_fd_socket (T poll, int fd);
extern void update_fd_socket_map (T poll, int fd, Socket_T socket);
extern void remove_fd_socket_map (T poll, int fd);

/* Backend wrapper private functions */
extern int backend_add_wrapped (PollBackend_T backend, int fd,
                                unsigned events);
extern int backend_mod_wrapped (PollBackend_T backend, int fd,
                                unsigned events);
extern int backend_del_wrapped (PollBackend_T backend, int fd);
extern int backend_wait_wrapped (PollBackend_T backend, int timeout);
extern int backend_get_event_wrapped (PollBackend_T backend, int index,
                                      int *fd_out, unsigned *events_out);

/* Validation and utility */
extern int validate_add_params (T poll, Socket_T socket, unsigned events);
extern int validate_mod_params (T poll, Socket_T socket, unsigned events);
extern unsigned poll_translate_to_backend (unsigned events);
extern unsigned poll_translate_from_backend (unsigned backend_events);

/* Event processing */
extern int process_events (T poll, int nev, SocketEvent_T **out_events);

/* Timer heap access for SocketTimer integration */
extern SocketTimer_heap_T *socketpoll_get_timer_heap (T poll);

/* Global constants */
#define MAP_LOAD_FACTOR 0.7f /* Resize threshold */

#endif /* SOCKETPOLL_PRIVATE_INCLUDED */
