/**
 * Socket-state.h - Socket state query functions
 *
 * Functions for querying socket connection state, binding status,
 * and endpoint information.
 */

#ifndef SOCKET_STATE_INCLUDED
#define SOCKET_STATE_INCLUDED

#include "core/SocketConfig.h"
#include "core/Except.h"

#define T Socket_T
typedef struct T *T;

/**
 * Socket_isconnected - Check if socket is connected
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getpeername() to determine connection state.
 * For TCP sockets, checks if peer address is available.
 */
extern int Socket_isconnected (T socket);

/**
 * Socket_isbound - Check if socket is bound to an address
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getsockname() to determine binding state.
 * A socket is bound if getsockname() succeeds and returns a valid address.
 * Wildcard addresses (0.0.0.0 or ::) still count as bound.
 */
extern int Socket_isbound (T socket);

/**
 * Socket_islistening - Check if socket is listening for connections
 * @socket: Socket to check
 * Returns: 1 if listening, 0 if not listening
 * Thread-safe: Yes (operates on single socket)
 * Note: Checks if socket is bound and not connected.
 * A socket is listening if it's bound but has no peer address.
 */
extern int Socket_islistening (T socket);

/**
 * Socket_fd - Get underlying file descriptor
 * @socket: Socket instance
 * Returns: File descriptor
 */
extern int Socket_fd (const T socket);

/**
 * Socket_getpeeraddr - Get peer IP address
 * @socket: Connected socket
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: Returns "(unknown)" if address info unavailable during accept/connect.
 * String is owned by socket, must not be freed/modified. Valid until socket
 * freed.
 */
extern const char *Socket_getpeeraddr (const T socket);

/**
 * Socket_getpeerport - Get peer port number
 * @socket: Connected socket
 * Returns: Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable
 * Note: Returns 0 if port info unavailable during accept/connect.
 */
extern int Socket_getpeerport (const T socket);

/**
 * Socket_getlocaladdr - Get local IP address
 * @socket: Socket instance
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: Returns "(unknown)" if address info unavailable. String is owned by
 * socket, must not be freed/modified. Valid until socket freed.
 */
extern const char *Socket_getlocaladdr (const T socket);

/**
 * Socket_getlocalport - Get local port number
 * @socket: Socket instance
 * Returns: Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable
 */
extern int Socket_getlocalport (const T socket);

#endif
