/**
 * Socket-async.h - Asynchronous DNS resolution operations
 *
 * Functions for performing DNS resolution asynchronously using the
 * SocketDNS module, allowing non-blocking hostname resolution.
 */

#ifndef SOCKET_ASYNC_INCLUDED
#define SOCKET_ASYNC_INCLUDED

#include "core/Except.h"
#include "dns/SocketDNS.h"

#define T Socket_T
typedef struct T *T;

/**
 * Socket_bind_async - Start async DNS resolution for bind
 * @dns: DNS resolver instance
 * @socket: Socket to bind
 * @host: IP address or hostname (NULL for any)
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 * Starts async DNS resolution. Use SocketDNS_getresult() to check completion,
 * then call Socket_bind_with_addrinfo() to perform bind.
 * For non-blocking operation with SocketPoll:
 *   SocketDNS_Request_T req = Socket_bind_async(dns, socket, host, port);
 *   // In event loop when DNS completes:
 *   struct addrinfo *res = SocketDNS_getresult(dns, req);
 *   if (res) Socket_bind_with_addrinfo(socket, res);
 */
extern SocketDNS_Request_T Socket_bind_async (SocketDNS_T dns, T socket,
                                              const char *host, int port);

/**
 * Socket_bind_async_cancel - Cancel pending async bind resolution
 * @dns: DNS resolver instance
 * @req: Request handle returned by Socket_bind_async
 * Returns: Nothing
 */
extern void Socket_bind_async_cancel (SocketDNS_T dns,
                                      SocketDNS_Request_T req);

/**
 * Socket_connect_async - Start async DNS resolution for connect
 * @dns: DNS resolver instance
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port (1 to SOCKET_MAX_PORT)
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 * Starts async DNS resolution. Use SocketDNS_getresult() to check completion,
 * then call Socket_connect_with_addrinfo() to perform connect.
 */
extern SocketDNS_Request_T Socket_connect_async (SocketDNS_T dns, T socket,
                                                 const char *host, int port);

/**
 * Socket_connect_async_cancel - Cancel pending async connect resolution
 * @dns: DNS resolver instance
 * @req: Request handle returned by Socket_connect_async
 * Returns: Nothing
 */
extern void Socket_connect_async_cancel (SocketDNS_T dns,
                                         SocketDNS_Request_T req);

/**
 * Socket_bind_with_addrinfo - Bind socket using resolved address
 * @socket: Socket to bind
 * @res: Resolved addrinfo result from DNS resolution
 * Raises: Socket_Failed on error
 * Performs bind operation using pre-resolved address. Tries each address
 * in the result list until one succeeds.
 */
extern void Socket_bind_with_addrinfo (T socket, struct addrinfo *res);

/**
 * Socket_connect_with_addrinfo - Connect socket using resolved address
 * @socket: Socket to connect
 * @res: Resolved addrinfo result from DNS resolution
 * Raises: Socket_Failed on error
 * Performs connect operation using pre-resolved address. Tries each address
 * in the result list until one succeeds.
 */
extern void Socket_connect_with_addrinfo (T socket, struct addrinfo *res);

#endif
