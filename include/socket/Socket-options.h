/**
 * Socket-options.h - Socket option configuration functions
 *
 * Functions for setting and getting socket options including timeouts,
 * buffer sizes, TCP parameters, and Unix domain socket operations.
 */

#ifndef SOCKET_OPTIONS_INCLUDED
#define SOCKET_OPTIONS_INCLUDED

#include "core/SocketConfig.h"
#include "core/Except.h"

#define T Socket_T
typedef struct T *T;

/**
 * Socket_setnonblocking - Enable non-blocking mode
 * @socket: Socket to modify
 * Raises: Socket_Failed on error
 */
extern void Socket_setnonblocking (T socket);

/**
 * Socket_setreuseaddr - Enable address reuse
 * @socket: Socket to modify
 * Raises: Socket_Failed on error
 */
extern void Socket_setreuseaddr (T socket);

/**
 * Socket_setreuseport - Enable port reuse across sockets
 * @socket: Socket to modify
 * Raises: Socket_Failed on error (or if SO_REUSEPORT unsupported)
 */
extern void Socket_setreuseport (T socket);

/**
 * Socket_settimeout - Set socket timeout
 * @socket: Socket to modify
 * @timeout_sec: Timeout in seconds (0 to disable)
 * Sets both send and receive timeouts
 * Raises: Socket_Failed on error
 */
extern void Socket_settimeout (T socket, int timeout_sec);

/**
 * Socket_setkeepalive - Enable TCP keepalive
 * @socket: Socket to modify
 * @idle: Seconds before sending keepalive probes
 * @interval: Interval between keepalive probes
 * @count: Number of probes before declaring dead
 * Raises: Socket_Failed on error
 */
extern void Socket_setkeepalive (T socket, int idle, int interval, int count);

/**
 * Socket_setnodelay - Disable Nagle's algorithm
 * @socket: Socket to modify
 * @nodelay: 1 to disable Nagle, 0 to enable
 * Raises: Socket_Failed on error
 */
extern void Socket_setnodelay (T socket, int nodelay);

/**
 * Socket_gettimeout - Get socket timeout
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: Socket_Failed on error
 * Note: Returns receive timeout (send timeout may differ)
 */
extern int Socket_gettimeout (T socket);

/**
 * Socket_getkeepalive - Get TCP keepalive configuration
 * @socket: Socket to query
 * @idle: Output - idle timeout in seconds
 * @interval: Output - interval between probes in seconds
 * @count: Output - number of probes before declaring dead
 * Raises: Socket_Failed on error
 * Note: Returns 0 for parameters not supported on this platform
 */
extern void Socket_getkeepalive (T socket, int *idle, int *interval,
                                 int *count);

/**
 * Socket_getnodelay - Get TCP_NODELAY setting
 * @socket: Socket to query
 * Returns: 1 if Nagle's algorithm is disabled, 0 if enabled
 * Raises: Socket_Failed on error
 */
extern int Socket_getnodelay (T socket);

/**
 * Socket_getrcvbuf - Get receive buffer size
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: Socket_Failed on error
 */
extern int Socket_getrcvbuf (T socket);

/**
 * Socket_getsndbuf - Get send buffer size
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: Socket_Failed on error
 */
extern int Socket_getsndbuf (T socket);

/**
 * Socket_setrcvbuf - Set receive buffer size
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 * Note: The kernel may adjust the value to be within system limits.
 * Use Socket_getrcvbuf() to verify the actual size set.
 */
extern void Socket_setrcvbuf (T socket, int size);

/**
 * Socket_setsndbuf - Set send buffer size
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 * Note: The kernel may adjust the value to be within system limits.
 * Use Socket_getsndbuf() to verify the actual size set.
 */
extern void Socket_setsndbuf (T socket, int size);

/**
 * Socket_setcongestion - Set TCP congestion control algorithm
 * @socket: Socket to modify
 * @algorithm: Algorithm name (e.g., "cubic", "reno", "bbr")
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.13+. Common algorithms:
 * - "cubic" (default on many Linux systems)
 * - "reno" (classic TCP)
 * - "bbr" (Google BBR, Linux 4.9+)
 * - "bbr2" (BBR v2, Linux 4.20+)
 * Use Socket_getcongestion() to query current algorithm.
 */
extern void Socket_setcongestion (T socket, const char *algorithm);

/**
 * Socket_getcongestion - Get TCP congestion control algorithm
 * @socket: Socket to query
 * @algorithm: Output buffer for algorithm name
 * @len: Buffer length
 * Returns: 0 on success, -1 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.13+.
 * The algorithm name is written to the provided buffer.
 */
extern int Socket_getcongestion (T socket, char *algorithm, size_t len);

/**
 * Socket_setfastopen - Enable TCP Fast Open
 * @socket: Socket to modify
 * @enable: 1 to enable, 0 to disable
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: TCP Fast Open allows sending data in SYN packet.
 * Only available on Linux 3.7+, FreeBSD 10.0+, macOS 10.11+.
 * Must be set before connect() or listen().
 * Use Socket_getfastopen() to query current setting.
 */
extern void Socket_setfastopen (T socket, int enable);

/**
 * Socket_getfastopen - Get TCP Fast Open setting
 * @socket: Socket to query
 * Returns: 1 if enabled, 0 if disabled, -1 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on platforms that support TCP Fast Open.
 */
extern int Socket_getfastopen (T socket);

/**
 * Socket_setusertimeout - Set TCP user timeout
 * @socket: Socket to modify
 * @timeout_ms: Timeout in milliseconds (> 0)
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: TCP user timeout controls how long to wait for ACK before
 * closing connection. Only available on Linux 2.6.37+.
 * Use Socket_getusertimeout() to query current timeout.
 */
extern void Socket_setusertimeout (T socket, unsigned int timeout_ms);

/**
 * Socket_getusertimeout - Get TCP user timeout
 * @socket: Socket to query
 * Returns: Timeout in milliseconds, or 0 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.37+.
 */
extern unsigned int Socket_getusertimeout (T socket);

/**
 * Socket_shutdown - Disable further sends and/or receives
 * @socket: Connected socket
 * @how: Shutdown mode (SHUT_RD, SHUT_WR, or SHUT_RDWR)
 * Raises: Socket_Failed on error
 * Thread-safe: No (callers must synchronize concurrent access to the socket)
 */
extern void Socket_shutdown (T socket, int how);

/**
 * Socket_setcloexec - Control close-on-exec flag
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: Socket_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: By default, all sockets have CLOEXEC enabled. This function
 * allows disabling it if you need to pass the socket to a child process.
 */
extern void Socket_setcloexec (T socket, int enable);

/**
 * Socket_bind_unix - Bind to Unix domain socket path
 * @socket: Socket to bind (AF_UNIX)
 * @path: Socket file path
 * Raises: Socket_Failed on error
 * Note: Fails with EADDRINUSE if path exists. Max path length ~108 bytes.
 * Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_bind_unix (T socket, const char *path);

/**
 * Socket_connect_unix - Connect to Unix domain socket path
 * @socket: Socket to connect (AF_UNIX)
 * @path: Socket file path
 * Raises: Socket_Failed on error
 * Note: Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_connect_unix (T socket, const char *path);

/**
 * Socket_getpeerpid - Get peer process ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer process ID, or -1 if unavailable
 * Note: Only works on Linux with SO_PEERCRED.
 * Returns -1 on other platforms or non-Unix sockets.
 */
extern int Socket_getpeerpid (const T socket);

/**
 * Socket_getpeeruid - Get peer user ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer user ID, or (uid_t)-1 if unavailable
 * Note: Only works on Linux with SO_PEERCRED.
 * Returns -1 on other platforms or non-Unix sockets.
 */
extern int Socket_getpeeruid (const T socket);

/**
 * Socket_getpeergid - Get peer group ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer group ID, or (gid_t)-1 if unavailable
 * Note: Only works on Linux with SO_PEERCRED.
 * Returns -1 on other platforms or non-Unix sockets.
 */
extern int Socket_getpeergid (const T socket);

/**
 * Socket_timeouts_get - Retrieve per-socket timeout configuration
 * @socket: Socket instance
 * @timeouts: Output timeout structure
 * Returns: Nothing
 */
extern void Socket_timeouts_get (const T socket, SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_set - Set per-socket timeout configuration
 * @socket: Socket instance
 * @timeouts: Timeout configuration (NULL to reset to defaults)
 * Returns: Nothing
 */
extern void Socket_timeouts_set (T socket, const SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_getdefaults - Get global default timeouts
 * @timeouts: Output timeout structure containing current defaults
 * Returns: Nothing
 */
extern void Socket_timeouts_getdefaults (SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_setdefaults - Set global default timeouts
 * @timeouts: New default timeout configuration
 * Returns: Nothing
 */
extern void Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts);

#endif
