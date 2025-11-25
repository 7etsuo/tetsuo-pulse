/**
 * SocketCommon-hints.c - Address resolution hint setup utilities
 *
 * Contains functions for setting up addrinfo hints structures used
 * in DNS resolution and address operations.
 */

#include <netdb.h>
#include <string.h>

#include "core/SocketConfig.h"
#include "socket/SocketCommon.h"

/**
 * SocketCommon_setup_hints - Initialize addrinfo hints structure
 * @hints: Hints structure to initialize
 * @socktype: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @flags: Additional flags (0 for connect/sendto, AI_PASSIVE for bind)
 * Thread-safe: Yes
 */
void
SocketCommon_setup_hints (struct addrinfo *hints, int socktype, int flags)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = SOCKET_AF_UNSPEC;
  hints->ai_socktype = socktype;
  hints->ai_flags = flags;
  hints->ai_protocol = 0;
}
