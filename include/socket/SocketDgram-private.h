#ifndef SOCKETDGRAM_PRIVATE_H_INCLUDED
#define SOCKETDGRAM_PRIVATE_H_INCLUDED

#include "socket/SocketCommon-private.h"  /* For SocketBase_T */

/* SocketDgram structure definition - embeds common base */
struct SocketDgram_T
{
  SocketBase_T base; /* Embedded common base with fd, arena, endpoints,
                        timeouts, metrics */
  /* Datagram-specific fields can be added here if needed (e.g., multicast
   * groups, TTL cache) */
};

#endif /* SOCKETDGRAM_PRIVATE_H_INCLUDED */
