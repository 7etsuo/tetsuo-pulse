#ifndef SOCKET_PRIVATE_H_INCLUDED
#define SOCKET_PRIVATE_H_INCLUDED

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketRateLimit.h"  /* For bandwidth limiting */
#include "socket/SocketCommon-private.h"  /* For SocketBase_T */
#include "socket/Socket.h"
#include <stdatomic.h>

/* Socket live count management - shared across socket modules */
extern void socket_live_increment(void);
extern void socket_live_decrement(void);
extern int socket_debug_live_count(void);

#if SOCKET_HAS_TLS
/* TLS field initialization - shared between Socket.c and Socket-accept.c */
extern void socket_init_tls_fields(Socket_T sock);
#endif

/* Socket structure definition - embeds common base */
struct Socket_T
{
  SocketBase_T base;  /**< Common base with fd, arena, endpoints, timeouts, metrics */

  /* Bandwidth limiting */
  SocketRateLimit_T bandwidth_limiter;  /**< Rate limiter for bandwidth (NULL if unlimited) */

  _Atomic int freed;                    /**< Atomic flag to prevent double-free (0=active, 1=being freed; use memory_order_acq_rel for exchange) */

#if SOCKET_HAS_TLS
  /* TLS-specific fields (retained as stream-only) */
  void *tls_ctx;          /* SSL_CTX* - opaque */
  void *tls_ssl;          /* SSL* - opaque */
  int tls_enabled;        /* 1 if TLS active */
  int tls_handshake_done; /* 1 if handshake complete */
  int tls_shutdown_done;  /* 1 if shutdown complete */
  int tls_last_handshake_state;
  char *tls_sni_hostname;
  void *tls_read_buf;
  void *tls_write_buf;
  size_t tls_read_buf_len;
  size_t tls_write_buf_len;
  SocketTimeouts_T tls_timeouts; /* TLS-specific timeouts (base has general) */
#endif
};

#endif /* SOCKET_PRIVATE_H_INCLUDED */
