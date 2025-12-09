#ifndef SOCKETDGRAM_PRIVATE_H_INCLUDED
#define SOCKETDGRAM_PRIVATE_H_INCLUDED

#include "socket/SocketCommon-private.h" /* For SocketBase_T */

/**
 * SocketDgram structure definition - embeds common base
 *
 * When SOCKET_HAS_TLS is defined, includes DTLS fields for encrypted
 * datagram communication (parallel to how Socket_T has TLS fields).
 */
struct SocketDgram_T
{
  SocketBase_T base; /**< Embedded common base with fd, arena, endpoints,
                          timeouts, metrics */

#if SOCKET_HAS_TLS
  /* DTLS-specific fields (enabled when TLS support compiled in) */
  void *dtls_ctx;                /**< SocketDTLSContext_T* - opaque */
  void *dtls_ssl;                /**< SSL* - opaque DTLS SSL object */
  int dtls_enabled;              /**< 1 if DTLS active on this socket */
  int dtls_handshake_done;       /**< 1 if handshake complete */
  int dtls_shutdown_done;        /**< 1 if shutdown complete */
  int dtls_last_handshake_state; /**< Last DTLSHandshakeState value */
  size_t dtls_mtu;               /**< Configured MTU for this connection */
  char *dtls_sni_hostname;       /**< SNI hostname (arena-allocated) */

  /* Cached peer resolution for efficient repeated sendto to same host/port
   * (30s TTL) */
  char *dtls_peer_host;           /**< Cached hostname (arena-allocated) */
  int dtls_peer_port;             /**< Cached port number */
  struct addrinfo *dtls_peer_res; /**< Cached resolved addrinfo (freeaddrinfo
                                     on invalidate) */
  int64_t dtls_peer_cache_ts;     /**< Monotonic timestamp of cache (invalidate
                                     after 30s) */

  /* BIO memory buffers for non-blocking I/O
   * DTLS uses memory BIOs to decouple SSL read/write from actual socket I/O,
   * allowing integration with our event polling system */
  void *dtls_rbio; /**< Read BIO (incoming encrypted data) */
  void *dtls_wbio; /**< Write BIO (outgoing encrypted data) */

  /* Read/write buffers for DTLS record layer */
  void *dtls_read_buf;       /**< Decrypted read buffer (arena-allocated) */
  void *dtls_write_buf;      /**< Encrypted write buffer (arena-allocated) */
  size_t dtls_read_buf_len;  /**< Current read buffer content length */
  size_t dtls_write_buf_len; /**< Current write buffer content length */
#endif                       /* SOCKET_HAS_TLS */

  /* Additional datagram-specific fields can be added here if needed
   * (e.g., multicast groups, TTL cache, connected peer info) */
};

#endif /* SOCKETDGRAM_PRIVATE_H_INCLUDED */
