#ifndef SOCKETDGRAM_PRIVATE_H_INCLUDED
#define SOCKETDGRAM_PRIVATE_H_INCLUDED

#include "socket/SocketCommon-private.h" /* For SocketBase_T */

/**
 * @file SocketDgram-private.h
 * @brief Internal implementation details for datagram (UDP) socket structure.
 * @ingroup core_io
 * @internal
 *
 * Defines the private struct SocketDgram_T, embedding SocketBase_T and
 * conditional DTLS fields. Intended for module-internal use only.
 *
 * @see SocketDgram.h for public API and opaque type declaration.
 * @see SocketCommon-private.h for base structure details.
 * @see Socket-private.h for analogous stream socket structure.
 */
/**
 * @brief Private structure for SocketDgram_T opaque type.
 * @ingroup core_io
 * @internal
 *
 * Embeds SocketBase_T for common socket fields (fd, arena, endpoints, timeouts, metrics).
 * Includes conditional DTLS fields when #SOCKET_HAS_TLS is enabled, providing support for
 * secure datagram encryption parallel to TLS in Socket_T.
 *
 * @var SocketDgram_T::base
 * Common base structure shared with other socket types.
 * Contains file descriptor, memory arena, local/remote addresses,
 * timeouts, and metrics tracking.
 *
 * @note This structure is not part of the public API and may change without notice.
 * Additional datagram-specific fields (e.g., multicast state) can be added here.
 *
 * @see SocketDgram.h for public interface.
 * @see SocketCommon-private.h for SocketBase_T details.
 * @see Socket-private.h for stream socket equivalent.
 * @see SocketDTLS.h for DTLS fields usage (if enabled).
 */
struct SocketDgram_T
{
  SocketBase_T base; /**< @copydoc SocketDgram_T::base */

#if SOCKET_HAS_TLS
  /**
   * @internal
   * DTLS-specific fields for secure datagram encryption.
   *
   * These fields are included only when SOCKET_HAS_TLS is enabled at compile time.
   * They provide Datagram TLS (DTLS) support, allowing TLS-secured UDP communications.
   * Key differences from stream TLS: handles packet loss/reordering, MTU fragmentation,
   * and uses memory BIOs for event-loop integration.
   *
   * @see @ref security "Security group" for TLS/DTLS modules.
   * @see SocketDTLS.h for public DTLS API.
   * @see SocketDTLSConfig.h for configuration options.
   */
  void *dtls_ctx;                /**< Opaque pointer to DTLS context (SocketDTLSContext_T *). Manages certificates, keys, and security parameters for the connection. @see SocketDTLSContext_T */
  void *dtls_ssl;                /**< Opaque pointer to the DTLS SSL object (e.g., OpenSSL SSL *). Manages the DTLS session state, handshake, and record layer processing. */
  int dtls_enabled;              /**< Boolean flag indicating DTLS is enabled and active (1 = yes, 0 = no). */
  int dtls_handshake_done;       /**< 1 if handshake complete */
  int dtls_shutdown_done;        /**< 1 if shutdown complete */
  int dtls_last_handshake_state; /**< Last DTLSHandshakeState value */
  size_t dtls_mtu;               /**< Configured MTU for this connection */
  char *dtls_sni_hostname;       /**< SNI hostname (arena-allocated) */

  /**
   * @internal
   * Cached peer resolution cache for efficient DTLS operations.
   *
   * Optimizes repeated sendto/recvfrom to the same host/port by caching
   * addrinfo results with a 30-second TTL (monotonic time-based).
   * Invalidated on resolution failure, expiry, or explicit reset.
   * Reduces DNS overhead in persistent DTLS sessions.
   *
   * @see SocketDNS.h for asynchronous DNS resolution used in population.
   */
  char *dtls_peer_host;           /**< Cached hostname (arena-allocated) */
  int dtls_peer_port;             /**< Cached port number */
  struct addrinfo *dtls_peer_res; /**< Cached resolved addrinfo (freeaddrinfo
                                     on invalidate) */
  int64_t dtls_peer_cache_ts;     /**< Monotonic timestamp of cache (invalidate
                                     after 30s) */

  /**
   * @internal
   * Memory BIOs for non-blocking DTLS I/O buffering.
   *
   * In DTLS, memory BIOs (Basic Input/Output) are used to handle encrypted data
   * independently of socket operations. This allows non-blocking handshake and
   * data transfer by buffering partial records and integrating with SocketPoll
   * for read/write readiness checks.
   *
   * - dtls_rbio: Buffer for incoming encrypted data from socket before decryption.
   * - dtls_wbio: Buffer for outgoing encrypted data to socket after encryption.
   *
   * @see SocketPoll.h for event-driven I/O multiplexing.
   * @see BIO(3) man page or TLS library docs for BIO usage.
   */
  void *dtls_rbio; /**< Read BIO (incoming encrypted data) */
  void *dtls_wbio; /**< Write BIO (outgoing encrypted data) */

  /**
   * @internal
   * Buffers for DTLS application data handling.
   *
   * Dedicated buffers for decrypted read data and encrypted write data at the
   * DTLS record layer. These facilitate zero-copy or minimal-copy processing
   * in non-blocking environments, with lengths tracking current usage.
   *
   * @note Buffers are securely cleared on free to prevent data leakage.
   * @see SocketBuf.h for general buffer management patterns (though these are raw).
   */
  void *dtls_read_buf;       /**< Decrypted read buffer (arena-allocated) */
  void *dtls_write_buf;      /**< Encrypted write buffer (arena-allocated) */
  size_t dtls_read_buf_len;  /**< Current read buffer content length */
  size_t dtls_write_buf_len; /**< Current write buffer content length */
#endif                       /* SOCKET_HAS_TLS */

  /**
   * @internal
   * Placeholder for non-conditional datagram-specific extensions.
   *
   * Future fields independent of TLS, enhancing core UDP capabilities:
   * - Multicast group management (joins, leaves, interfaces)
   * - TTL and hop limit optimization caches
   * - Connected peer state for simplified send/recv API
   * - Broadcast and packet info flags
   *
   * These would complement public SocketDgram API without security dependencies.
   *
   * @see SocketDgram.h for existing UDP features.
   * @see SocketDgram_bind(), SocketDgram_joinmulticast() for related public ops.
   */
};

#endif /* SOCKETDGRAM_PRIVATE_H_INCLUDED */
