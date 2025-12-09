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
  /**
   * @var dtls_ctx
   * @brief Opaque pointer to the DTLS context object.
   * References an instance of SocketDTLSContext_T or underlying TLS library context (e.g., SSL_CTX *).
   * Manages global security parameters: certificates, private keys, cipher suites, and protocol versions for the connection.
   * Created during DTLS enablement and used to initialize per-connection SSL objects.
   * @internal
   * @ingroup security
   * @see SocketDTLSContext_T for public type.
   * @see SocketDTLSConfig.h for configuration options.
   * @see dtls_ssl for per-connection session object.
   */
  void *dtls_ctx;                /**< @copydoc dtls_ctx */
  /**
   * @var dtls_ssl
   * @brief Opaque pointer to the per-connection DTLS SSL session object.
   * Instance of underlying TLS library's SSL structure (e.g., OpenSSL SSL *) handling the specific DTLS session.
   * Manages handshake state, record encryption/decryption, certificate verification, and session keys.
   * Created from dtls_ctx during connection setup.
   * @internal
   * @ingroup security
   * @see SSL(3) or equivalent TLS library docs for details.
   * @see dtls_ctx for the parent context.
   * @see dtls_handshake_done for handshake status.
   */
  void *dtls_ssl;                /**< @copydoc dtls_ssl */
  /**
   * @var dtls_enabled
   * @brief Flag indicating if DTLS is enabled on this datagram socket.
   * Set to 1 when DTLS context and SSL object are initialized and active, 0 otherwise.
   * Controls whether DTLS encryption/decryption is applied to I/O operations.
   * @internal
   * @ingroup security
   * @see SocketDTLS_enable() or equivalent initialization function.
   * @see dtls_ctx and dtls_ssl for enabled components.
   */
  int dtls_enabled;              /**< @copydoc dtls_enabled */
  /**
   * @var dtls_handshake_done
   * @brief Flag indicating whether the DTLS handshake has completed successfully.
   * Set to 1 upon successful completion of the DTLS handshake process, 0 otherwise.
   * This flag is used internally to determine if encrypted data transfer can begin.
   * @internal
   * @ingroup security
   * @see dtls_ssl for the SSL object used in handshake.
   * @see SocketDTLS.h for public DTLS handshake functions.
   */
  int dtls_handshake_done;       /**< @copydoc dtls_handshake_done */
  /**
   * @var dtls_shutdown_done
   * @brief Flag indicating whether the DTLS shutdown process has completed.
   * Set to 1 after successful DTLS shutdown handshake or close_notify alert exchange, 0 otherwise.
   * Used to track connection closure state for resource cleanup.
   * @internal
   * @ingroup security
   * @see SocketDTLS_shutdown() for initiating shutdown.
   * @see dtls_ssl for the SSL object involved in shutdown.
   */
  int dtls_shutdown_done;        /**< @copydoc dtls_shutdown_done */
  /**
   * @var dtls_last_handshake_state
   * @brief Records the last DTLS handshake state from the TLS library.
   * Stores the result of the most recent DTLS handshake operation (e.g., DTLS_HANDSHAKE_WANT_READ).
   * Used for resuming or error recovery in non-blocking handshake loops.
   * @internal
   * @ingroup security
   * @see SocketDTLSHandshakeState for possible values.
   * @see dtls_ssl for the SSL context providing this state.
   */
  int dtls_last_handshake_state; /**< @copydoc dtls_last_handshake_state */
  /**
   * @var dtls_mtu
   * @brief Configured Maximum Transmission Unit (MTU) for DTLS packets.
   * Specifies the maximum size of DTLS records to avoid IP fragmentation.
   * Typically set to path MTU minus DTLS overhead (e.g., 1200-1400 bytes).
   * @internal
   * @ingroup security
   * @see SocketDTLS_set_mtu() if public API exists, or configuration functions.
   * @see dtls_ctx for context where MTU is applied.
   */
  size_t dtls_mtu;               /**< @copydoc dtls_mtu */
  /**
   * @var dtls_sni_hostname
   * @brief Server Name Indication (SNI) hostname string for DTLS.
   * Arena-allocated string used during TLS handshake to indicate the target server name.
   * Allows virtual hosting on the server side; required for SNI extension in TLS.
   * @internal
   * @ingroup security
   * @see SocketDTLS_set_hostname() or equivalent for setting.
   * @see dtls_ctx for context configuration.
   */
  char *dtls_sni_hostname;       /**< @copydoc dtls_sni_hostname */

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
  /**
   * @var dtls_peer_host
   * @brief Cached peer hostname for efficient DTLS resolution.
   * Arena-allocated string storing the last resolved hostname to avoid repeated DNS lookups.
   * Part of the peer resolution cache with 30-second TTL.
   * @internal
   * @ingroup security
   * @see dtls_peer_cache_ts for cache timestamp.
   * @see SocketDNS.h for DNS resolution used to populate this cache.
   */
  char *dtls_peer_host;           /**< @copydoc dtls_peer_host */
  /**
   * @var dtls_peer_port
   * @brief Cached peer port number for the DTLS connection.
   * Stores the port associated with the cached hostname and resolution for quick access.
   * Updated during cache population from resolution results.
   * @internal
   * @ingroup security
   * @see dtls_peer_host for associated hostname.
   * @see dtls_peer_res for resolved addresses.
   */
  int dtls_peer_port;             /**< @copydoc dtls_peer_port */
  /**
   * @var dtls_peer_res
   * @brief Cached resolved address information for peer.
   * Pointer to addrinfo structure from getaddrinfo, holding IP addresses and socket params.
   * Freed with freeaddrinfo() upon cache invalidation or socket free.
   * Enables efficient sendto/recvfrom without re-resolving host each time.
   * @internal
   * @ingroup security
   * @see dtls_peer_host and dtls_peer_port for cache keys.
   * @see SocketDNS.h for resolution source.
   */
  struct addrinfo *dtls_peer_res; /**< @copydoc dtls_peer_res */
  /**
   * @var dtls_peer_cache_ts
   * @brief Monotonic timestamp when peer resolution cache was populated.
   * Used to enforce 30-second TTL for cache validity; cache invalidated if current time exceeds this + 30s.
   * Relies on Socket_get_monotonic_ms() for consistent timing across system clock changes.
   * @internal
   * @ingroup security
   * @see Socket_get_monotonic_ms() for time source.
   * @see dtls_peer_res for cached data controlled by this timestamp.
   */
  int64_t dtls_peer_cache_ts;     /**< @copydoc dtls_peer_cache_ts */

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
  /**
   * @var dtls_rbio
   * @brief Read BIO for incoming encrypted DTLS data.
   * Memory BIO buffering encrypted packets received from the socket before decryption by the DTLS layer.
   * Integrates with non-blocking I/O via SocketPoll for read readiness.
   * @internal
   * @ingroup security
   * @see BIO(3) for OpenSSL BIO documentation.
   * @see SocketPoll.h for event integration.
   * @see dtls_wbio for write counterpart.
   */
  void *dtls_rbio; /**< @copydoc dtls_rbio */
  /**
   * @var dtls_wbio
   * @brief Write BIO for outgoing encrypted DTLS data.
   * Memory BIO buffering encrypted packets generated by the DTLS layer before transmission over the socket.
   * Supports non-blocking write operations with flow control and partial writes.
   * @internal
   * @ingroup security
   * @see BIO(3) for OpenSSL BIO documentation.
   * @see SocketPoll.h for event-driven write readiness.
   * @see dtls_rbio for read counterpart.
   */
  void *dtls_wbio; /**< @copydoc dtls_wbio */

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
  /**
   * @var dtls_read_buf
   * @brief Buffer for decrypted application data received via DTLS.
   * Arena-allocated raw buffer holding plaintext data after DTLS decryption.
   * Facilitates zero-copy processing in non-blocking recv operations.
   * @internal
   * @ingroup security
   * @see dtls_read_buf_len for current content length.
   * @see SocketBuf_secureclear() pattern for sensitive data handling (though raw buffer).
   */
  void *dtls_read_buf;       /**< @copydoc dtls_read_buf */
  /**
   * @var dtls_write_buf
   * @brief Buffer holding encrypted data ready for transmission over DTLS.
   * Arena-allocated storage for ciphertext generated by the DTLS encryption process.
   * Used to buffer outgoing data post-encryption before socket send operations.
   * Supports minimal-copy transmission in non-blocking scenarios.
   * @internal
   * @ingroup security
   * @see dtls_write_buf_len for tracking filled length.
   * @see SocketBuf.h for related buffer management concepts.
   * @see dtls_wbio for the associated memory BIO.
   */
  void *dtls_write_buf;      /**< @copydoc dtls_write_buf */
  /**
   * @var dtls_read_buf_len
   * @brief Length of valid decrypted data in the read buffer.
   * Tracks the number of bytes currently available in dtls_read_buf after decryption.
   * Updated after successful recv/decrypt operations; used for data availability checks.
   * @internal
   * @ingroup security
   * @see dtls_read_buf for the buffer data.
   * @see dtls_write_buf_len for write counterpart.
   */
  size_t dtls_read_buf_len;  /**< @copydoc dtls_read_buf_len */
  /**
   * @var dtls_write_buf_len
   * @brief Length of valid encrypted data in the write buffer.
   * Tracks bytes ready for transmission in dtls_write_buf post-encryption.
   * Incremented after encrypt operations, decremented after successful sends.
   * @internal
   * @ingroup security
   * @see dtls_write_buf for the buffer data.
   * @see dtls_read_buf_len for read counterpart.
   */
  size_t dtls_write_buf_len; /**< @copydoc dtls_write_buf_len */
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
