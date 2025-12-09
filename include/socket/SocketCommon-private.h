#ifndef SOCKETCOMMON_PRIVATE_INCLUDED
#define SOCKETCOMMON_PRIVATE_INCLUDED

/**
 * @file SocketCommon-private.h
 * @brief Private declarations for the SocketCommon module.
 * @ingroup core_io
 * @internal
 *
 * Contains internal structure definitions (e.g., SocketBase_T implementation),
 * static helper functions, and module exception forward declarations.
 *
 * This header is included only from SocketCommon.c and related implementation
 * files (e.g., Socket.c, SocketDgram.c). It is NOT part of the public API.
 *
 * @warning Do NOT include this header in public headers or user code.
 * @see SocketCommon.h for the public interface.
 * @see @ref core_io "Core I/O Module Group" for overview.
 *
 * ### Coding Standards Compliance
 * - Opaque types declared in public headers (.h), full structs defined here.
 * - GNU C11 style with comprehensive Doxygen documentation for maintainers.
 * - Module-specific exceptions declared here for convenience across implementations.
 * - Thread-safety documented per function; generally requires external synchronization.
 *
 * @see docs/CODING_STANDARDS.md for full rules (if exists) or .cursorrules.
 */

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/Socket.h" /* For SocketTimeouts_T if not in config */
#include "socket/SocketCommon.h"
#include <stdbool.h>

/**
 * @brief Internal implementation structure for SocketBase_T opaque type.
 * @ingroup core_io
 * @internal
 *
 * Defines the full structure for the shared socket base, embedded in subtypes
 * like Socket_T and SocketDgram_T. Manages common resources and state including
 * fd, arena, endpoints, timeouts, and metrics.
 *
 * @see SocketBase_T (opaque) in SocketCommon.h
 * @see SocketCommon_new_base(), SocketCommon_free_base()
 */
struct SocketBase_T
{
  int fd;        /**< Socket file descriptor (-1 if closed) */
  Arena_T arena; /**< Per-socket memory arena for lifecycle */
  int domain;    /**< Address domain (AF_INET, AF_INET6, AF_UNIX) */
  int type;      /**< Socket type (SOCK_STREAM, SOCK_DGRAM) */
  int protocol;  /**< Protocol (0 for default) */
  pthread_mutex_t
      mutex; /**< Mutex for thread-safe base access (options, endpoints) */

  /* Endpoint information */
  struct sockaddr_storage local_addr; /**< Local bound address */
  socklen_t local_addrlen;            /**< Length of local_addr */
  char *localaddr; /**< String representation of local address (allocated in
                      arena) */
  int localport;   /**< Local port number */

  struct sockaddr_storage remote_addr; /**< Remote peer address */
  socklen_t remote_addrlen;            /**< Length of remote_addr */
  char *remoteaddr; /**< String representation of remote address (allocated in
                       arena) */
  int remoteport;   /**< Remote port number */

  SocketTimeouts_T timeouts; /**< Timeout configuration */

  SocketMetricsSnapshot metrics; /**< Per-socket metrics snapshot */

  /* Additional common fields can be added here */
  /* e.g., bool is_nonblock; int refcount; etc. */
};

/* ============================================================================
 * Accessor Functions for SocketBase_T Fields
 * ============================================================================
 * These functions provide controlled access to private fields of SocketBase_T.
 * Defined in SocketCommon.c; used by socket subtypes for internal operations.
 * Generally not thread-safe; caller must acquire base->mutex if needed.
 * @internal
 * @ingroup core_io
 */

/**
 * @brief Retrieve the socket file descriptor from the base structure.
 * @internal
 * @param base Socket base instance (non-NULL).
 * @return File descriptor (int fd, -1 if closed/invalid).
 * @note Direct access discouraged; use for low-level operations like poll/epoll.
 * @see socket(2), close(2)
 */
extern int SocketBase_fd (SocketBase_T base);

/**
 * @brief Get the memory arena associated with the socket base.
 * @internal
 * @param base Socket base instance.
 * @return Arena_T used for this socket's allocations.
 * @note Used for allocating per-socket resources (buffers, strings).
 * @see Arena.h, ALLOC() macro
 */
extern Arena_T SocketBase_arena (SocketBase_T base);

/**
 * @brief Get the address domain (family) of the socket.
 * @internal
 * @param base Socket base instance.
 * @return Domain (AF_INET, AF_INET6, AF_UNIX, etc.).
 * @note Set at creation; used for address resolution and options.
 * @see getaddrinfo(3), AF_*
 */
extern int SocketBase_domain (SocketBase_T base);

/**
 * @brief Get cached remote address string representation.
 * @internal
 * @param base Socket base instance.
 * @return Pointer to arena-allocated remote address string, or NULL if unset/unavailable.
 * @note String format: numeric IP or Unix path; NULL-checked.
 * @see SocketBase_remoteport()
 */
static inline char *
SocketBase_remoteaddr (SocketBase_T base)
{
  return base ? base->remoteaddr : NULL;
}

/**
 * @brief Get remote peer port number.
 * @internal
 * @param base Socket base instance.
 * @return Remote port (0 if unknown/unconnected).
 * @see SocketBase_remoteaddr()
 */
static inline int
SocketBase_remoteport (SocketBase_T base)
{
  return base ? base->remoteport : 0;
}

/**
 * @brief Get cached local address string representation.
 * @internal
 * @param base Socket base instance.
 * @return Pointer to arena-allocated local address string, or NULL if unset.
 * @note Updated after bind(); format depends on domain.
 * @see SocketBase_localport()
 */
static inline char *
SocketBase_localaddr (SocketBase_T base)
{
  return base ? base->localaddr : NULL;
}

/**
 * @brief Get local port number.
 * @internal
 * @param base Socket base instance.
 * @return Local port (0 if unbound).
 * @see SocketBase_localaddr()
 */
static inline int
SocketBase_localport (SocketBase_T base)
{
  return base ? base->localport : 0;
}

/**
 * @brief Get pointer to timeouts configuration structure.
 * @internal
 * @param base Socket base instance.
 * @return Pointer to timeouts struct, or NULL if base invalid.
 * @note Allows modification; caller should lock mutex if threaded.
 * @see SocketCommon_set_timeouts() for global defaults.
 */
static inline SocketTimeouts_T *
SocketBase_timeouts (SocketBase_T base)
{
  return base ? &base->timeouts : NULL;
}

/* Additional endpoint field accessors can be added as needed */

/**
 * @brief Set the timeouts configuration for the socket base.
 * @internal
 * @param base Socket base instance.
 * @param timeouts Source timeouts to copy (may be NULL for defaults).
 * @note Copies values; does not take ownership.
 * @see SocketBase_timeouts() getter.
 * @see SocketCommon_timeouts_getdefaults()
 */
extern void SocketBase_set_timeouts (SocketBase_T base,
                                     const SocketTimeouts_T *timeouts);

/* ... add more extern decls for getters/setters as needed */

/**
 * @brief Create a new socket file descriptor.
 * @internal
 * @param domain Address family (AF_INET, etc.).
 * @param type Socket type (SOCK_STREAM, etc.).
 * @param protocol Protocol (usually 0).
 * @param exc_type Exception to raise on failure.
 * @return New fd on success, -1 on error (raises exception).
 * @note Wrapper around socket() syscall with error handling.
 * @see socket(2)
 */
extern int SocketCommon_create_fd (int domain, int type, int protocol,
                                   Except_T exc_type);

/**
 * @brief Initialize a pre-allocated SocketBase_T instance.
 * @internal
 * @param base Pre-allocated base structure.
 * @param fd File descriptor to associate.
 * @param domain Address family.
 * @param type Socket type.
 * @param protocol Protocol.
 * @param exc_type Exception for errors.
 * @note Initializes fields, creates arena, sets CLOEXEC, etc.
 * @note Called after socket() or from_fd().
 * @see SocketCommon_new_base() which allocates + inits.
 */
extern void SocketCommon_init_base (SocketBase_T base, int fd, int domain,
                                    int type, int protocol, Except_T exc_type);

/**
 * @brief Determine socket address family from base or fd.
 * @internal
 * @param base Socket base (may be NULL).
 * @param raise_on_fail If true, raise exc_type on failure.
 * @param exc_type Exception to raise if raise_on_fail.
 * @return AF_* family, or AF_UNSPEC on failure (no raise).
 * @note Uses SO_DOMAIN (Linux) or getsockname() fallback.
 * @note Unifies family detection across modules.
 */
extern int
SocketCommon_get_family (SocketBase_T base, bool raise_on_fail,
                         Except_T exc_type);

/* ============================================================================
 * Shared Socket Option Functions
 * ============================================================================
 * Consolidated implementations for common socket options to avoid duplication
 * across Socket.c, SocketDgram.c, and other modules. These handle setsockopt()
 * with proper error raising via exceptions.
 *
 * @internal
 * @ingroup core_io
 * @note All functions lock base->mutex for thread-safety.
 * @note Platform-specific handling (e.g., SO_NOSIGPIPE on BSD).
 */

/**
 * @brief Enable address reuse (SO_REUSEADDR).
 * @internal
 * @param base Socket base.
 * @param exc_type Exception to raise on failure.
 * @note Allows binding to same address/port after close; standard for servers.
 * @see setsockopt(2), SO_REUSEADDR
 */
extern void SocketCommon_setreuseaddr (SocketBase_T base, Except_T exc_type);

/**
 * @brief Enable port reuse (SO_REUSEPORT).
 * @internal
 * @param base Socket base.
 * @param exc_type Exception to raise on failure.
 * @note Allows multiple sockets to bind same port (load balancing); Linux/BSD.
 * @see setsockopt(2), SO_REUSEPORT
 */
extern void SocketCommon_setreuseport (SocketBase_T base, Except_T exc_type);

/**
 * @brief Set socket-level timeout for I/O operations.
 * @internal
 * @param base Socket base.
 * @param timeout_sec Timeout in seconds (0=disable).
 * @param exc_type Exception on failure.
 * @note Sets both SO_SNDTIMEO and SO_RCVTIMEO.
 * @see SocketCommon_getoption_timeval()
 */
extern void SocketCommon_settimeout (SocketBase_T base, int timeout_sec,
                                     Except_T exc_type);

/**
 * @brief Set FD_CLOEXEC flag with error handling.
 * @internal
 * @param base Socket base.
 * @param enable 1 to set, 0 to clear.
 * @param exc_type Exception on failure.
 * @note Prevents fd inheritance across exec(); uses fcntl F_SETFD.
 * @see SocketCommon_setcloexec() public variant.
 */
extern void SocketCommon_setcloexec_with_error (SocketBase_T base, int enable,
                                                Except_T exc_type);

/**
 * @brief Disable SIGPIPE generation on send (platform-specific).
 * @internal
 * @param fd File descriptor.
 * @note On BSD/macOS: sets SO_NOSIGPIPE=1; on Linux: uses MSG_NOSIGNAL in send.
 * @note Library policy: No global signal handlers; handle per-operation or opt.
 * @see send(2), MSG_NOSIGNAL
 */
extern void SocketCommon_disable_sigpipe (int fd);

/**
 * @brief Deep copy of addrinfo linked list (internal implementation).
 * @internal
 * @param src Source addrinfo chain (may be NULL).
 * @return Deep copy allocated with malloc (free with SocketCommon_free_addrinfo).
 * @note Copies entire chain, including ai_addr and ai_canonname.
 * @note Used internally for resolve_address caching; public in SocketCommon.h.
 * @see SocketCommon_free_addrinfo()
 * @see getaddrinfo(3)
 */
extern struct addrinfo *SocketCommon_copy_addrinfo (
    const struct addrinfo *src);

/* ============================================================================
 * Internal Low-Level Utility Functions
 * ============================================================================
 * Helper functions for hostname validation, IP detection, and string conversion.
 * Shared across SocketCommon-resolve.c and SocketCommon-utils.c implementations.
 * Prefixed 'socketcommon_' for internal namespace.
 *
 * @internal
 * @ingroup core_io
 */

/**
 * @brief Normalize and validate host string for safe resolution use.
 * @internal
 * @param host Input host (may be NULL, wildcard, or invalid).
 * @return Safe host string: NULL for wildcards/invalids, validated copy otherwise.
 * @note Handles normalization (e.g., "0.0.0.0" -> NULL for bind).
 * @see SocketCommon_normalize_wildcard_host()
 */
extern const char *socketcommon_get_safe_host (const char *host);

/**
 * @brief Internal hostname validation with optional exception raising.
 * @internal
 * @param host Hostname string.
 * @param use_exceptions True to raise exc_type on failure.
 * @param exception_type Type to raise if invalid and using exceptions.
 * @return 1 valid, 0 invalid (no raise), -1 error.
 * @note Checks length, format; used by public validate_hostname().
 */
extern int socketcommon_validate_hostname_internal (const char *host,
                                                    int use_exceptions,
                                                    Except_T exception_type);

/**
 * @brief Detect if string is a valid IP address (v4/v6).
 * @internal
 * @param host String to test.
 * @return true if parses as IP, false otherwise.
 * @note No allocation; fast string check.
 * @see SocketCommon_parse_ip() for family extraction.
 */
extern bool socketcommon_is_ip_address (const char *host);

/**
 * @brief Format port number as string with bounds checking.
 * @internal
 * @param port Port integer (0-65535 expected).
 * @param port_str Output buffer.
 * @param bufsize Buffer size (>=6).
 * @note Validates range; uses snprintf; null-terminates.
 * @note Used in error messages, URI building.
 */
extern void socketcommon_convert_port_to_string (int port, char *port_str,
                                                 size_t bufsize);

/* ============================================================================
 * Module Exception Forward Declarations
 * ============================================================================
 * Convenience forward declarations for module-specific exceptions.
 * Allows .c files to RAISE without per-file externs.
 * Definitions in respective .c files (Socket.c, etc.).
 * Also declared publicly in SocketCommon.h for user TRY/EXCEPT blocks.
 *
 * @internal for implementation convenience.
 * @ingroup core_io
 * @see Except_T in core/Except.h
 * @see SOCKET_DECLARE_MODULE_EXCEPTION() macro pattern.
 */

/**
 * @brief Generic socket failure exception (creation, bind, connect, etc.).
 * @ingroup core_io
 * @see Socket module errors.
 */
extern const Except_T Socket_Failed;

/**
 * @brief UDP/Datagram-specific failure exception.
 * @ingroup core_io
 * @see SocketDgram module.
 */
extern const Except_T SocketDgram_Failed;

/**
 * @brief Common utility failure (resolve, options, validation).
 * @ingroup core_io
 * @see SocketCommon utilities.
 */
extern const Except_T SocketCommon_Failed;

/**
 * @brief Sanitize and clamp timeout value to valid range.
 * @internal
 * @param timeout_ms Raw timeout milliseconds (may be negative or excessive).
 * @return Validated timeout: >=0 clamped to INT_MAX, or -1 if invalid input.
 * @note Applies library policy: negative -> 0 (no timeout), huge -> max int.
 * @note Used in timeout setters to prevent overflow/underflow.
 * @see SocketTimeouts_T, SocketCommon_settimeout()
 */
extern int socketcommon_sanitize_timeout (int timeout_ms);

#endif /* SOCKETCOMMON_PRIVATE_INCLUDED */
