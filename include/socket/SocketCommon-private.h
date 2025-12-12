/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETCOMMON_PRIVATE_INCLUDED
#define SOCKETCOMMON_PRIVATE_INCLUDED

/**
 * @file SocketCommon-private.h
 * @ingroup core_io
 * @brief Private declarations for SocketCommon module providing shared socket
 * infrastructure.
 * @internal
 *
 * This private header defines internal structures, helper functions, and
 * exception forward declarations shared between Socket and SocketDgram
 * implementations. It enables code reuse for common operations like base
 * initialization, option setting, and endpoint caching while maintaining
 * opaque public API.
 *
 *  Architecture Overview
 *
 * ```
 * ┌─────────────────────────────┐
 * │   Public API (Socket.h)     │
 * │   ├── Socket_T (opaque)     │
 * │   └── SocketDgram_T (opaque)│
 * └─────────┬───────────────────┘
 *           │ embeds/uses
 * ┌─────────▼───────────────────┐
 * │ SocketCommon-private.h      │
 * │ ├── struct SocketBase_T     │
 * │ ├── Accessors (get/set)     │
 * │ ├── Option setters          │
 * │ ├── Utilities (resolve,...) │
 * │ └── Exceptions              │
 * └─────────────────────────────┘
 *           │ implements in
 * ┌─────────▼───────────────────┐
 * │   SocketCommon.c            │
 * └─────────────────────────────┘
 * ```
 *
 *  Features
 *
 * - **Shared Base Structure**: SocketBase_T provides common fields (fd, arena,
 * endpoints, timeouts, metrics) embedded in subtypes.
 * - **Thread-Safe Accessors**: Controlled getters/setters with mutex
 * protection documentation.
 * - **Unified Option Setting**: Common implementations for SO_REUSEADDR,
 * SO_REUSEPORT, timeouts, CLOEXEC, SIGPIPE handling.
 * - **Address Resolution Helpers**: Internal validation, normalization,
 * caching for endpoints.
 * - **Exception Forwarding**: Module exceptions declared for consistent error
 * handling across files.
 * - **Platform Abstraction**: Handles differences (e.g., SO_DOMAIN on Linux,
 * getsockname fallback).
 *
 *  Platform Requirements
 *
 * - POSIX-compliant system with socket(), setsockopt(), fcntl(),
 * getaddrinfo().
 * - pthreads for mutex-based thread safety in base access.
 * - CLOCK_MONOTONIC for timing (via SocketUtil).
 * - No TLS dependencies (pure socket layer).
 *
 *  Usage Guidelines
 *
 * - Include only from .c implementation files, never public headers or user
 * code.
 * - Use accessors instead of direct field access for encapsulation.
 * - Always acquire base->mutex for multi-threaded modifications.
 * - Follow resource order: Arena -> FD -> Mutex init -> Endpoint cache.
 *
 * @warning Direct inclusion exposes internal ABI; changes may break subtypes.
 * @warning Not thread-safe by default; docs specify per-function guarantees.
 *
 * @see SocketCommon.h for public utilities and base API.
 * @see Socket.h and SocketDgram.h for subtype-specific operations.
 * @see @ref core_io "Core I/O Module Group" for complete socket primitives.
 * @see docs/ERROR_HANDLING.md for exception patterns.
 * @see .cursorrules for coding and build standards.
 */

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/Socket.h" /* For SocketTimeouts_T if not in config */
#include "socket/SocketCommon.h"
#include <stdbool.h>

/**
 * @brief Internal implementation of SocketBase_T opaque type.
 * @ingroup core_io
 * @internal
 *
 * Complete structure definition for the shared socket base, which is embedded
 * directly within subtype implementations (e.g., struct Socket_T, struct
 * SocketDgram_T). Centralizes management of common socket state: file
 * descriptor, memory arena, endpoint addresses/ports, timeouts, metrics, and
 * synchronization primitives.
 *
 *  Embedding Pattern
 *
 * Subtypes declare:
 *
 * @code{.c}
 * struct Subtype_T {
 *   SocketBase_T base;  // Embedded, not pointer
 *   // Subtype-specific fields
 * };
 * @endcode
 *
 * Access via getters/setters in this private header to maintain encapsulation.
 *
 *  Thread Safety
 *
 * - **Read Access**: Conditional - safe for immutable fields (domain, type)
 * without lock.
 * - **Write Access**: Requires pthread_mutex_lock(&base.mutex) / unlock.
 * - **Concurrent Use**: External synchronization needed for shared sockets
 * across threads.
 *
 *  Resource Lifecycle
 *
 * - **Creation**: SocketCommon_new_base() or SocketCommon_init_base()
 * allocates arena, initializes mutex, sets CLOEXEC.
 * - **Cleanup**: SocketCommon_free_base() closes fd, destroys mutex, disposes
 * arena.
 * - **Order**: FD close before mutex destroy before arena dispose.
 *
 * @note Endpoint strings (localaddr, remoteaddr) allocated in base.arena;
 * lifetime tied to base.
 * @note Metrics snapshot updated by I/O operations; use for per-socket
 * statistics.
 * @note Timeouts applied to connect, send/recv, etc. via base.timeouts.
 *
 * @see SocketBase_T opaque typedef in SocketCommon.h
 * @see SocketCommon_new_base() for allocation
 * @see SocketCommon_free_base() for deallocation
 * @see SocketCommon_init_base() for initialization from existing FD
 * @see docs/METRICS.md for metrics usage
 * @see core/SocketConfig.h for SocketTimeouts_T details
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

  SocketMetricsSnapshot metrics; /**< Per-socket metrics snapshot (legacy) */

  /* Per-socket statistics tracking */
  SocketStats_T stats; /**< Cumulative I/O statistics for this socket */
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
 * @ingroup core_io
 *
 * Provides access to the underlying file descriptor for low-level system calls
 * like poll(2), epoll_ctl(2), or direct read/write operations.
 *
 * @param[in] base Socket base instance (non-NULL)
 * @return File descriptor (int fd, -1 if closed/invalid)
 *
 * @throws None
 * @threadsafe Conditional - safe if no concurrent modification to base (fd
 * typically read-only after init)
 * @complexity O(1) - direct field access
 *
 *  Usage
 *
 * @code{.c}
 * int fd = SocketBase_fd(base);
 * if (fd >= 0) {
 *     // Use fd for poll or epoll
 *     struct pollfd pfd = { .fd = fd, .events = POLLIN };
 *     poll(&pfd, 1, timeout);
 * }
 * @endcode
 *
 * @note Direct fd access bypasses library wrappers; prefer high-level Socket_*
 * functions.
 * @warning fd is owned by base; do NOT close(2) directly - use Socket_free()
 * @see socket(2), close(2)
 * @see SocketCommon.h for public API equivalents like Socket_fd()
 */
extern int SocketBase_fd (SocketBase_T base);

/**
 * @brief Get the memory arena associated with the socket base.
 * @internal
 * @ingroup core_io
 *
 * Returns the per-socket Arena_T used for all allocations related to this
 * socket instance, ensuring consistent lifecycle management and avoiding
 * leaks.
 *
 * @param[in] base Socket base instance
 * @return Arena_T used for this socket's allocations
 *
 * @throws None
 * @threadsafe Conditional - safe if no concurrent arena modification
 * (typically read-only)
 * @complexity O(1) - direct field return
 *
 *  Usage Example
 *
 * @code{.c}
 * Arena_T arena = SocketBase_arena(base);
 * char *endpoint = ALLOC(arena, strlen(host) + 1);
 * strcpy(endpoint, host);  // Arena-managed allocation
 * @endcode
 *
 * @note All socket-related allocations (buffers, endpoint strings) should use
 * this arena.
 * @note Arena lifetime tied to socket base; dispose via
 * SocketCommon_free_base().
 * @see core/Arena.h for arena API and ALLOC()/CALLOC() macros
 * @see @ref foundation "Foundation Module Group" for memory management details
 * @see SocketBase_T for arena role in resource management
 */
extern Arena_T SocketBase_arena (SocketBase_T base);

/**
 * @brief Get the address domain (family) of the socket.
 * @internal
 * @ingroup core_io
 *
 * Returns the address family used when creating the socket, determining
 * supported address types (IPv4, IPv6, Unix domain).
 *
 * @param[in] base Socket base instance
 * @return Domain constant (AF_INET, AF_INET6, AF_UNIX, etc.)
 *
 * @throws None
 * @threadsafe Yes - immutable after creation, no lock needed
 * @complexity O(1) - direct field access
 *
 * @note Set during socket creation; immutable throughout lifetime.
 * @note Used internally for address validation, option setting, resolution
 * hints.
 *
 *  Usage Example
 *
 * @code{.c}
 * int domain = SocketBase_domain(base);
 * if (domain == AF_INET) {
 *     // IPv4-specific handling
 * } else if (domain == AF_INET6) {
 *     // IPv6-specific handling
 * }
 * @endcode
 *
 * @see getaddrinfo(3) for address resolution using domain
 * @see AF_* constants in <sys/socket.h>
 * @see SocketCommon_resolve_address() in SocketCommon.h for domain-aware
 * resolution
 */
extern int SocketBase_domain (SocketBase_T base);

/**
 * @brief Get cached remote address string representation.
 * @internal
 * @ingroup core_io
 *
 * Returns the pre-cached string representation of the remote peer's address,
 * formatted as numeric IP (IPv4/IPv6) or Unix domain path.
 *
 * @param[in] base Socket base instance
 * @return Pointer to arena-allocated string, or NULL if unset, unconnected, or
 * invalid
 *
 * @throws None
 * @threadsafe Conditional - acquire base->mutex if concurrent modification to
 * endpoints possible
 * @complexity O(1) - direct pointer return
 *
 *  Usage Example
 *
 * @code{.c}
 * const char *remote_ip = SocketBase_remoteaddr(base);
 * if (remote_ip) {
 *     SOCKET_LOG_INFO_MSG("Connected to %s", remote_ip);
 * } else {
 *     SOCKET_LOG_WARN_MSG("No remote address available");
 * }
 * @endcode
 *
 * @note String allocated in base.arena; valid until base disposal or
 * recaching.
 * @note Cached via SocketCommon_cache_endpoint() after connect/accept.
 * @note Format: "192.168.1.1" (IPv4), "[::1]" (IPv6), "/tmp/socket" (Unix)
 * @warning Do not free() the returned string - managed by arena.
 *
 * @see SocketBase_remoteport() for companion port getter
 * @see SocketCommon_cache_endpoint() for caching mechanism details
 * @see Socket_getpeeraddr() public wrapper in Socket.h
 */
static inline char *
SocketBase_remoteaddr (SocketBase_T base)
{
  return base ? base->remoteaddr : NULL;
}

/**
 * @brief Get remote peer port number.
 * @internal
 * @ingroup core_io
 * @param base Socket base instance.
 * @return Remote port (0 if unknown/unconnected).
 * @threadsafe Conditional - acquire base->mutex if concurrent access possible.
 * @see SocketBase_remoteaddr()
 * @see Socket_getpeerport() public wrapper.
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
 * @brief Set timeouts configuration in the socket base structure.
 * @internal
 * @ingroup core_io
 *
 * Copies timeout values from source to base.timeouts, applying to subsequent
 * operations like connect(), send/recv, DNS resolution. NULL source uses
 * global defaults. Safe no-op if base or source NULL.
 *
 *  Timeout Structure (SocketTimeouts_T)
 *
 * | Field | Purpose | Default |
 * |-------|---------|---------|
 * | connect_ms | Connection establishment | 30000 ms |
 * | send_ms | Send operations | 0 (no timeout) |
 * | recv_ms | Receive operations | 0 (no timeout) |
 * | dns_ms | DNS resolution | Global default |
 *
 * @param[in] base Socket base instance to update
 * @param[in] timeouts Source configuration to copy (NULL = global defaults)
 *
 * @throws None - defensive against NULL inputs
 * @threadsafe No - caller must lock base->mutex to prevent concurrent access
 * @complexity O(1) - structure copy
 *
 *  Usage Example
 *
 * @code{.c}
 * pthread_mutex_lock(&base->mutex);
 * SocketTimeouts_T custom = { .connect_ms = 5000, .send_ms = 10000 };
 * SocketBase_set_timeouts(base, &custom);
 * pthread_mutex_unlock(&base->mutex);
 *
 * // Or use defaults
 * SocketBase_set_timeouts(base, NULL);
 * @endcode
 *
 * @note Copies values; source ownership unchanged. Updates apply immediately
 * to new operations.
 * @note Global defaults via SocketCommon_timeouts_getdefaults(); modifiable
 * via SocketCommon_timeouts_setdefaults().
 * @note For socket-level SO_SNDTIMEO/SO_RCVTIMEO, use
 * SocketCommon_settimeout().
 * @warning Without mutex, race conditions may corrupt timeouts during
 * concurrent sets.
 *
 * @see SocketBase_timeouts() for direct pointer access (lock required)
 * @see SocketCommon_timeouts_getdefaults() for copying global defaults
 * @see SocketCommon_timeouts_setdefaults() for setting globals
 * @see SocketCommon_settimeout() for low-level socket option timeouts
 * @see core/SocketConfig.h for SocketTimeouts_T definition
 * @see docs/TIMEOUTS.md for timeout best practices
 */
extern void SocketBase_set_timeouts (SocketBase_T base,
                                     const SocketTimeouts_T *timeouts);

/* ... add more extern decls for getters/setters as needed */

/**
 * @brief Create a new socket file descriptor with error handling and CLOEXEC
 * setup.
 * @internal
 * @ingroup core_io
 *
 * Low-level wrapper around socket(2) system call that creates a new file
 * descriptor, sets FD_CLOEXEC flag, disables SIGPIPE generation
 * (platform-specific), and raises specified exception on failure. Used during
 * socket instance creation before base init.
 *
 *  Error Conditions
 *
 * | errno | Meaning | Retryable |
 * |-------|---------|-----------|
 * | EACCES | Permission denied | No |
 * | EMFILE | Per-process fd limit | Yes (after close) |
 * | ENFILE | System-wide fd limit | Yes (system resource) |
 * | EAFNOSUPPORT | Address family unsupported | No |
 * | ENOBUFS | No buffer space | Yes (transient) |
 *
 * @param[in] domain Address family (AF_INET, AF_INET6, AF_UNIX)
 * @param[in] type Socket type (SOCK_STREAM, SOCK_DGRAM)
 * @param[in] protocol Protocol (usually 0 for default)
 * @param[in] exc_type Exception type to raise on failure (e.g., Socket_Failed)
 * @return New non-negative file descriptor on success, -1 on error (raises
 * exc_type)
 *
 * @throws exc_type on socket(2) failure with formatted message including errno
 *
 * @threadsafe Yes - no shared state or globals modified
 * @complexity O(1) - single system call + flag setup
 *
 *  Usage Example
 *
 * @code{.c}
 * TRY {
 *     int fd = SocketCommon_create_fd(AF_INET, SOCK_STREAM, 0, Socket_Failed);
 *     SocketBase_T base = CALLOC(NULL, 1, sizeof(struct SocketBase_T));
 *     SocketCommon_init_base(base, fd, AF_INET, SOCK_STREAM, 0,
 * Socket_Failed);
 *     // Now embed base in subtype struct
 * } EXCEPT(Socket_Failed) {
 *     SOCKET_LOG_ERROR_MSG("Failed to create socket: %s",
 * Socket_GetLastError()); return -1; } END_TRY;
 * @endcode
 *
 * @note Automatically sets FD_CLOEXEC to prevent fd inheritance on execve(2).
 * @note Handles platform-specific SIGPIPE suppression (SO_NOSIGPIPE or
 * MSG_NOSIGNAL policy).
 * @note Caller responsible for closing fd on error paths before raising.
 * @warning Do not use directly in application code; internal library use only.
 *
 * @see socket(2) for underlying system call
 * @see SocketCommon_init_base() for initializing SocketBase_T with returned fd
 * @see SocketCommon_setcloexec_with_error() for explicit CLOEXEC handling
 * @see SocketCommon_disable_sigpipe() for SIGPIPE details
 * @see docs/SECURITY.md#file-descriptor-leaks for CLOEXEC importance
 */
extern int SocketCommon_create_fd (int domain, int type, int protocol,
                                   Except_T exc_type);

/**
 * @brief Initialize pre-allocated SocketBase_T with FD and parameters.
 * @internal
 * @ingroup core_io
 *
 * Performs full initialization of a pre-allocated base structure: sets fields,
 * creates per-socket arena, initializes mutex, sets CLOEXEC flag, disables
 * SIGPIPE, caches initial endpoints if possible, initializes timeouts and
 * metrics to defaults. Used when creating sockets from existing FDs (e.g.,
 * accept(2), dup(2), or raw socket()).
 *
 * @param[in,out] base Pre-allocated base structure (must be zeroed or from
 * CALLOC)
 * @param[in] fd File descriptor to associate (must be valid socket FD)
 * @param[in] domain Address family matching FD (AF_INET, etc.)
 * @param[in] type Socket type matching FD (SOCK_STREAM, etc.)
 * @param[in] protocol Protocol matching FD (usually 0)
 * @param[in] exc_type Exception type for any initialization failures
 *
 * @throws exc_type on failures: arena alloc, mutex init, fcntl CLOEXEC,
 * getsockname cache
 *
 * @threadsafe No - assumes exclusive access to base and FD
 * @complexity O(1) - fixed operations + potential getsockname(2)
 *
 *  Usage Example
 *
 * @code{.c}
 * TRY {
 *     int fd = accept(server_fd, NULL, 0);  // Or socket(), etc.
 *     if (fd >= 0) {
 *         SocketBase_T base = CALLOC(arena, 1, sizeof(*base));
 *         SocketCommon_init_base(base, fd, AF_INET, SOCK_STREAM, 0,
 * Socket_Failed);
 *         // Embed base in Socket_T or SocketDgram_T
 *         // Update endpoints post-accept via getsockname/getpeername
 *     }
 * } EXCEPT(Socket_Failed) {
 *     close(fd);  // Cleanup on error
 * } END_TRY;
 * @endcode
 *
 * @note Takes ownership of fd; closes on error paths via exception handling.
 * @note Arena created internally; all subsequent allocations use it.
 * @note Mutex initialized to PTHREAD_MUTEX_DEFAULT; recursive locks possible
 * but discouraged.
 * @note Endpoints cached if possible (getsockname success); otherwise lazy.
 * @warning base must not be used before init; post-init, follow lock protocol.
 * @note Alternative to SocketCommon_new_base() when FD pre-exists.
 *
 * @see SocketCommon_new_base() for allocation + init in one step
 * @see SocketCommon_create_fd() for creating FD prior to init
 * @see SocketCommon_setcloexec_with_error() internal CLOEXEC call
 * @see SocketCommon_update_local_endpoint() for post-bind endpoint refresh
 * @see docs/ERROR_HANDLING.md for TRY/EXCEPT patterns with FD cleanup
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
extern int SocketCommon_get_family (SocketBase_T base, bool raise_on_fail,
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
 * @note On BSD/macOS: sets SO_NOSIGPIPE=1; on Linux: uses MSG_NOSIGNAL in
 * send.
 * @note Library policy: No global signal handlers; handle per-operation or
 * opt.
 * @see send(2), MSG_NOSIGNAL
 */
extern void SocketCommon_disable_sigpipe (int fd);

/**
 * @brief Deep copy of addrinfo linked list (internal implementation).
 * @internal
 * @param src Source addrinfo chain (may be NULL).
 * @return Deep copy allocated with malloc (free with
 * SocketCommon_free_addrinfo).
 * @note Copies entire chain, including ai_addr and ai_canonname.
 * @note Used internally for resolve_address caching; public in SocketCommon.h.
 * @see SocketCommon_free_addrinfo()
 * @see getaddrinfo(3)
 */
extern struct addrinfo *
SocketCommon_copy_addrinfo (const struct addrinfo *src);

/* ============================================================================
 * Internal Low-Level Utility Functions
 * ============================================================================
 * Helper functions for hostname validation, IP detection, and string
 * conversion. Shared across SocketCommon-resolve.c and SocketCommon-utils.c
 * implementations. Prefixed 'socketcommon_' for internal namespace.
 *
 * @internal
 * @ingroup core_io
 */

/**
 * @brief Normalize and validate host string for safe resolution use.
 * @internal
 * @param host Input host (may be NULL, wildcard, or invalid).
 * @return Safe host string: NULL for wildcards/invalids, validated copy
 * otherwise.
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

/**
 * @brief Module Exception Forward Declarations
 * @internal
 * @ingroup core_io
 *
 * Forward declarations of module-specific exception types (Except_T) for use
 * in internal implementations. Enables consistent error raising across Socket,
 * SocketDgram, and common utilities without per-file definitions.
 *
 * These exceptions are also exposed publicly in SocketCommon.h for
 * application-level TRY/EXCEPT handling. Definitions provided in respective .c
 * source files.
 *
 *  Exception Usage Pattern
 *
 * @code{.c}
 * SOCKET_DECLARE_MODULE_EXCEPTION(SocketCommon);  // In .c file
 *
 * // Raising
 * SOCKET_RAISE_FMT(SocketCommon, SocketCommon_Failed, "resolve failed: %s",
 * gai_strerror(err));
 * @endcode
 *
 *  Category and Retryability
 *
 * All socket exceptions:
 * - **Category**: NETWORK (system calls) or APPLICATION (validation)
 * - **Retryable**: Use SocketError_is_retryable_errno(Socket_geterrno()) to
 * check
 * - **Details**: Available via Socket_GetLastError(), Socket_geterrno()
 *
 * @note Thread-safe: Yes (Except_T is value type, stack-based)
 * @see core/Except.h for TRY/EXCEPT/FINALLY/END_TRY macros and Except_T
 * details
 * @see SOCKET_DECLARE_MODULE_EXCEPTION() and SOCKET_RAISE_* macros in internal
 * headers
 * @see docs/ERROR_HANDLING.md for comprehensive exception patterns and best
 * practices
 * @see SocketError_categorize_errno() for automatic categorization
 */

/**
 * @brief Generic socket operation failure exception.
 * @internal
 * @ingroup core_io
 *
 * Raised for core socket operations failures: socket(2), bind(2), connect(2),
 * listen(2), accept(2), send/recv family, Unix domain ops, option setting.
 *
 *  Common Triggers
 * - System resource exhaustion (EMFILE, ENFILE, ENOBUFS)
 * - Permission issues (EACCES, EPERM)
 * - Address errors (EADDRINUSE, EADDRNOTAVAIL, EINVAL)
 * - Connection issues (ECONNREFUSED, ETIMEDOUT, ECONNRESET)
 *
 * Category: NETWORK
 * Retryable: Yes for transient errors (use SocketError_is_retryable_errno())
 *
 * @see Socket.h for TCP-specific details
 * @see SocketDgram.h for UDP details
 * @see Socket_geterrno() for underlying errno
 */
extern const Except_T Socket_Failed;

/**
 * @brief Datagram/UDP-specific operation failure exception.
 * @internal
 * @ingroup core_io
 *
 * Specific to UDP/SocketDgram operations: sendto(2)/recvfrom(2), multicast
 * join/leave, broadcast enable, TTL setting, connected UDP mode.
 *
 *  Common Triggers
 * - Multicast errors (invalid group, permission denied)
 * - Broadcast without SO_BROADCAST
 * - TTL/hop limit out of range
 * - Datagram too large (EMSGSIZE)
 *
 * Category: NETWORK
 * Retryable: Depends on errno - check SocketError_is_retryable_errno()
 *
 * @see SocketDgram.h for full UDP API documentation
 * @see SocketCommon_join_multicast() for multicast-specific errors
 */
extern const Except_T SocketDgram_Failed;

/**
 * @brief Shared utility function failure exception.
 * @internal
 * @ingroup core_io
 *
 * For errors in common utilities: address resolution (getaddrinfo),
 * hostname/port validation, iovec calculations/advances, option setting
 * helpers, endpoint caching.
 *
 *  Common Triggers
 * - DNS resolution timeouts/failures (gai errors)
 * - Invalid input (bad port, too-long hostname, iov overflow)
 * - Option setting failures (setsockopt EINVAL, ENOPROTOOPT)
 * - Memory allocation in helpers (via Arena_Failed chaining)
 *
 * Category: NETWORK or APPLICATION
 * Retryable: Yes for network transients, no for validation errors
 *
 * @see SocketCommon_resolve_address() for resolution errors
 * @see SocketCommon_validate_port() and validate_hostname() for input
 * validation
 * @see SocketCommon_calculate_total_iov_len() for iovec ops
 */
extern const Except_T SocketCommon_Failed;

/**
 * @brief Sanitize raw timeout value, applying library policy for valid range.
 * @internal
 * @ingroup core_io
 *
 * Clamps and normalizes timeout milliseconds to prevent invalid or overflow
 * values in socket operations. Library policy:
 * - Negative: Treated as 0 (no timeout/infinite)
 * - Zero: No timeout
 * - Positive huge (>INT_MAX): Clamped to INT_MAX
 * - Invalid input (e.g., NaN if float cast): -1 error
 *
 * Used defensively in all timeout setters (connect_ms, send_ms, etc.) to
 * ensure safe values before applying to base.timeouts or SO_*TIMEO options.
 *
 *  Input/Output Mapping
 *
 * | Input (ms) | Output (ms) | Behavior |
 * |------------|-------------|----------|
 * | < 0 | 0 | Infinite/no timeout |
 * | 0 | 0 | No timeout |
 * | 1..INT_MAX | unchanged | Valid timeout |
 * | > INT_MAX | INT_MAX | Clamped max |
 * | Invalid | -1 | Error (caller handles) |
 *
 * @param[in] timeout_ms Raw timeout value from config or user input
 * @return Sanitized timeout (>=0 valid, -1 error)
 *
 * @throws None - returns error code instead
 * @threadsafe Yes - pure function, no state
 * @complexity O(1) - simple comparisons and clamps
 *
 *  Usage Example
 *
 * @code{.c}
 * int safe_timeout = socketcommon_sanitize_timeout(user_config->connect_ms);
 * if (safe_timeout < 0) {
 *     SOCKET_LOG_WARN_MSG("Invalid timeout; using default");
 *     safe_timeout = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS;
 * }
 * base->timeouts.connect_ms = safe_timeout;
 * @endcode
 *
 * @note Prevents signed overflow in time calculations (e.g.,
 * SocketTimeout_deadline_ms).
 * @note Consistent policy across all timeout fields in SocketTimeouts_T.
 * @warning Callers must check return <0 and fallback to defaults.
 * @note Used internally by SocketBase_set_timeouts() and option setters.
 *
 * @see SocketTimeouts_T fields (connect_ms, send_ms, recv_ms, dns_ms)
 * @see SocketCommon_settimeout() for applying to SO_SNDTIMEO/SO_RCVTIMEO
 * @see core/SocketConfig.h for default timeout constants
 * @see docs/TIMEOUTS.md for timeout configuration guide
 */
extern int socketcommon_sanitize_timeout (int timeout_ms);

#endif /* SOCKETCOMMON_PRIVATE_INCLUDED */
