#ifndef SOCKETPOLL_BACKEND_INCLUDED
#define SOCKETPOLL_BACKEND_INCLUDED

/**
 * @file SocketPoll_backend.h
 * @brief Abstract interface for platform-specific polling implementations.
 * @ingroup event_system
 *
 * Defines the internal backend abstraction layer that all polling implementations
 * must conform to. Not part of the public API - for backend implementors only.
 *
 * Supported Backend Implementations:
 * - epoll (Linux): High-performance edge-triggered I/O multiplexing
 * - kqueue (BSD/macOS): High-performance event notification system
 * - poll (POSIX): Portable level-triggered fallback for other systems
 *
 * Backend Selection Strategy:
 * - Compile-time selection via CMake based on platform capabilities
 * - Linux kernel 2.6.8+: epoll (optimal performance, edge-triggered)
 * - BSD/macOS systems: kqueue (optimal performance, edge-triggered)
 * - Other POSIX-compliant systems: poll (portable, level-triggered)
 *
 * Interface Contract:
 * - All backends provide identical API for SocketPoll operations
 * - Memory management through Arena_T for efficient cleanup
 * - Error reporting via errno (POSIX standard)
 * - Event translation to SocketPoll_Events format
 * - Thread safety handled at SocketPoll layer
 *
 * Implementation Notes:
 * - Backend implementations in src/poll/ directory
 * - Automatic selection via build system platform detection
 * - Each backend provides identical behavior with platform-optimized performance
 *
 * @see PollBackend_T for backend type definition.
 * @see backend_new() for backend instance creation.
 * @see backend_add() for socket registration interface.
 * @see backend_wait() for event waiting interface.
 * @see @ref event_system for complete polling system documentation.
 * @see @ref foundation for arena-based memory management patterns.
 * @see @ref core_io for socket integration requirements.
 * @see src/poll/ for backend source implementations (epoll, kqueue, poll).
 * @see docs/ASYNC_IO.md for event system usage in async contexts.
 */

#include "core/Arena.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

/**
 * @brief Opaque type for platform-specific polling backend instances.
 * @ingroup event_system
 *
 * Represents a backend-specific polling implementation that abstracts
 * platform differences between epoll, kqueue, and poll. Each backend
 * provides the same interface while using the most efficient system
 * calls available on the target platform.
 *
 * Memory Management: Backend instances are allocated from Arena_T
 * for efficient cleanup when the poll instance is destroyed.
 *
 * @see backend_new() for backend creation.
 * @see backend_free() for backend cleanup.
 * @see backend_add() for socket registration.
 * @see backend_wait() for event waiting.
 */
typedef struct PollBackend_T *PollBackend_T;

/**
 * @brief Validate maxevents parameter with overflow protection.
 * @ingroup event_system
 *
 * Common validation macro used by all backend implementations to prevent
 * integer overflow attacks and ensure safe memory allocation. Validates
 * that maxevents is positive and won't cause overflow when calculating
 * event array sizes.
 *
 * Validation Logic:
 * - maxevents must be > 0 (EINVAL if not)
 * - maxevents * sizeof(event_type) must not exceed SIZE_MAX (EOVERFLOW if not)
 *
 * Error Handling: Sets errno and returns NULL from calling function
 * on validation failure, allowing consistent error propagation.
 *
 * @param maxevents Maximum events to validate (must be > 0).
 * @param event_type Event structure type for sizeof calculation.
 * @return Returns NULL from calling function on validation failure.
 * @note Sets errno to EINVAL for non-positive maxevents.
 * @note Sets errno to EOVERFLOW for potential integer overflow.
 * @note Used by all backend_new() implementations.
 * @see backend_new() for usage in backend creation functions.
 * @see SIZE_MAX for overflow protection limits.
 * @see Arena_alloc() for safe allocation that respects these limits.
 * @see SocketPoll_new() for public interface that validates parameters.
 */
#ifndef VALIDATE_MAXEVENTS
#define VALIDATE_MAXEVENTS(maxevents, event_type)                             \
  do                                                                          \
    {                                                                         \
      if ((size_t)(maxevents) <= 0)                                           \
        {                                                                     \
          errno = EINVAL;                                                     \
          return NULL;                                                        \
        }                                                                     \
      if ((size_t)(maxevents) > SIZE_MAX / sizeof (event_type))               \
        {                                                                     \
          errno = EOVERFLOW;                                                  \
          return NULL;                                                        \
        }                                                                     \
    }                                                                         \
  while (0)
#endif

/* ==================== Common Backend Macros ==================== */

/**
 * @brief Validate file descriptor parameter for backend operations.
 * @ingroup event_system
 *
 * Common validation macro used by all backend implementations to ensure
 * file descriptors are valid before performing backend operations. Provides
 * defense-in-depth validation to catch invalid descriptors early and
 * prevent undefined behavior in system calls.
 *
 * Validation Logic: File descriptor must be >= 0 (negative values invalid).
 *
 * Error Handling: Sets errno to EBADF and returns -1 from calling function
 * on validation failure, ensuring consistent error reporting.
 *
 * @param fd File descriptor to validate (must be >= 0).
 * @return Returns -1 from calling function on validation failure.
 * @note Sets errno to EBADF for negative file descriptors.
 * @note Used by backend_add(), backend_mod(), backend_del() implementations.
 * @see backend_add() for usage in socket registration operations.
 * @see backend_mod() for usage in event modification operations.
 * @see backend_del() for usage in socket removal operations.
 * @see Socket_fd() for obtaining valid file descriptors from Socket_T.
 * @see SocketPoll_add() for public interface that validates sockets.
 */
#define VALIDATE_FD(fd)                                                       \
  do                                                                          \
    {                                                                         \
      if ((fd) < 0)                                                           \
        {                                                                     \
          errno = EBADF;                                                      \
          return -1;                                                          \
        }                                                                     \
    }                                                                         \
  while (0)

/* ==================== Backend Interface ==================== */

/**
 * @brief Backend Interface - Abstract Polling Operations.
 * @ingroup event_system
 *
 * Defines the complete interface that all polling backend implementations
 * must provide for consistent SocketPoll operations. Each backend abstracts
 * a platform-specific polling mechanism while providing identical behavior.
 *
 * Backend Selection and Priority:
 * - Linux kernel 2.6.8+: epoll (optimal performance, edge-triggered)
 * - BSD/macOS systems: kqueue (optimal performance, edge-triggered)
 * - POSIX-compliant systems: poll (portable fallback, level-triggered)
 * - Selection occurs at compile-time via Makefile platform detection
 *
 * Interface Contract and Guarantees:
 * - Return Value: -1 on error (errno set) or 0 on success
 * - Memory Management: All allocations use provided Arena_T
 * - Thread Safety: Handled at SocketPoll layer (backends need not be thread-safe)
 * - Event Format: All backends translate to SocketPoll_Events bitmask
 * - Error Handling: POSIX errno values for consistent error reporting
 * - Resource Cleanup: backend_free() handles complete cleanup
 *
 * Implementation Requirements:
 * - Validate parameters using VALIDATE_FD and VALIDATE_MAXEVENTS macros
 * - Handle EINTR gracefully (automatic restart not required)
 * - Support all SocketPoll_Events (READ, WRITE, ERROR, HANGUP)
 * - Provide backend_name() for debugging and logging
 *
 * @see backend_new() for backend instance creation.
 * @see backend_add() for socket registration interface.
 * @see backend_wait() for event waiting and retrieval.
 * @see backend_get_event() for event details access.
 * @see PollBackend_T for backend instance type.
 * @see SocketPoll_Events for standardized event type definitions.
 * @see VALIDATE_FD for parameter validation requirements.
 * @see VALIDATE_MAXEVENTS for overflow protection requirements.
 */

/**
 * @brief Create new backend instance.
 * @ingroup event_system
 * @param arena Arena for memory allocation (backend and events allocated here).
 * @param maxevents Maximum events to return per wait.
 * @return Backend instance or NULL on failure (errno set).
 * @note On failure, arena allocations are leaked but freed by caller arena dispose.
 * @note Validates maxevents parameter for overflow protection.
 * @see VALIDATE_MAXEVENTS for parameter validation.
 * @see Arena_T for memory management.
 * @see backend_free() for cleanup.
 * @see backend_add() for socket registration.
 * @see backend_wait() for event waiting.
 */
extern PollBackend_T backend_new (Arena_T arena, int maxevents);

/**
 * @brief Close backend resources.
 * @ingroup event_system
 * @param backend Backend instance (fd closed, memory freed by arena dispose).
 * @note Only closes the backend file descriptor; memory allocations owned by arena.
 * @note Safe to call multiple times (idempotent).
 * @see Arena_dispose() for complete cleanup including backend memory.
 * @see backend_new() for creation.
 */
extern void backend_free (PollBackend_T backend);

/**
 * @brief Add socket to poll set.
 * @ingroup event_system
 * @param backend Backend instance.
 * @param fd File descriptor to monitor.
 * @param events Events to monitor (bitmask of POLL_READ | POLL_WRITE).
 * @return 0 on success, -1 on failure (sets errno).
 * @note Validates fd parameter before backend operations.
 * @note Socket automatically set to non-blocking mode by SocketPoll.
 * @see VALIDATE_FD for file descriptor validation.
 * @see SocketPoll_Events for event type definitions.
 * @see backend_mod() for modifying events.
 * @see backend_del() for removal.
 * @see backend_wait() for event waiting.
 */
extern int backend_add (PollBackend_T backend, int fd, unsigned events);

/**
 * @brief Modify monitored events.
 * @ingroup event_system
 * @param backend Backend instance.
 * @param fd File descriptor to modify.
 * @param events New events to monitor (bitmask of POLL_READ | POLL_WRITE).
 * @return 0 on success, -1 on failure (sets errno).
 * @note Validates fd parameter before backend operations.
 * @note More efficient than remove/add sequence for backends that support it.
 * @see VALIDATE_FD for file descriptor validation.
 * @see SocketPoll_Events for event type definitions.
 * @see backend_add() for initial registration.
 * @see backend_del() for removal.
 */
extern int backend_mod (PollBackend_T backend, int fd, unsigned events);

/**
 * @brief Remove socket from poll set.
 * @ingroup event_system
 * @param backend Backend instance.
 * @param fd File descriptor to remove.
 * @return 0 on success, -1 on failure (sets errno).
 * @note Should succeed silently if fd not in set (idempotent operation).
 * @note Validates fd parameter before backend operations.
 * @see VALIDATE_FD for file descriptor validation.
 * @see backend_add() for registration.
 * @see backend_mod() for modification.
 */
extern int backend_del (PollBackend_T backend, int fd);

/**
 * @brief Wait for events.
 * @ingroup event_system
 * @param backend Backend instance (modifies internal events array for output).
 * @param timeout_ms Timeout in milliseconds (-1 for infinite, 0 for immediate).
 * @return Number of events ready (>= 0), or -1 on error (sets errno).
 * @note Returns 0 on timeout, EINTR (signal interrupt), or immediate return.
 * @note Internal event array updated for backend_get_event() retrieval.
 * @note Thread-safe: Assumes single-threaded access via SocketPoll mutex.
 * @see backend_get_event() for retrieving event details.
 * @see backend_add() for socket registration.
 * @see SocketPoll_wait() for public interface that calls this.
 */
extern int backend_wait (PollBackend_T backend, int timeout_ms);

/**
 * @brief Get event details for index.
 * @ingroup event_system
 * @param backend Backend instance (const - read-only access to events array).
 * @param index Event index (0 to count-1 from backend_wait return value).
 * @param fd_out Output parameter - file descriptor that triggered event.
 * @param events_out Output parameter - events that occurred (POLL_READ | POLL_WRITE).
 * @return 0 on success, -1 on invalid index.
 * @threadsafe Yes - Read-only access to backend's internal event array.
 * @note Called repeatedly by SocketPoll to translate backend events to SocketEvent_T.
 * @note Used in event translation pipeline: fd -> events -> SocketEvent_T.
 * @see backend_wait() for event waiting that populates the array.
 * @see SocketPoll_Events for event type definitions.
 * @see SocketEvent_T for translated event structure.
 * @see SocketPoll_wait() for complete event processing pipeline.
 */
extern int backend_get_event (const PollBackend_T backend, int index,
                              int *fd_out, unsigned *events_out);

/**
 * @brief Get human-readable backend name for debugging and logging.
 * @ingroup event_system
 * @return Static string identifying the backend ("epoll", "kqueue", or "poll").
 * @note Returned string is compile-time constant and safe for repeated calls.
 * @note Useful for logging backend-specific behavior and performance characteristics.
 * @note Helps identify active backend for platform-specific issue diagnosis.
 * @note Never NULL - always returns valid string for current backend.
 * @see backend_new() for compile-time backend selection logic.
 * @see SocketPoll_new() for backend initialization during poll creation.
 */
extern const char *backend_name (void);

#endif /* SOCKETPOLL_BACKEND_INCLUDED */
