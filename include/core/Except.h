/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef EXCEPT_INCLUDED
#define EXCEPT_INCLUDED

#include <setjmp.h>

/**
 * @file Except.h
 * @ingroup foundation
 * @brief Structured exception handling for C with TRY/EXCEPT/FINALLY blocks.
 *
 * This header implements a comprehensive exception handling system for C
 * programs, providing try/catch/finally semantics using setjmp/longjmp under
 * the hood. Designed for robust error management in networked applications,
 * with thread-local stacks to support concurrent operations without
 * synchronization overhead.
 *
 * Key capabilities:
 * - Hierarchical named exceptions with descriptive reasons
 * - Automatic propagation and specific catching
 * - Guaranteed cleanup via FINALLY on all paths
 * - Integration with assert() for debugging
 * - Safe early returns and nesting support
 *
 * ## Architecture Overview
 *
 * ```
 * Application Code
 *     |
 *   TRY { ... RAISE(e) ... }
 *     |     (setjmp + stack push)
 *   longjmp() --> EXCEPT(e) / ELSE / FINALLY
 *     |             (match + flag update)
 *   END_TRY (pop + re-raise if unhandled)
 *     |
 * Outer Handler or Termination
 * ```
 *
 * Thread-local stack (Except_stack) holds frames with jmp_buf for unwinding.
 * Exceptions (Except_T) carry type and reason for dispatch and diagnostics.
 *
 * ## Features
 *
 * | Feature | Description |
 * |---------|-------------|
 * | Structured Blocks | TRY/EXCEPT/ELSE/FINALLY/END_TRY for control flow |
 * | Exception Types | Named const Except_T instances for type-safe catching |
 * | Propagation | RERAISE for chaining handlers; automatic via END_TRY |
 * | Cleanup | FINALLY executes always; RETURN cleans stack |
 * | Thread Safety | Independent per-thread stacks; no locks needed |
 * | Debugging | Captures file/line; integrates with assert() |
 *
 * ## Platform Requirements
 *
 * - Standard C11 with <setjmp.h> support
 * - Thread-local storage (__thread or equivalent)
 * - POSIX threads for multi-threading (tested on Linux/macOS/Windows)
 * - Compiler support for volatile and GNU extensions (via CMake)
 * - Avoid in signal handlers or non-async-signal-safe contexts
 *
 * ## Basic Usage Example
 *
 * @code{.c}
 * #include "core/Except.h"
 * extern const Except_T ExampleError;  // Defined elsewhere
 *
 * void example_function() {
 *   TRY {
 *     // Protected code - may raise exceptions
 *     volatile int status = risky_operation();
 *     if (status != 0) {
 *       RAISE(ExampleError);
 *     }
 *     // Success path
 *   } EXCEPT(ExampleError) {
 *     // Specific error handling
 *     printf("Handled error: %s\n", Except_frame.exception->reason);
 *   } ELSE {
 *     // Unexpected errors
 *     printf("Unexpected: %s at %s:%d\n", Except_frame.exception->reason,
 *            Except_frame.file, Except_frame.line);
 *     RERAISE;  // Propagate further
 *   } FINALLY {
 *     // Cleanup always runs
 *     cleanup_resources();
 *   } END_TRY;
 * }
 * @endcode
 *
 * ## Advanced Usage: Custom Exception and Nesting
 *
 * @code{.c}
 * // Define custom exception
 * const Except_T CustomError = { &Assert_Failed, "Custom error occurred" };
 *
 * void nested_example() {
 *   TRY {  // Outer
 *     outer_setup();
 *     TRY {  // Inner
 *       inner_op();  // May raise CustomError
 *     } EXCEPT(CustomError) {
 *       handle_inner();
 *       RERAISE;  // To outer
 *     } FINALLY {
 *       inner_cleanup();
 *     } END_TRY;
 *   } EXCEPT(CustomError) {
 *     // Outer handling
 *     outer_recovery();
 *   } FINALLY {
 *     outer_cleanup();
 *   } END_TRY;
 * }
 * @endcode
 *
 * @note Use volatile for variables crossing exception boundaries to avoid
 * optimization issues.
 * @warning setjmp/longjmp not portable to all platforms; tested on major
 * OS/compilers.
 * @warning In production, enable runtime checks (avoid -DNDEBUG); assertions
 * optional.
 * @warning Deep nesting increases stack usage; monitor in threaded
 * environments.
 * @complexity Macro expansion O(1); runtime depends on nesting depth.
 *
 * @see Except_T for exception payload structure.
 * @see Except_Frame for internal stack frames.
 * @see Assert_Failed base for assertion errors.
 * @see @ref foundation for memory/error foundations this builds on.
 * @see @ref core_io for example module using exceptions (Socket operations).
 * @see docs/ERROR_HANDLING.md for full guide, custom exceptions, volatile
 * rules, and threading.
 * @see docs/SECURITY.md for security implications in networked code.
 */

/**
 * @brief Exception structure for structured error handling.
 * @ingroup foundation
 *
 * This value type (copyable struct, not opaque) encapsulates an exception
 * instance with a type identifier (for matching in handlers) and a
 * human-readable reason string. Serves as the payload for all raised
 * exceptions in the system, enabling type-safe dispatch via pointer comparison
 * in EXCEPT blocks.
 *
 * Key characteristics:
 * - Immutable after creation (const members)
 * - Hierarchical via type chaining (e.type points to base or self)
 * - Thread-safe for reading/copying (no internal state)
 * - Used in Except_frame.exception for handler access
 * - Module-specific exceptions derive conceptually from Assert_Failed or
 * custom bases
 *
 * Definition pattern for modules:
 *   extern const Except_T Module_Failed;  // In .h
 *   const Except_T Module_Failed = { &BaseException, "Module-specific failure
 * reason" };  // In .c
 *
 * In handlers, access via Except_frame.exception->reason for details, and
 * compare type.
 *
 * ## Fields
 *
 * | Field | Type | Description |
 * |-------|------|-------------|
 * | type | const Except_T * | Pointer to exception type (self or base for
 * hierarchy matching) | | reason | const char * | Null-terminated string
 * describing the error (compile-time constant typically) |
 *
 * @threadsafe Yes - immutable value type; safe to copy and read from any
 * thread.
 *
 * ## Usage Example: Defining and Using Module Exception
 *
 * @code{.c}
 * // In module.h
 * extern const Except_T Socket_Failed;
 *
 * // In module.c
 * #include "core/Except.h"
 * const Except_T Socket_Failed = {
 *   .type = &Assert_Failed,  // Or custom base
 *   .reason = "Socket operation failed (check errno)"
 * };
 *
 * // Raising
 * void socket_connect(Socket_T s, ...) {
 *   TRY {
 *     // ...
 *     if (sys_call_fails) {
 *       RAISE(Socket_Failed);
 *     }
 *   } END_TRY;
 * }
 *
 * // Handling
 * TRY {
 *   connect_socket(...);
 * } EXCEPT(Socket_Failed) {
 *   const Except_T *ex = Except_frame.exception;
 *   fprintf(stderr, "Socket error: %s (type: %p)\n", ex->reason, ex->type);
 * } END_TRY;
 * @endcode
 *
 * @note Define exceptions as file-scope const for efficiency and linker dedup.
 * @warning Never modify fields after definition; treat as immutable.
 * @warning Reason strings should be static/constant to avoid lifetime issues.
 * @complexity O(1) - simple struct access.
 *
 * @see Assert_Failed for base assertion exception.
 * @see Except_frame.exception for runtime access in handlers.
 * @see RAISE for raising instances.
 * @see EXCEPT for type-based catching via pointer match.
 * @see docs/ERROR_HANDLING.md for defining custom exceptions and hierarchies.
 * @see @ref foundation for related infrastructure.
 */
typedef struct Except_T
{
  const struct Except_T *type; /**< Exception type identifier */
  const char *reason;          /**< Human-readable error description */
} Except_T;

/**
 * @brief Exception frame for TRY/EXCEPT/FINALLY blocks.
 * @ingroup foundation
 *
 * Internal opaque structure (forward-declared for typedef) that holds the
 * state for one level of exception handling context. Pushed onto thread-local
 * Except_stack by TRY macro, capturing setjmp() buffer for non-local jumps,
 * exception details, and metadata for debugging and propagation.
 *
 * Implementation details (for maintainers):
 * - Linked list via prev pointer for stack unwinding
 * - jmp_buf env stores register state and return address for longjmp()
 * - Stores raised exception info for handlers (EXCEPT/ELSE access via
 * Except_frame)
 * - File/line captured at raise time for precise error location
 * - Managed automatically by macros; manual access risks corruption
 *
 * Lifecycle:
 * - Created in TRY: allocate locals, setjmp(), push to stack
 * - Updated on RAISE: set exception/file/line
 * - Popped on normal exit, RETURN, or after handling
 * - Reused in RERAISE for propagation
 *
 * ## Internal Fields (Do Not Use Directly)
 *
 * | Field | Type | Purpose |
 * |-------|------|---------|
 * | prev | Except_Frame * | Link to previous (outer) frame in stack |
 * | env | jmp_buf | setjmp/longjmp buffer for control transfer |
 * | file | const char * | Source file of exception raise (for diagnostics) |
 * | line | int | Source line of exception raise |
 * | exception | const Except_T * | Pointer to raised exception details |
 *
 * @note Internal implementation detail - users interact via macros only.
 * @note sizeof(Except_Frame) includes jmp_buf (platform-dependent size ~200
 * bytes).
 * @warning Direct manipulation can corrupt stack or cause crashes; use macros.
 * @threadsafe Internal - accessed only within thread's context by macros.
 *
 * ## Example Internal Flow (for Understanding)
 *
 * @code{.c}
 * // Simplified macro expansion insight
 * // TRY expands to:
 * Except_Frame frame;  // Local frame
 * frame.prev = Except_stack;
 * Except_stack = &frame;
 * Except_flag = setjmp(frame.env);  // 0 if normal, non-zero on longjmp
 * if (Except_flag == 0) {  // Enter protected code
 *   // User code here
 * }
 * // EXCEPT/ELSE/FINALLY handle jumps to here
 * // END_TRY pops and checks for re-raise
 * @endcode
 *
 * @warning jmp_buf size and portability vary; avoid embedding in user structs.
 * @complexity N/A - runtime structure.
 *
 * @see Except_stack for the stack head pointer.
 * @see TRY for frame creation and push.
 * @see END_TRY for frame pop and cleanup.
 * @see RAISE/RERAISE for updating frame exception data.
 * @see docs/ERROR_HANDLING.md for advanced macro expansion and internal
 * mechanics.
 */
typedef struct Except_Frame Except_Frame;
struct Except_Frame
{
  Except_Frame *prev; /**< Previous frame in exception stack */
  jmp_buf env;        /**< setjmp/longjmp context for non-local control flow */
  const char *file;   /**< Source file where exception was raised */
  int line;           /**< Source line where exception was raised */
  const Except_T *exception; /**< Exception that was raised */
};

/**
 * @brief Exception handling states for TRY/EXCEPT/FINALLY blocks.
 * @ingroup foundation
 *
 * Internal enumeration tracking the phase of exception processing within a TRY
 * construct. Managed via local volatile Except_flag variable in macro
 * expansion. Determines control flow: entering protected code, handling raised
 * exceptions, post-handling cleanup, or finalization.
 *
 * State transitions:
 * - Except_entered (0): Initial setjmp() returns 0, enter TRY body
 * - Except_raised (1): longjmp() returns non-zero, check handlers
 * - Except_handled (2): Matched EXCEPT/ELSE, mark handled
 * - Except_finalized (3): FINALLY executed or normal path finalized
 *
 * Used internally by macros for conditional execution and cleanup decisions.
 * Values are small integers for efficient flag comparison.
 *
 * ## State Values
 *
 * | Value | Name | Description | Triggered By |
 * |-------|------|-------------|--------------|
 * | 0 | Except_entered | TRY block entered successfully, no exception yet |
 * setjmp() normal return | | 1 | Except_raised | Exception raised, dispatch to
 * handlers | longjmp() from RAISE/RERAISE | | 2 | Except_handled | Exception
 * caught by EXCEPT/ELSE | Handler match in macros | | 3 | Except_finalized |
 * FINALLY or block exit processed | FINALLY exec or normal END_TRY |
 *
 * @note Internal to macro implementation; users do not interact directly.
 * @warning Values are hardcoded; changes require macro updates.
 * @threadsafe Implicit - local volatile flag per TRY block.
 *
 * @code{.c}
 * // Example transition in macro (simplified)
 * Except_flag = setjmp(env);  // 0 -> entered
 * if (Except_flag == 0) {  // TRY body
 *   // ...
 * } else if (match_except) {  // raised -> handled
 *   Except_flag = Except_handled;
 *   // Handler code
 * }
 * // FINALLY checks flag for finalization
 * @endcode
 *
 * @see TRY macro expansion using Except_flag.
 * @see EXCEPT/ELSE setting to Except_handled.
 * @see FINALLY using Except_entered for conditional exec.
 * @see docs/ERROR_HANDLING.md for macro internals and state machine.
 */
enum
{
  Except_entered = 0, /**< TRY block entered, no exception raised */
  Except_raised,      /**< Exception raised, executing EXCEPT or FINALLY */
  Except_handled,     /**< Exception handled, executing FINALLY or END_TRY */
  Except_finalized    /**< FINALLY block executed, cleaning up */
};

/**
 * @brief Thread-local exception stack for TRY/EXCEPT/FINALLY blocks.
 * @ingroup foundation
 *
 * External thread-local variable serving as the head of a linked list of
 * Except_Frame structures, representing the stack of active exception handling
 * contexts for the current thread. Manipulated exclusively by exception macros
 * (TRY pushes, END_TRY pops).
 *
 * Implementation:
 * - Declared with __thread (GCC/Clang) or __declspec(thread) (MSVC) for TLS
 * - Points to top-most (innermost) frame; NULL when no active TRY blocks
 * - Stack grows downward via frame->prev links
 * - Unwinding via longjmp() doesn't require explicit pops (handled by macros)
 *
 * Access patterns (internal):
 * - TRY: Except_stack = new_frame; new_frame->prev = old_stack
 * - RAISE/END_TRY: Traverse via prev for propagation if needed
 * - RETURN: Manual pop via assignment to prev
 *
 * Threading model:
 * - Per-thread isolation: no synchronization needed between threads
 * - Safe for concurrent TRY blocks in different threads
 * - Not shared; multi-threaded apps have independent stacks
 *
 * Debugging/Inspection:
 * - Can query depth or top frame for diagnostics (advanced, not recommended)
 * - Stack overflow possible with excessive nesting (monitor via valgrind/ASan)
 *
 * ## Usage Notes (Indirect via Macros)
 *
 * @code{.c}
 * // No direct access; example macro usage affecting stack
 * void threaded_example() {
 *   TRY {  // Pushes frame to this thread's Except_stack
 *     shared_resource_op();  // Other thread unaffected
 *   } END_TRY;  // Pops frame
 * }
 *
 * // In multi-threaded context
 * // Thread A: own stack with frames
 * // Thread B: independent stack
 * @endcode
 *
 * @note Users never access directly; macros ensure correctness.
 * @note Initial value NULL; indicates no active contexts.
 * @warning Direct modification corrupts handling; undefined behavior.
 * @threadsafe Yes - TLS ensures isolation; read/write safe within thread.
 *
 * @see Except_Frame for node structure in the stack.
 * @see TRY for push operation.
 * @see END_TRY/RETURN for pop operations.
 * @see RAISE for frame update during raise.
 * @see docs/ERROR_HANDLING.md for threading considerations and stack
 * management.
 */
#ifdef _WIN32
extern __declspec (thread) Except_Frame *Except_stack;
#else
extern __thread Except_Frame *Except_stack;
#endif

/**
 * @brief Standard exception raised by failed assertions.
 * @ingroup foundation
 *
 * This base-level exception serves as the root for assertion failures and
 * programming errors detected via assert() or manual RAISE(Assert_Failed).
 * Indicates invariant violations, invalid states, or bugs that should never
 * occur in production code under correct usage.
 *
 * Purpose and usage:
 * - Base type for module-specific assertion exceptions (e.type =
 * &Assert_Failed)
 * - Triggered automatically by standard assert() integration
 * - In release builds (-DNDEBUG), assert() may be no-op, but manual raises
 * persist
 * - Handlers can catch Assert_Failed for generic bug reporting/dumps
 *
 * In the library, used for:
 * - Precondition/postcondition checks
 * - Internal consistency assertions
 * - API contract violations
 *
 * Custom assertions:
 *   assert(condition && "Detailed failure message");  // Auto-raises with
 * reason Or manual: RAISE(Assert_Failed); for no message
 *
 * ## Hierarchy Example
 *
 * @code{.c}
 * // Base
 * extern const Except_T Assert_Failed;
 *
 * // Module derives (conceptually)
 * const Except_T Arena_AssertFailed = { &Assert_Failed, "Arena internal
 * assertion failed" };
 *
 * // In code
 * assert(arena != NULL && "Arena must be valid");
 * // If fails, raises Assert_Failed with runtime-generated reason including
 * message
 * @endcode
 *
 * @note Compile with asserts enabled in debug; consider runtime checks in
 * production.
 * @note assert() reason includes C string literal for diagnostics.
 * @warning Not for recoverable runtime errors; use domain-specific exceptions.
 * @threadsafe Yes - const global variable.
 *
 * @see assert() standard macro integration.
 * @see RAISE(Assert_Failed) for manual assertion-like raises.
 * @see Module-specific exceptions deriving from this base.
 * @see docs/ERROR_HANDLING.md for assertion strategies vs runtime exceptions.
 * @see @ref foundation for error handling infrastructure.
 */
extern const Except_T Assert_Failed;

/**
 * @brief Raise an exception (internal function - use RAISE() macro instead).
 * @ingroup foundation
 *
 * This internal function stores the provided exception information in the
 * current thread's exception frame and performs a non-local jump using
 * longjmp() to unwind the call stack to the nearest enclosing TRY block's
 * setjmp() buffer. It enables structured exception handling in C without
 * traditional unwinding.
 *
 * Important behavior and edge cases:
 * - Updates the top Except_frame with exception, file, and line information
 * - Traverses the thread-local Except_stack to find the target frame
 * - If no TRY frame exists on the stack, results in undefined behavior (likely
 * crash)
 * - Exception propagation continues up the call stack if not handled
 * - Compatible with volatile variables to prevent optimizer issues
 *
 * Typical internal usage within RAISE() and RERAISE macros for error
 * conditions after failed operations, validations, or system calls.
 *
 * @param[in] e Exception to raise (must not be NULL; typically a const
 * Except_T variable).
 * @param[in] file Source file name where the exception occurred (from
 * __FILE__).
 * @param[in] line Source line number where the exception occurred (from
 * __LINE__).
 *
 * @return This function does not return normally; control is transferred via
 * longjmp().
 *
 * @throws N/A - This function implements the raising mechanism itself.
 *
 * @threadsafe No - modifies thread-local Except_stack and Except_frame.
 *
 * ## Usage Example (via RAISE macro - preferred)
 *
 * @code{.c}
 * extern const Except_T Socket_Failed;
 *
 * TRY {
 *   // Potentially failing operation
 *   if (connect(fd, addr, addrlen) < 0) {
 *     RAISE(Socket_Failed);  // Expands to Except_raise(&Socket_Failed,
 * __FILE__, __LINE__)
 *   }
 * } EXCEPT(Socket_Failed) {
 *   // Handle specific exception
 *   fprintf(stderr, "Connection failed: %s\n",
 * Except_frame.exception->reason); } FINALLY {
 *   // Cleanup resources
 * } END_TRY;
 * @endcode
 *
 * ## Direct Call (not recommended)
 *
 * @code{.c}
 * if (error) {
 *   Except_raise(&MyException, __FILE__, __LINE__);
 * }
 * @endcode
 *
 * @note Always prefer RAISE() macro to automatically capture file and line
 * info.
 * @warning longjmp() bypasses destructors/cleanup; use FINALLY blocks for
 * resource management.
 * @warning Caller must ensure a valid TRY frame exists on the stack.
 * @complexity O(d) where d is depth of nested TRY blocks (stack traversal).
 *
 * @see RAISE() macro for convenient user-level exception raising with source
 * location.
 * @see RERAISE for propagating caught exceptions.
 * @see TRY macro for establishing exception handling context.
 * @see Except_T for exception structure.
 * @see docs/ERROR_HANDLING.md for best practices and patterns.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
extern _Noreturn void Except_raise (const Except_T *e, const char *file,
                                    int line);
#elif defined(__GNUC__) || defined(__clang__)
extern void Except_raise (const Except_T *e, const char *file, int line)
    __attribute__ ((noreturn));
#elif defined(_MSC_VER)
extern __declspec (noreturn) void Except_raise (const Except_T *e,
                                                const char *file, int line);
#else
extern void Except_raise (const Except_T *e, const char *file, int line);
#endif

/**
 * @brief Raise an exception with current file and line information.
 * @ingroup foundation
 *
 * This macro raises the specified exception variable, automatically capturing
 * the current source file (__FILE__) and line number (__LINE__) for debugging.
 * It expands to a call to Except_raise(&(e), __FILE__, __LINE__), transferring
 * control via longjmp() to the nearest enclosing TRY block's exception
 * handler.
 *
 * Use this macro in error conditions to provide structured error handling.
 * The exception will propagate up the call stack until caught or the program
 * terminates.
 *
 * Edge cases:
 * - If called outside a TRY block, leads to undefined behavior (stack
 * corruption possible)
 * - e must be an lvalue (variable); expressions like &SomeException won't work
 * correctly
 * - Thread-local; each thread's exception stack is independent
 *
 * @param[in] e Exception variable to raise (e.g., Socket_Failed,
 * Arena_Failed). Must be a variable name, not an expression or temporary.
 *
 * @return Does not return normally; control transfers to exception handler via
 * longjmp().
 *
 * @throws The specified exception e (propagates via non-local jump).
 *
 * @threadsafe No - modifies thread-local exception stack.
 *
 * ## Usage Example
 *
 * @code{.c}
 * #include "core/Except.h"
 * extern const Except_T MyModule_Failed;
 *
 * void risky_operation() {
 *   TRY {
 *     // Simulate error condition
 *     if (some_condition_fails()) {
 *       RAISE(MyModule_Failed);  // Raises with current file/line
 *     }
 *     // Normal code path
 *   } EXCEPT(MyModule_Failed) {
 *     // Specific handling
 *     fprintf(stderr, "Operation failed at %s:%d: %s\n",
 *             Except_frame.file, Except_frame.line, e.reason);
 *   } FINALLY {
 *     // Always execute cleanup
 *     cleanup_resources();
 *   } END_TRY;
 * }
 * @endcode
 *
 * ## Advanced Usage with Custom Exception
 *
 * @code{.c}
 * // Define module exception
 * const Except_T MyModule_Failed = { &Assert_Failed, "MyModule operation
 * failed" };
 *
 * TRY {
 *   // ...
 *   if (validation_error) {
 *     RAISE(MyModule_Failed);
 *   }
 * } EXCEPT(MyModule_Failed) {
 *   // Recover or log
 *   RERAISE;  // Propagate if not recoverable
 * } END_TRY;
 * @endcode
 *
 * @note For custom exceptions, define as: const Except_T MyError = {
 * &Some_Base, "reason" };
 * @warning Must be called within a TRY block; otherwise undefined behavior.
 * @warning Avoid in signal handlers or other contexts where longjmp is unsafe.
 * @complexity O(1) - constant time, modulo stack unwinding cost.
 *
 * @see Except_raise() for low-level implementation details.
 * @see TRY for establishing exception handling context.
 * @see EXCEPT for catching specific exceptions.
 * @see RERAISE for propagating caught exceptions.
 * @see docs/ERROR_HANDLING.md for exception best practices and module
 * exception declaration.
 */
#define RAISE(e) Except_raise (&(e), __FILE__, __LINE__)

/**
 * @brief Re-raise the currently caught exception.
 * @ingroup foundation
 *
 * This macro re-raises the exception that was caught by the current EXCEPT or
 * ELSE block. It uses the information stored in the current Except_frame
 * (exception, file, line) to propagate the exception up the call stack to the
 * next enclosing TRY block.
 *
 * Useful for error recovery or logging where the exception is handled locally
 * but needs to be propagated for higher-level handling. Allows chaining of
 * exception handlers.
 *
 * Behavior:
 * - Extracts exception details from Except_frame (set by the original RAISE)
 * - Performs longjmp() to unwind to parent frame
 * - Preserves original raise location and reason for debugging
 * - Only valid after an exception has been caught (Except_flag ==
 * Except_handled)
 *
 * Edge cases:
 * - Calling outside handler context leads to invalid memory access or wrong
 * exception
 * - Propagates through multiple levels until caught or stack exhausted
 *
 * @param None - uses current thread-local Except_frame data.
 *
 * @return Does not return normally; re-raises via longjmp().
 *
 * @throws The originally caught exception (propagated upward).
 *
 * @threadsafe No - relies on and modifies thread-local exception state.
 *
 * ## Usage Example
 *
 * @code{.c}
 * TRY {
 *   // Nested operation
 *   inner_function();  // Might raise Socket_Failed
 * } EXCEPT(Socket_Failed) {
 *   // Local handling: log the error
 *   log_error("Socket error in inner_function: %s",
 * Except_frame.exception->reason);
 *
 *   // But propagate for higher-level handling
 *   RERAISE;  // Re-raises the same Socket_Failed exception
 * } FINALLY {
 *   // Cleanup
 * } END_TRY;
 * @endcode
 *
 * ## Multi-Level Propagation
 *
 * @code{.c}
 * // Outer handler
 * TRY {
 *   risky_call();
 * } EXCEPT(Socket_Failed) {
 *   // Final handling or abort
 *   fprintf(stderr, "Unrecoverable socket failure\n");
 *   // No RERAISE here - exception stops propagating
 * } END_TRY;
 *
 * // Inner function (called by risky_call)
 * void risky_call() {
 *   TRY {
 *     // ...
 *     if (error) RAISE(Socket_Failed);
 *   } EXCEPT(Socket_Failed) {
 *     // Partial recovery or additional checks
 *     RERAISE;  // Continue propagation
 *   } END_TRY;
 * }
 * @endcode
 *
 * @note RERAISE preserves the original exception details for accurate
 * debugging.
 * @warning Only use within EXCEPT/ELSE blocks after exception caught.
 * @warning Does not create new exception frame; reuses current one.
 * @complexity O(1) - direct use of frame data and longjmp.
 *
 * @see RAISE() for initial exception raising.
 * @see EXCEPT for catching and entering handler context.
 * @see Except_raise() for low-level re-raising mechanism.
 * @see TRY for enclosing context required.
 * @see docs/ERROR_HANDLING.md for propagation patterns and best practices.
 */
#define RERAISE                                                               \
  Except_raise ((const Except_T *)Except_frame.exception, Except_frame.file,  \
                Except_frame.line)

/**
 * @brief Return from function while cleaning up exception stack.
 * @ingroup foundation
 *
 * This macro provides a safe way to return from a function within a TRY block,
 * automatically popping the current exception frame from the thread-local
 * stack before executing the return statement. Prevents exception stack leaks
 * when exiting early from protected code regions.
 *
 * Implementation uses a switch statement with comma operator to perform the
 * stack cleanup as a side effect, ensuring compatibility with complex return
 * expressions including those with commas (e.g., RETURN a ? b : c;).
 *
 * Essential for maintaining exception handling integrity and avoiding resource
 * leaks or corrupted stack states in multi-level TRY scenarios.
 *
 * Edge cases:
 * - Only affects current frame; nested frames remain intact
 * - Safe for both void and value-returning functions
 * - Thread-local operation; no impact on other threads
 *
 * @param None - the macro consumes the return expression provided after
 * RETURN.
 *
 * @return Returns the value/expression provided (or void); stack cleanup
 * occurs first.
 *
 * @throws None - does not raise exceptions; only cleans up stack.
 *
 * @threadsafe No - modifies thread-local Except_stack; must be used within
 * originating thread's TRY context.
 *
 * ## Basic Usage Examples
 *
 * @code{.c}
 * // Void function early return
 * void process_data() {
 *   TRY {
 *     // Setup
 *     if (invalid_input()) {
 *       RETURN;  // Cleans stack and returns void
 *     }
 *     // Continue processing...
 *   } END_TRY;
 * }
 * @endcode
 *
 * ## Value-Returning Function
 *
 * @code{.c}
 * int compute_value(int input) {
 *   int result = 0;
 *   TRY {
 *     if (input < 0) {
 *       RETURN -1;  // Returns -1 after stack cleanup
 *     }
 *     result = expensive_computation(input);
 *     RETURN result;  // Normal return with cleanup
 *   } END_TRY;
 *   return result;  // Unreachable if RETURN used
 * }
 * @endcode
 *
 * ## Complex Expression Return
 *
 * @code{.c}
 * Socket_T create_connection(const char *host, int port) {
 *   TRY {
 *     // Validation and setup
 *     if (!valid_host(host)) {
 *       RETURN NULL;
 *     }
 *     Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     Socket_connect(sock, host, port);
 *     // On success, return with cleanup
 *     RETURN sock;  // Works even with simple expressions
 *   } EXCEPT(Socket_Failed) {
 *     // Handle error
 *     RETURN NULL;
 *   } END_TRY;
 * }
 * @endcode
 *
 * @note Equivalent to manual stack pop + return, but safer and more readable.
 * @warning Subtle implementation relies on comma operator precedence; do not
 * modify macro expansion.
 * @warning Only pops current frame; use in innermost TRY for correct behavior.
 * @complexity O(1) - simple pointer assignment and return.
 *
 * @see TRY macro for creating frames that require cleanup on early return.
 * @see END_TRY for automatic cleanup on block exit.
 * @see Except_stack for the thread-local stack being managed.
 * @see docs/ERROR_HANDLING.md for advanced TRY block patterns and stack
 * management.
 */
#define RETURN                                                                \
  switch (Except_stack = ((Except_Frame *)Except_stack)->prev, 0)             \
  default:                                                                    \
    return

/**
 * @brief Internal helper macro for exception frame cleanup.
 * @ingroup foundation
 *
 * Utility macro invoked by EXCEPT, ELSE, FINALLY, and END_TRY to conditionally
 * pop the current exception frame from Except_stack if the TRY block was
 * entered normally (Except_flag == Except_entered) without raising an
 * exception.
 *
 * Ensures stack integrity on all exit paths:
 * - Normal completion: pop frame
 * - Raised exception: defer pop until handled or propagated
 * - Avoids leaks in non-exceptional paths
 *
 * Implementation:
 * - Checks Except_flag state
 * - If entered: save prev = stack->prev, then stack = prev (pop)
 * - No-op if already raised/handled (frame still needed for info)
 *
 * Used internally to balance TRY pushes with pops.
 *
 * @note Strictly internal; part of macro expansion - users never invoke
 * directly.
 * @warning Modifies global Except_stack; context-sensitive.
 *
 * @code{.c}
 * // Appears in expansions like:
 * #define EXCEPT(e) \
 *   EXCEPT_POP_FRAME_IF_ENTERED \
 *   } else if (...) { \
 *     // handler
 * @endcode
 *
 * @see TRY for corresponding push.
 * @see END_TRY for final cleanup.
 * @see Except_stack for the stack variable.
 */
#define EXCEPT_POP_FRAME_IF_ENTERED                                           \
  if (Except_flag == Except_entered)                                          \
    {                                                                         \
      Except_Frame *prev_frame = NULL;                                        \
      if (Except_stack != NULL)                                               \
        prev_frame = Except_stack->prev;                                      \
      Except_stack = prev_frame;                                              \
    }

/**
 * @brief Start a TRY/EXCEPT/FINALLY exception handling block.
 * @ingroup foundation
 *
 * This macro initiates a structured exception handling context similar to
 * try/catch in higher-level languages. It pushes a new Except_Frame onto the
 * thread-local Except_stack, captures the current continuation point using
 * setjmp(), and executes the protected code block. If no exception occurs,
 * execution continues normally. If RAISE() is called within the block, control
 * jumps back to the setjmp() point via longjmp(), allowing exception handlers
 * (EXCEPT/ELSE) to execute.
 *
 * Key features and behavior:
 * - Thread-local stack management - each thread maintains independent contexts
 * - Supports nested TRY blocks with proper frame stacking/unwinding
 * - Integrates with FINALLY for guaranteed cleanup (executes on all exit
 * paths)
 * - Variables modified across potential longjmp() boundaries must be volatile
 *   to prevent compiler optimization issues
 * - Automatic frame cleanup on normal exit or RETURN usage
 *
 * Typical usage patterns include protecting resource acquisition/usage,
 * error-prone system calls, and validation logic where failures need
 * structured recovery.
 *
 * Edge cases:
 * - Deep nesting may consume stack space (each frame ~sizeof(jmp_buf) +
 * overhead)
 * - setjmp() may not capture all registers on some architectures/compilers
 * - longjmp() from signal handlers or async contexts is unsafe
 *
 * @param None - macro expands to local variables and control flow setup.
 *
 * @return None - establishes control context; does not return a value.
 *
 * @throws Exceptions raised via RAISE() within block are caught by subsequent
 * handlers.
 *
 * @threadsafe No - allocates and modifies thread-local Except_stack and frame.
 *
 * ## Basic Usage Example
 *
 * @code{.c}
 * #include "core/Except.h"
 * extern const Except_T DivideByZeroError;
 *
 * double safe_divide(double a, double b) {
 *   double result;
 *   TRY {
 *     if (b == 0.0) {
 *       RAISE(DivideByZeroError);
 *     }
 *     result = a / b;  // Protected operation
 *     RETURN result;   // Early return with stack cleanup
 *   } EXCEPT(DivideByZeroError) {
 *     result = 0.0;    // Default value on error
 *     fprintf(stderr, "Division by zero avoided\n");
 *   } FINALLY {
 *     // Always executes: logging, metrics, etc.
 *     log_operation("divide", a, b, result);
 *   } END_TRY;
 *   return result;
 * }
 * @endcode
 *
 * ## Nested TRY Blocks
 *
 * @code{.c}
 * void complex_operation() {
 *   TRY {  // Outer TRY
 *     resource_setup();
 *     TRY {  // Inner TRY
 *       inner_operation();  // May raise InnerError
 *     } EXCEPT(InnerError) {
 *       RERAISE;  // Propagate to outer
 *     } END_TRY;
 *   } EXCEPT(OuterError) {
 *     // Handle or log outer-level error
 *   } FINALLY {
 *     resource_cleanup();  // Both levels ensure cleanup
 *   } END_TRY;
 * }
 * @endcode
 *
 * ## With Volatile Variables
 *
 * @code{.c}
 * volatile int status = 0;  // Volatile to survive longjmp
 * TRY {
 *   status = setup();
 *   if (status < 0) {
 *     RAISE(Error);
 *   }
 *   // Use status...
 *   RETURN status;
 * } END_TRY;
 * @endcode
 *
 * @note Declare modified variables as volatile int/pointer etc. to ensure
 * visibility post-longjmp.
 * @warning Avoid non-volatile locals modified in TRY if RAISE possible -
 * optimizer may eliminate them.
 * @warning Limit nesting depth to avoid excessive stack usage or performance
 * overhead.
 * @complexity O(1) - setjmp() call and frame allocation (amortized).
 *
 * @see RAISE() for raising exceptions within protected blocks.
 * @see EXCEPT for specific exception handling.
 * @see ELSE for catch-all handling.
 * @see FINALLY for guaranteed cleanup code.
 * @see END_TRY to finalize the block and propagate unhandled exceptions.
 * @see RETURN for early returns with automatic stack cleanup.
 * @see docs/ERROR_HANDLING.md for detailed patterns, volatile usage, and
 * nesting guidelines.
 * @see @ref foundation for other base infrastructure modules.
 */
#define TRY                                                                   \
  do                                                                          \
    {                                                                         \
      volatile int Except_flag;                                               \
      volatile Except_Frame Except_frame;                                     \
      jmp_buf *env_ptr = (jmp_buf *)&Except_frame.env;                        \
      Except_frame.prev = Except_stack;                                       \
      Except_frame.file = NULL;                                               \
      Except_frame.line = 0;                                                  \
      Except_frame.exception = NULL;                                          \
      Except_stack = (Except_Frame *)&Except_frame;                           \
      Except_flag = setjmp (*env_ptr);                                        \
      if (Except_flag == Except_entered)                                      \
        {

/**
 * @brief Catch a specific exception type within a TRY block.
 * @ingroup foundation
 *
 * This macro defines a handler for a specific exception type caught from the
 * preceding TRY block. It compares the raised exception's type pointer exactly
 * with the provided exception variable e. If matching, executes the handler
 * code and sets Except_flag to Except_handled, allowing subsequent FINALLY or
 * END_TRY processing.
 *
 * Supports chaining multiple EXCEPT blocks for different exception types,
 * evaluated in order (first match wins). Non-matching exceptions propagate to
 * ELSE or outer handlers.
 *
 * Behavior details:
 * - Pops frame if entered normally (Except_flag == Except_entered)
 * - Exact pointer match on e->type == raised->type
 * - Access Except_frame.exception->reason for error details in handler
 * - After handler, exception is considered handled unless RERAISE used
 *
 * Best practices:
 * - Order most specific exceptions first
 * - Use for recovery, logging, or partial handling
 * - Combine with FINALLY for resource cleanup
 *
 * Edge cases:
 * - No preceding TRY: compile error (macro expansion assumes frame)
 * - Multiple matches: only first EXCEPT triggers
 * - RERAISE in handler propagates to outer scopes
 *
 * @param[in] e Exception variable defining the type to catch (e.g.,
 * Socket_Failed). Uses &e for comparison.
 *
 * @return None - executes handler block if match, otherwise skips.
 *
 * @throws None - handles rather than throws; use RERAISE to propagate.
 *
 * @threadsafe No - accesses and modifies thread-local Except_flag and stack.
 *
 * ## Basic Usage Example
 *
 * @code{.c}
 * extern const Except_T Socket_Failed;
 * extern const Except_T Memory_Failed;
 *
 * void connect_with_recovery(const char *host, int port) {
 *   Socket_T sock = NULL;
 *   TRY {
 *     sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     Socket_connect(sock, host, port);  // May raise Socket_Failed
 *     // Or other ops raising Memory_Failed
 *   } EXCEPT(Socket_Failed) {
 *     // Specific network error handling
 *     fprintf(stderr, "Connection failed: %s\n",
 * Except_frame.exception->reason); sock = NULL;  // Indicate failure }
 * EXCEPT(Memory_Failed) {
 *     // Handle OOM separately
 *     perror("Memory allocation failed");
 *     abort();  // Or RERAISE;
 *   } FINALLY {
 *     if (sock) Socket_free(&sock);  // Always cleanup
 *   } END_TRY;
 *   // Use sock or handle NULL
 * }
 * @endcode
 *
 * ## Chained Handlers with Propagation
 *
 * @code{.c}
 * TRY {
 *   operation_that_may_fail();
 * } EXCEPT(SpecificError) {
 *   // Handle specifically
 *   log_specific(SpecificError);
 *   RERAISE;  // Propagate for general handling
 * } EXCEPT(AnotherError) {
 *   // Alternative handling
 * } ELSE {
 *   // Catch-all for unexpected exceptions
 *   log_unexpected(Except_frame.exception);
 *   RERAISE;  // Or handle terminally
 * } END_TRY;
 * @endcode
 *
 * @note Compare using exact exception variable; subtypes not supported (use
 * base types for hierarchy).
 * @warning Pointer comparison only - different variables with same structure
 * won't match.
 * @warning Place after TRY, before ELSE/FINALLY/END_TRY in sequence.
 * @complexity O(1) - direct pointer comparison and flag update.
 *
 * @see TRY for initiating the protected block.
 * @see ELSE for handling unmatched exceptions.
 * @see RERAISE to propagate from within handler.
 * @see FINALLY for code executing after handling.
 * @see END_TRY to close block and re-raise unhandled.
 * @see docs/ERROR_HANDLING.md for handler ordering, exception hierarchies, and
 * recovery patterns.
 */
#define EXCEPT(e)                                                             \
  EXCEPT_POP_FRAME_IF_ENTERED                                                 \
  }                                                                           \
  else if (Except_frame.exception && Except_frame.exception->type == &(e))    \
  {                                                                           \
    Except_flag = Except_handled;

/**
 * @brief Catch any exception not caught by previous EXCEPT blocks.
 * @ingroup foundation
 *
 * This macro provides a catch-all handler for any exception raised in the
 * preceding TRY block that did not match any prior EXCEPT blocks. It executes
 * when an exception is pending (Except_flag == Except_raised) but no specific
 * handler claimed it.
 *
 * Serves as the default case in exception dispatching, useful for generic
 * error handling, logging unexpected errors, or providing fallback recovery
 * mechanisms. After execution, sets Except_flag to Except_handled unless
 * RERAISE is called.
 *
 * Behavior:
 * - Automatically triggers on unhandled exceptions from TRY
 * - Access full Except_frame details (exception, reason, file, line)
 * - Only one ELSE per TRY block; placement after all EXCEPTs
 * - Integrates with FINALLY for post-handling cleanup
 *
 * Best practices:
 * - Use for logging/tracing unexpected exceptions
 * - Decide to RERAISE for propagation or handle terminally
 * - Avoid swallowing exceptions without logging
 *
 * Edge cases:
 * - No exception raised: ELSE skipped entirely
 * - After ELSE, unhandled exceptions re-raised by END_TRY
 * - Can chain with RERAISE to outer handlers
 *
 * @param None - triggers on any unmatched exception type.
 *
 * @return None - executes fallback handler code if triggered.
 *
 * @throws None directly; may re-raise via RERAISE.
 *
 * @threadsafe No - updates thread-local Except_flag and interacts with stack.
 *
 * ## Basic Usage Example
 *
 * @code{.c}
 * extern const Except_T KnownError;
 *
 * void operation_with_fallback() {
 *   TRY {
 *     risky_code();  // May raise KnownError or unexpected exceptions
 *   } EXCEPT(KnownError) {
 *     // Handle known case
 *     recover_from_known();
 *   } ELSE {
 *     // Fallback for unknown/unexpected exceptions
 *     log_unexpected(Except_frame.exception->reason,
 *                    Except_frame.file, Except_frame.line);
 *     // Option 1: Terminate handling
 *     // return; or set error state
 *
 *     // Option 2: Propagate
 *     // RERAISE;
 *   } FINALLY {
 *     cleanup();
 *   } END_TRY;
 * }
 * @endcode
 *
 * ## Logging and Propagation
 *
 * @code{.c}
 * TRY {
 *   // ...
 * } EXCEPT(NetworkError) {
 *   // Specific
 * } EXCEPT(MemoryError) {
 *   // Specific
 * } ELSE {
 *   // Generic handling for all others
 *   metrics_increment(UNEXPECTED_EXCEPTION);
 *   error_report("Caught unexpected: %s at %s:%d",
 *                Except_frame.exception->reason,
 *                Except_frame.file, Except_frame.line);
 *   RERAISE;  // Let outer handler deal with it
 * } END_TRY;
 * @endcode
 *
 * @note Provides safety net for unanticipated exceptions in robust code.
 * @warning Only one ELSE per TRY; multiple compile to invalid syntax.
 * @warning Must follow all EXCEPT blocks; order matters for dispatching.
 * @warning Always log or report in ELSE to avoid silent failures.
 * @complexity O(1) - simple flag check and execution.
 *
 * @see EXCEPT for specific type matching.
 * @see TRY for block initiation.
 * @see RERAISE to continue propagation from ELSE.
 * @see FINALLY for code after ELSE execution.
 * @see END_TRY for block closure and unhandled re-raise.
 * @see docs/ERROR_HANDLING.md for catch-all strategies and error reporting.
 */
#define ELSE                                                                  \
  EXCEPT_POP_FRAME_IF_ENTERED                                                 \
  }                                                                           \
  else                                                                        \
  {                                                                           \
    Except_flag = Except_handled;

/**
 * @brief Define cleanup code that executes regardless of exceptions.
 * @ingroup foundation
 *
 * This macro defines a block of code guaranteed to execute upon exit from the
 * TRY/EXCEPT/ELSE handlers, irrespective of whether an exception was raised,
 * handled, or propagated. It implements the finally clause semantics for
 * resource management, ensuring cleanup occurs on all control flow paths:
 * normal return, early RETURN, exception handling, or re-raise via RERAISE.
 *
 * Execution timing:
 * - After TRY (normal path)
 * - After each EXCEPT/ELSE handler (if exception caught)
 * - Before END_TRY re-raises unhandled exceptions
 * - Even if RERAISE called in handlers (post-handler cleanup)
 *
 * Critical for RAII-like patterns in C: file closes, socket frees, memory
 * releases, locks unlocks, etc. Prevents leaks in exceptional paths.
 *
 * Behavior details:
 * - Checks Except_flag == Except_entered to finalize if no exception
 * - Integrates with frame popping via EXCEPT_POP_FRAME_IF_ENTERED
 * - No exception propagation from FINALLY; errors inside are not caught by
 * this block
 *
 * Best practices:
 * - Place resource acquisition in TRY, cleanup in FINALLY
 * - Keep FINALLY idempotent (safe to call multiple times)
 * - Avoid raising exceptions in FINALLY (use logging instead)
 * - Use volatile for shared state if needed
 *
 * Edge cases:
 * - Empty FINALLY: compiles but executes nothing
 * - Multiple FINALLY: compile error (only one allowed)
 * - FINALLY before EXCEPT: invalid sequence, use correct order
 *
 * @param None - defines cleanup block post-handlers.
 *
 * @return None - executes cleanup code unconditionally on exit paths.
 *
 * @throws Exceptions raised in FINALLY propagate outside the TRY block.
 *
 * @threadsafe No - updates local Except_flag; thread-local context.
 *
 * ## Basic Resource Cleanup Example
 *
 * @code{.c}
 * FILE *file = NULL;
 * TRY {
 *   file = fopen("data.txt", "r");  // May fail
 *   if (!file) RAISE(FileOpenFailed);
 *   // Process file...
 * } EXCEPT(FileOpenFailed) {
 *   // Handle open error
 * } EXCEPT(OtherError) {
 *   // Handle processing error
 * } FINALLY {
 *   // Guaranteed cleanup regardless of path
 *   if (file) {
 *     fclose(file);
 *     file = NULL;
 *   }
 * } END_TRY;
 * @endcode
 *
 * ## With Early Return and RERAISE
 *
 * @code{.c}
 * Socket_T sock;
 * TRY {
 *   sock = Socket_new(...);
 *   if (connect_fails) RETURN NULL;  // FINALLY still executes
 *   // Normal ops
 * } EXCEPT(SocketError) {
 *   log_error();
 *   RERAISE;  // FINALLY executes before propagation
 * } FINALLY {
 *   Socket_free(&sock);  // Always called
 * } END_TRY;
 * @endcode
 *
 * ## Nested Cleanup
 *
 * @code{.c}
 * TRY {  // Outer
 *   outer_resource();
 *   TRY {  // Inner
 *     inner_resource();
 *   } FINALLY {
 *     inner_cleanup();  // Inner first
 *   } END_TRY;
 * } FINALLY {
 *   outer_cleanup();  // Then outer
 * } END_TRY;
 * @endcode
 *
 * @note FINALLY ensures deterministic cleanup, complementing RAII where
 * possible.
 * @warning Do not rely on FINALLY for exception handling; use EXCEPT for that.
 * @warning Exceptions in FINALLY escape the block - catch in outer TRY if
 * needed.
 * @warning Only one per TRY; follows EXCEPT/ELSE in sequence.
 * @complexity O(1) - conditional flag check and execution.
 *
 * @see TRY for resource acquisition.
 * @see EXCEPT/ELSE for error paths leading to FINALLY.
 * @see RERAISE interaction with FINALLY execution.
 * @see END_TRY for final block closure.
 * @see RETURN for early exit triggering FINALLY.
 * @see docs/ERROR_HANDLING.md for cleanup patterns, idempotency, and nesting.
 */
#define FINALLY                                                               \
  EXCEPT_POP_FRAME_IF_ENTERED                                                 \
  }                                                                           \
  {                                                                           \
    if (Except_flag == Except_entered)                                        \
      Except_flag = Except_finalized;

/**
 * @brief Complete a TRY/EXCEPT/FINALLY exception handling block.
 * @ingroup foundation
 *
 * This macro finalizes the exception handling construct by popping the current
 * exception frame from the thread-local stack, executing any pending FINALLY
 * block (if not already), and re-raising any unhandled exceptions (Except_flag
 * == Except_raised) to propagate them to outer TRY blocks or terminate the
 * program.
 *
 * Cleanup sequence:
 * - Calls EXCEPT_POP_FRAME_IF_ENTERED to remove frame if entered normally
 * - Checks for pending raised exceptions and invokes RERAISE if needed
 * - Ensures all local variables (Except_flag, Except_frame) are scoped
 * correctly
 * - Closes the do-while(0) loop structure for TRY expansion
 *
 * Essential for proper resource management and exception propagation. Without
 * END_TRY, frames leak, unhandled exceptions are forgotten, and control flow
 * breaks.
 *
 * Behavior on exit paths:
 * - Normal completion: stack cleaned, no re-raise
 * - Handled exception: stack cleaned, no re-raise
 * - Unhandled: RERAISE propagates via longjmp()
 * - Early RETURN: already handled via macro, END_TRY finalizes
 *
 * Edge cases:
 * - Missing END_TRY: compile/link errors or runtime corruption
 * - Nested blocks: each requires own END_TRY
 * - Unhandled in top-level: may terminate program (depends on Except_raise
 * impl)
 *
 * @param None - concludes the entire TRY construct.
 *
 * @return None - restores normal control flow or propagates via re-raise.
 *
 * @throws Re-raises unhandled exceptions from this block.
 *
 * @threadsafe No - finalizes thread-local frame and flag state.
 *
 * ## Complete Block Example
 *
 * @code{.c}
 * // Full TRY construct
 * TRY {
 *   // Acquisition and protected code
 *   resource = acquire_resource();
 *   if (!resource) RAISE(AcquireFailed);
 *   use_resource(resource);
 * } EXCEPT(AcquireFailed) {
 *   // Handle acquisition failure
 *   error_state = ACQUIRE_ERROR;
 * } EXCEPT(UseFailed) {
 *   // Handle usage error
 *   partial_rollback();
 *   RERAISE;  // Propagate if needed
 * } ELSE {
 *   // Unexpected
 *   emergency_shutdown();
 * } FINALLY {
 *   // Release regardless
 *   release_resource(resource);
 * } END_TRY;  // Cleans up, re-raises if unhandled
 * @endcode
 *
 * ## Minimal TRY-EXCEPT-END_TRY
 *
 * @code{.c}
 * TRY {
 *   risky_op();
 * } EXCEPT(KnownError) {
 *   recover();
 * } END_TRY;  // Handles cleanup and propagation
 * @endcode
 *
 * ## Top-Level Unhandled Propagation
 *
 * @code{.c}
 * // In main or top function
 * TRY {
 *   main_logic();
 * } EXCEPT(AnyError) {
 *   // Last chance
 *   log_fatal();
 *   // No RERAISE - terminate gracefully
 * } FINALLY {
 *   global_cleanup();
 * } END_TRY;
 * // If unhandled here, program ends with default handler
 * @endcode
 *
 * @note Always pair with TRY; forms complete exception handling unit.
 * @warning Omitting END_TRY leads to leaks and undefined behavior.
 * @warning Position after all EXCEPT/ELSE/FINALLY in sequence.
 * @warning Unhandled exceptions re-raised - ensure outer handling or
 * termination strategy.
 * @complexity O(1) - frame pop and conditional RERAISE.
 *
 * @see TRY for block start.
 * @see EXCEPT/ELSE for handlers leading to END_TRY.
 * @see FINALLY for pre-END_TRY cleanup.
 * @see RERAISE mechanism invoked by END_TRY for propagation.
 * @see docs/ERROR_HANDLING.md for complete constructs, nesting, and top-level
 * handling.
 */
#define END_TRY                                                               \
  EXCEPT_POP_FRAME_IF_ENTERED                                                 \
  }                                                                           \
  if (Except_flag == Except_raised)                                           \
    RERAISE;                                                                  \
  }                                                                           \
  while (0)

#undef T
#endif
