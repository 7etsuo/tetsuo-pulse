#ifndef EXCEPT_INCLUDED
#define EXCEPT_INCLUDED

#include <setjmp.h>

/**
 * @file Except.h
 * @ingroup foundation
 * @brief Structured exception handling for C with TRY/EXCEPT/FINALLY blocks.
 *
 * IMPORTANT: Do NOT compile with -DNDEBUG in production code. The exception
 * system relies on runtime checks that are critical for safety. While assert()
 * statements will be disabled, the explicit NULL checks will remain active.
 *
 * This module provides structured exception handling similar to try/catch
 * in other languages. It uses setjmp/longjmp for non-local control flow.
 *
 * Features:
 * - TRY/EXCEPT/FINALLY blocks
 * - Thread-safe implementation (thread-local exception stack)
 * - Named exceptions with reason strings
 * - Exception propagation with RERAISE
 *
 * Usage:
 *   TRY
 *     // Code that might raise an exception
 *     if (error_condition)
 *       RAISE(Socket_Failed);
 *   EXCEPT(Socket_Failed)
 *     // Handle specific exception
 *   FINALLY
 *     // Cleanup code (always executed)
 *   END_TRY;
 *
 * @note Exception handling uses setjmp/longjmp which can cause issues with
 *       variable optimization. Use volatile for variables modified in TRY blocks.
 * @warning Do not compile with -DNDEBUG in production - exception safety relies
 *          on runtime checks.
 *
 * @see Except_T for exception type definition.
 * @see RAISE() macro for raising exceptions.
 * @see TRY/EXCEPT/FINALLY macros for exception handling.
 * @see Except_raise() for internal exception raising function.
 * @see @ref core_io for modules that use this exception system.
 * @see docs/ERROR_HANDLING.md for detailed exception handling documentation and best practices.
 */

/**
 * @brief Exception structure for structured error handling.
 * @ingroup foundation
 *
 * Value type (not opaque) representing an exception with a type and human-readable reason string.
 * Exceptions are raised using RAISE() and caught with TRY/EXCEPT blocks.
 *
 * @see TRY/EXCEPT/FINALLY macros for exception handling.
 * @see RAISE() macro for raising exceptions.
 * @see @ref foundation for core foundation modules.
 */
typedef struct Except_T
{
  const struct Except_T *type; /**< Exception type identifier */
  const char *reason; /**< Human-readable error description */
} Except_T;

/**
 * @brief Exception frame for TRY/EXCEPT/FINALLY blocks.
 * @ingroup foundation
 *
 * Internal structure representing an exception handling context on the
 * thread-local exception stack. Each TRY block creates a new frame.
 *
 * @note This is an internal structure - users should not manipulate directly.
 * @see TRY macro for creating exception frames.
 * @see Except_stack for thread-local exception stack.
 */
typedef struct Except_Frame Except_Frame;
struct Except_Frame
{
  Except_Frame *prev; /**< Previous frame in exception stack */
  jmp_buf env; /**< setjmp/longjmp context for non-local control flow */
  const char *file; /**< Source file where exception was raised */
  int line; /**< Source line where exception was raised */
  const Except_T *exception; /**< Exception that was raised */
};

/**
 * @brief Exception handling states for TRY/EXCEPT/FINALLY blocks.
 * @ingroup foundation
 *
 * Internal states used by the exception handling macros to track
 * the current state of exception processing.
 */
enum
{
  Except_entered = 0, /**< TRY block entered, no exception raised */
  Except_raised, /**< Exception raised, executing EXCEPT or FINALLY */
  Except_handled, /**< Exception handled, executing FINALLY or END_TRY */
  Except_finalized /**< FINALLY block executed, cleaning up */
};

/**
 * @brief Thread-local exception stack for TRY/EXCEPT/FINALLY blocks.
 * @ingroup foundation
 *
 * Thread-local storage containing the current exception handling context.
 * Each TRY block pushes a new frame onto this stack.
 *
 * @note This is thread-local - each thread has its own exception stack.
 * @threadsafe Yes - each thread has independent stack.
 * @see Except_Frame for frame structure.
 * @see TRY macro for stack manipulation.
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
 * Exception raised when an assert() fails. Used for programming errors
 * and contract violations that should not occur in correct code.
 *
 * @note Assertions should be used for programming errors, not runtime errors.
 * @see assert() macro which raises this exception on failure.
 */
extern const Except_T Assert_Failed;

/**
 * @brief Raise an exception (internal function - use RAISE() macro instead).
 * @ingroup foundation
 * @param e Exception to raise (must not be NULL).
 * @param file Source file where exception is raised.
 * @param line Source line where exception is raised.
 * @threadsafe No - modifies thread-local exception stack.
 * @note Use RAISE() macro instead of calling directly.
 * @warning Uses longjmp() - ensure no local variables need cleanup.
 * @see RAISE() macro for user-level exception raising.
 * @see TRY/EXCEPT macros for exception handling.
 * @see RERAISE macro for re-raising caught exceptions.
 */
void Except_raise (const Except_T *e, const char *file, int line);

/**
 * @brief Raise an exception with current file and line information.
 * @ingroup foundation
 * @param e Exception variable to raise (not a pointer).
 * @threadsafe No - modifies thread-local exception stack.
 * @note Uses longjmp() internally - ensure proper cleanup in FINALLY blocks.
 * @warning Exception must be a variable name, not an expression.
 * @see TRY/EXCEPT macros for catching exceptions.
 * @see RERAISE for re-raising caught exceptions.
 */
#define RAISE(e) Except_raise (&(e), __FILE__, __LINE__)

/**
 * @brief Re-raise the currently caught exception.
 * @ingroup foundation
 * @threadsafe No - modifies thread-local exception stack.
 * @note Only valid within EXCEPT or ELSE blocks.
 * @warning Must be called from within an exception handler.
 * @see EXCEPT macro for exception catching.
 * @see RAISE() macro for initial exception raising.
 */
#define RERAISE                                                               \
  Except_raise ((const Except_T *)Except_frame.exception, Except_frame.file,  \
                Except_frame.line)

/**
 * @brief Return from function while cleaning up exception stack.
 * @ingroup foundation
 * @threadsafe No - modifies thread-local exception stack (use within same-thread TRY context).
 *
 * Safe return macro that pops the current exception frame before returning.
 * Must be used within TRY blocks when returning early to prevent stack leaks.
 *
 * The switch/default pattern uses the comma operator to clean up the stack
 * as a side effect before returning, allowing complex return expressions.
 *
 * @note Only use within TRY blocks.
 * @warning Uses comma operator and switch statement - subtle implementation.
 *
 * Usage examples:
 *   RETURN;              // For void functions
 *   RETURN value;        // For functions returning a value
 *   RETURN func(a, b);   // Works with function calls containing commas
 *
 * @see TRY macro for exception handling blocks.
 * @see END_TRY for normal block exit.
 */
#define RETURN                                                                \
  switch (Except_stack = ((Except_Frame *)Except_stack)->prev, 0)             \
  default:                                                                    \
    return

/**
 * @brief Internal helper macro for exception frame cleanup.
 * @ingroup foundation
 * @note Internal use only - do not use directly.
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
 * Begins an exception handling context. Code within the TRY block can raise
 * exceptions that will be caught by subsequent EXCEPT blocks.
 *
 * Must be paired with END_TRY. Can include EXCEPT, ELSE, and FINALLY blocks.
 *
 * @note Variables modified in TRY blocks should be declared volatile.
 * @warning Uses setjmp/longjmp - ensure proper resource cleanup.
 * @threadsafe No - modifies thread-local exception stack.
 *
 * Usage:
 *   TRY {
 *     // Code that might raise exceptions
 *     RAISE(Some_Exception);
 *   } EXCEPT(Some_Exception) {
 *     // Handle exception
 *   } END_TRY;
 *
 * @see EXCEPT macro for catching specific exceptions.
 * @see ELSE macro for catching all other exceptions.
 * @see FINALLY macro for cleanup code.
 * @see END_TRY macro to complete the block.
 * @see RAISE() macro for raising exceptions.
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
 * @param e Exception variable to catch (not a pointer).
 *
 * Catches exceptions of the specified type raised within the preceding TRY block.
 * Multiple EXCEPT blocks can be chained to handle different exception types.
 *
 * @note Exception variable must match exactly (pointer comparison).
 * @warning Only catches exact exception type - use ELSE for catch-all.
 * @threadsafe No - operates on thread-local exception stack.
 *
 * Usage:
 *   TRY {
 *     RAISE(Socket_Failed);
 *   } EXCEPT(Socket_Failed) {
 *     // Handle Socket_Failed specifically
 *   } EXCEPT(Other_Exception) {
 *     // Handle Other_Exception
 *   } END_TRY;
 *
 * @see TRY macro for starting exception handling.
 * @see ELSE macro for catching all other exceptions.
 * @see FINALLY macro for cleanup code.
 * @see RERAISE for re-raising caught exceptions.
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
 * Catch-all handler for exceptions that don't match any preceding EXCEPT blocks.
 * Acts like a default case in a switch statement for exceptions.
 *
 * @note Only one ELSE block allowed per TRY block.
 * @warning Must come after all EXCEPT blocks but before FINALLY.
 * @threadsafe No - operates on thread-local exception stack.
 *
 * Usage:
 *   TRY {
 *     // Code that might raise exceptions
 *   } EXCEPT(Specific_Exception) {
 *     // Handle specific exception
 *   } ELSE {
 *     // Handle any other exception
 *   } END_TRY;
 *
 * @see EXCEPT macro for catching specific exceptions.
 * @see TRY macro for starting exception handling.
 * @see FINALLY macro for cleanup code.
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
 * Block of code that executes after TRY/EXCEPT/ELSE blocks, regardless of
 * whether an exception was raised or handled. Used for resource cleanup.
 *
 * @note Executes even if exception is re-raised with RERAISE.
 * @warning Only one FINALLY block allowed per TRY block.
 * @threadsafe No - operates on thread-local exception stack.
 *
 * Usage:
 *   TRY {
 *     resource = allocate_resource();
 *     // Use resource
 *   } EXCEPT(Some_Exception) {
 *     // Handle exception
 *   } FINALLY {
 *     // Always cleanup
 *     if (resource) free_resource(resource);
 *   } END_TRY;
 *
 * @see TRY macro for starting exception handling.
 * @see EXCEPT macro for catching exceptions.
 * @see END_TRY macro to complete the block.
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
 * Closes the exception handling block and cleans up the exception frame.
 * Re-raises any unhandled exceptions to propagate them up the call stack.
 *
 * @note Must be the final macro in a TRY block sequence.
 * @warning Forgets unhandled exceptions if not used.
 * @threadsafe No - modifies thread-local exception stack.
 *
 * Usage:
 *   TRY {
 *     // Protected code
 *   } EXCEPT(Some_Exception) {
 *     // Exception handler
 *   } FINALLY {
 *     // Cleanup code
 *   } END_TRY;  // Completes the block
 *
 * @see TRY macro for starting exception handling.
 * @see EXCEPT macro for catching exceptions.
 * @see FINALLY macro for cleanup code.
 * @see RERAISE for exception propagation.
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
