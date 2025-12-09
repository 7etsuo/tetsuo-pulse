/**
 * Except.c - Exception handling implementation
 *
 * Part of the Socket Library
 *
 * This module provides a structured exception handling mechanism for C,
 * enabling non-local jumps with proper cleanup semantics via TRY/EXCEPT/
 * FINALLY/END_TRY macros defined in Except.h.
 *
 * THREAD SAFETY:
 * Uses thread-local storage (TLS) for the exception stack. Each thread
 * maintains its own independent exception stack with no cross-thread
 * visibility or synchronization needed. The TLS provides proper memory
 * ordering guarantees.
 *
 * REQUIREMENTS:
 * - C11 or later, OR
 * - GCC/Clang with __thread support, OR
 * - MSVC with __declspec(thread) support
 *
 * SECURITY:
 * - Thread-local exception stack prevents race conditions
 * - NULL exception pointer validation prevents undefined behavior
 * - Uses abort() for uncaught exceptions (fail-fast for safety)
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/Except.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** Default string for unknown file locations */
#define EXCEPT_UNKNOWN_FILE "unknown"

/** Format string for uncaught exception header */
#define EXCEPT_UNCAUGHT_FMT "Uncaught exception"

/** Format string for NULL pointer error */
#define EXCEPT_NULL_PTR_FMT                                                   \
  "FATAL: Except_raise called with NULL exception pointer"

/** Format string for programming error hint */
#define EXCEPT_PROG_ERROR_FMT                                                 \
  "This indicates a programming error in exception usage"

/** Abort message */
#define EXCEPT_ABORTING_FMT "aborting..."

/* ============================================================================
 * Thread-Local Storage
 * ============================================================================
 */

/**
 * Thread-local exception stack
 *
 * Each thread maintains its own exception stack. No synchronization is
 * needed between threads since each thread has independent storage.
 */
#ifdef _WIN32
__declspec (thread) Except_Frame *Except_stack = NULL;
#else
__thread Except_Frame *Except_stack = NULL;
#endif

/* ============================================================================
 * Global Exception Types
 * ============================================================================
 */

/** Built-in assertion failure exception */
const Except_T Assert_Failed = { &Assert_Failed, "Assertion failed" };

/* ============================================================================
 * Static Helper Functions - Output
 * ============================================================================
 */

/**
 * except_flush_stderr - Flush stderr and ensure output is written
 *
 * Thread-safe: Yes (stderr is thread-safe per POSIX)
 *
 * Used before abort() to ensure error messages are visible.
 */
static void
except_flush_stderr (void)
{
  fflush (stderr);
}

/**
 * except_emit_fatal - Emit a fatal error message to stderr
 * @message: Message to emit (must not be NULL)
 *
 * Thread-safe: Yes
 *
 * Writes message to stderr followed by newline.
 */
static void
except_emit_fatal (const char *message)
{
  assert (message != NULL);
  fprintf (stderr, "%s\n", message);
}

/**
 * except_emit_reason - Write exception reason to stderr
 * @e: Exception with reason to print
 *
 * Thread-safe: Yes
 *
 * Outputs ": <reason>" or ": (no reason provided)" if reason is NULL.
 */
static void
except_emit_reason (const Except_T *e)
{
  assert (e != NULL);

  fprintf (stderr, ": %s",
           e->reason != NULL ? e->reason : "(no reason provided)");
}

/**
 * except_emit_location - Write source location to stderr
 * @file: Source file (may be NULL)
 * @line: Line number (may be 0 if unknown)
 *
 * Thread-safe: Yes
 *
 * Outputs location in format " raised at file:line\n" with graceful
 * degradation when file or line is unavailable.
 */
static void
except_emit_location (const char *file, int line)
{
  if (file != NULL)
    {
      fprintf (stderr, " raised at %s", file);
      if (line > 0)
        fprintf (stderr, ":%d\n", line);
      else
        fprintf (stderr, "\n");
    }
  else if (line > 0)
    {
      fprintf (stderr, " raised at line %d\n", line);
    }
  else
    {
      fprintf (stderr, " (location unknown)\n");
    }
}

/**
 * except_finish_abort - Final steps for exception abort paths
 *
 * Emits "aborting..." message, flushes stderr, and aborts the program.
 * Used by multiple fatal error handlers to avoid code duplication.
 *
 * This function does not return.
 *
 * Thread-safe: Yes
 *
 * Security: Ensures diagnostic messages are visible before termination.
 */
static void
except_finish_abort (void)
{
  except_emit_fatal (EXCEPT_ABORTING_FMT);
  except_flush_stderr ();
  abort ();
}

/* ============================================================================
 * Static Helper Functions - Validation
 * ============================================================================
 */

/**
 * except_validate_not_null - Validate exception pointer is not NULL
 * @e: Exception pointer to validate
 *
 * If the pointer is NULL, prints error message and aborts. This is a
 * programming error that cannot be recovered from.
 *
 * Thread-safe: Yes
 */
static void
except_validate_not_null (const Except_T *e)
{
  if (e != NULL)
    return;

  except_emit_fatal (EXCEPT_NULL_PTR_FMT);
  except_emit_fatal (EXCEPT_PROG_ERROR_FMT);
  except_finish_abort ();
}

/* ============================================================================
 * Static Helper Functions - Uncaught Handling
 * ============================================================================
 */

/**
 * except_abort_uncaught - Handle uncaught exception by aborting
 * @e: Exception that was uncaught
 * @file: Source file where exception was raised
 * @line: Line number where exception was raised
 *
 * Prints diagnostic information and aborts. This function does not return.
 *
 * Thread-safe: Yes
 */
static void
except_abort_uncaught (const Except_T *e, const char *file, int line)
{
  fprintf (stderr, "%s", EXCEPT_UNCAUGHT_FMT);
  except_emit_reason (e);
  except_emit_location (file, line);
  except_finish_abort ();
}

/* ============================================================================
 * Static Helper Functions - Frame Management
 * ============================================================================
 */

/**
 * except_store_exception - Store exception info in current frame
 * @frame: Exception frame to store info in (must not be NULL)
 * @e: Exception to store (must not be NULL)
 * @file: Source file location (may be NULL)
 * @line: Line number location (may be 0)
 *
 * Thread-safe: Yes (operates on caller's frame)
 */
static void
except_store_exception (Except_Frame *frame, const Except_T *e,
                        const char *file, int line)
{
  assert (frame != NULL);
  assert (e != NULL);

  frame->exception = e;
  frame->file = (file != NULL) ? file : EXCEPT_UNKNOWN_FILE;
  frame->line = (line > 0) ? line : 0;
}

/**
 * except_pop_frame - Unwind exception stack by popping current frame
 * @frame: Current exception frame to pop
 *
 * Updates the thread-local exception stack to point to the previous frame.
 *
 * Thread-safe: Yes (thread-local storage)
 */
/**
 * except_pop_frame - Unwind exception stack by popping current frame
 * @frame: Current exception frame to pop (must not be NULL)
 *
 * Updates the thread-local exception stack to point to the previous frame.
 * Called during exception unwinding before jumping to handler.
 *
 * Returns: void
 * Thread-safe: Yes (thread-local storage)
 */
static void
except_pop_frame (Except_Frame *frame)
{
  assert (frame != NULL);
  Except_stack = frame->prev;
}

/**
 * except_jump_to_handler - Perform non-local jump to exception handler
 * @frame: Exception frame containing jump buffer
 *
 * This function does not return - it performs a longjmp to the TRY block.
 *
 * Thread-safe: Yes (operates on caller's frame)
 */
/**
 * except_jump_to_handler - Perform non-local jump to exception handler
 * @frame: Exception frame containing jump buffer (must not be NULL)
 *
 * This function does not return - it performs a longjmp to the TRY block
 * with value Except_raised (1) to indicate exception was raised.
 *
 * Returns: Does not return
 * Raises: longjmp(Except_raised) to nearest TRY handler
 * Thread-safe: Yes (operates on caller's frame and thread-local stack)
 *
 * Note: Casting away volatile is safe because setjmp already saved the
 * environment contents non-volatily in the frame.
 */
static void
except_jump_to_handler (Except_Frame *frame)
{
  jmp_buf *env_ptr;

  assert (frame != NULL);

  /* Cast away volatile - jmp_buf contents already saved by setjmp */
  env_ptr = (jmp_buf *)&frame->env;
  longjmp (*env_ptr, Except_raised);
}

/* ============================================================================
 * Public Functions
 * ============================================================================
 */

/**
 * Except_raise - Raise an exception with location information
 * @e: Exception to raise (must not be NULL)
 * @file: Source file where exception was raised (may be NULL)
 * @line: Line number where exception was raised (may be 0)
 *
 * Raises an exception by performing a non-local jump to the nearest
 * exception handler. The exception stack must be properly set up by
 * TRY blocks.
 *
 * If no handler exists (Except_stack is NULL), this function prints
 * diagnostic information and calls abort(). This is the correct behavior
 * for uncaught exceptions - fail-fast rather than continue with undefined
 * state.
 *
 * Returns: Does not return (either jumps to handler or aborts)
 *
 * Raises: Performs longjmp to TRY block, or aborts if uncaught
 *
 * Thread-safe: Yes - uses thread-local exception stack with no shared
 *              state between threads.
 *
 * Security: Validates NULL exception pointer to prevent undefined behavior.
 *           Uses abort() for uncaught exceptions (fail-fast for safety).
 */
void
Except_raise (const Except_T *e, const char *file, int line)
{
  Except_Frame *frame;

  except_validate_not_null (e);

  frame = Except_stack;

  if (frame == NULL)
    except_abort_uncaught (e, file, line);

  except_store_exception (frame, e, file, line);
  except_pop_frame (frame);
  except_jump_to_handler (frame);
}
