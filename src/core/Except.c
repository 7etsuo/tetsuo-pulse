/**
 * Except.c - Exception handling implementation
 * Thread Safety:
 * This implementation uses thread-local storage (TLS) for the exception stack.
 * On POSIX systems, this requires __thread (C11/GCC extension). On Windows,
 * it uses __declspec(thread). The thread-local storage provides proper memory
 * ordering guarantees - each thread has its own independent exception stack
 * with no cross-thread visibility or synchronization needed.
 * Requirements:
 * - C11 or later, OR
 * - GCC/Clang with __thread support, OR
 * - MSVC with __declspec(thread) support
 * Security Notes:
 * - Thread-local exception stack prevents race conditions in multithreaded code
 * - NULL exception pointer validation prevents undefined behavior
 * - Uses abort() for fatal errors (uncaught exceptions) - appropriate for safety
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"

#define T Except_T

/* Use thread-local storage for exception stack
 * Each thread has its own exception stack - no synchronization needed */
#ifdef _WIN32
__declspec(thread) Except_Frame *Except_stack = NULL;
#else
__thread Except_Frame *Except_stack = NULL;
#endif

const Except_T Assert_Failed = {"Assertion failed"};

/**
 * except_validate_pointer - Validate exception pointer is not NULL
 * @e: Exception pointer to validate
 */
static void except_validate_pointer(const T *e)
{
    if (e == NULL)
    {
        fprintf(stderr, "FATAL: Except_raise called with NULL exception pointer\n");
        fprintf(stderr, "This indicates a programming error in exception usage\n");
        fprintf(stderr, "aborting...\n");
        fflush(stderr);
        abort();
    }
}

/**
 * except_print_reason - Print exception reason to stderr
 * @e: Exception with reason to print
 */
static void except_print_reason(const T *e)
{
    if (e->reason)
        fprintf(stderr, ": %s", e->reason);
    else
        fprintf(stderr, ": (no reason provided)");
}

/**
 * except_print_location - Print exception location information
 * @file: Source file (may be NULL)
 * @line: Line number (may be 0)
 */
static void except_print_location(const char *file, int line)
{
    if (file)
    {
        if (line > 0)
            fprintf(stderr, " raised at %s:%d\n", file, line);
        else
            fprintf(stderr, " raised at %s\n", file);
    }
    else if (line > 0)
    {
        fprintf(stderr, " raised at line %d\n", line);
    }
    else
    {
        fprintf(stderr, " (location unknown)\n");
    }
}

/**
 * except_handle_uncaught - Handle uncaught exception by printing and aborting
 * @e: Exception that was uncaught
 * @file: Source file where exception was raised
 * @line: Line number where exception was raised
 */
static void except_handle_uncaught(const T *e, const char *file, int line)
{
    fprintf(stderr, "Uncaught exception");
    except_print_reason(e);
    except_print_location(file, line);
    fprintf(stderr, "aborting...\n");
    fflush(stderr);
    abort();
}

/**
 * except_store_in_frame - Store exception info in current frame
 * @p: Exception frame to store info in
 * @e: Exception to store
 * @file: Source file location
 * @line: Line number location
 */
static void except_store_in_frame(Except_Frame *p, const T *e, const char *file, int line)
{
    p->exception = e;
    p->file = file ? file : "unknown";
    p->line = line > 0 ? line : 0;
}

/**
 * except_unwind_stack - Unwind exception stack by popping current frame
 * @p: Current exception frame
 */
static void except_unwind_stack(Except_Frame *p)
{
    Except_stack = p->prev;
}

/**
 * except_perform_jump - Perform non-local jump to exception handler
 * @p: Exception frame containing jump buffer
 */
static void except_perform_jump(Except_Frame *p)
{
    /* Cast jmp_buf to non-volatile for longjmp - jmp_buf array is already saved */
    jmp_buf *env_ptr = (jmp_buf *)&p->env;
    longjmp(*env_ptr, Except_raised);
}

/**
 * Except_raise - Raise an exception with location information
 * @e: Exception to raise (must not be NULL)
 * @file: Source file where exception was raised (may be NULL)
 * @line: Line number where exception was raised (may be 0)
 * Raises an exception by performing a non-local jump to the nearest exception
 * handler. The exception stack must be properly set up by TRY blocks.
 * Thread Safety: Thread-safe due to thread-local exception stack.
 * No synchronization needed between threads.
 * Security: Validates NULL exception pointer to prevent undefined behavior.
 * Uses abort() for uncaught exceptions (appropriate for fatal errors).
 */
void
Except_raise(const T *e, const char *file, int line)
{
    /* Read Except_stack into local variable - ensures we get current value */
    volatile Except_Frame *volatile_p = Except_stack;
    Except_Frame *p = (Except_Frame *)volatile_p;

    except_validate_pointer(e);

    if (p == NULL)
        except_handle_uncaught(e, file, line);

    except_store_in_frame(p, e, file, line);
    except_unwind_stack(p);
    except_perform_jump(p);
}

#undef T
