/**
 * Except.c - Exception handling implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Thread Safety:
 * This implementation uses thread-local storage (TLS) for the exception stack.
 * On POSIX systems, this requires __thread (C11/GCC extension). On Windows,
 * it uses __declspec(thread). The thread-local storage provides proper memory
 * ordering guarantees - each thread has its own independent exception stack
 * with no cross-thread visibility or synchronization needed.
 *
 * Requirements:
 * - C11 or later, OR
 * - GCC/Clang with __thread support, OR
 * - MSVC with __declspec(thread) support
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Except.h"

#define T Except_T

/* Use thread-local storage for exception stack
 * Each thread has its own exception stack - no synchronization needed */
#ifdef _WIN32
__declspec(thread) Except_Frame *Except_stack = NULL;
#else
__thread Except_Frame *Except_stack = NULL;
#endif

const Except_T Assert_Failed = {"Assertion failed"};

void Except_raise(const T *e, const char *file, int line)
{
    Except_Frame *p;

    /* Runtime check for NULL exception pointer - critical for safety
     * IMPORTANT: Caller must ensure 'e' points to valid memory for the duration
     * of exception propagation. Typically, exceptions are static/global constants
     * (e.g., Socket_Failed) or have thread-local storage duration. Stack-allocated
     * exceptions are unsafe and will cause undefined behavior. */
    if (e == NULL)
    {
        fprintf(stderr, "FATAL: Except_raise called with NULL exception pointer\n");
        fprintf(stderr, "aborting...\n");
        fflush(stderr);
        abort();
    }

    p = Except_stack;
    if (p == NULL)
    {
        fprintf(stderr, "Uncaught exception");
        if (e->reason)
            fprintf(stderr, ": %s", e->reason);
        else
            fprintf(stderr, ": (no reason provided)");

        /* Always include location info for better diagnostics */
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

        fprintf(stderr, "aborting...\n");
        fflush(stderr);
        abort();
    }

    /* Store exception info before modifying stack */
    p->exception = e;
    p->file = file ? file : "unknown";
    p->line = line > 0 ? line : 0;

    /* Pop the exception frame before longjmp */
    Except_stack = p->prev;

    /* Jump directly using the original jmp_buf */
    longjmp(p->env, Except_raised);
}

#undef T
