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
 * Provides try/catch/finally semantics using setjmp/longjmp. Each thread
 * maintains an independent exception stack for concurrent operations.
 *
 * ## Usage
 *
 * @code{.c}
 * extern const Except_T MyError;
 *
 * void example(void) {
 *   TRY {
 *     if (failure) RAISE(MyError);
 *   } EXCEPT(MyError) {
 *     fprintf(stderr, "Error: %s\n", Except_frame.exception->reason);
 *   } FINALLY {
 *     cleanup();
 *   } END_TRY;
 * }
 * @endcode
 *
 * @note Variables modified in TRY blocks must be volatile to survive longjmp.
 * @warning Avoid setjmp/longjmp in signal handlers.
 */

/**
 * @brief Exception payload with type identifier and description.
 *
 * Define module exceptions as: `const Except_T MyError = { &BaseType, "reason"
 * };`
 */
typedef struct Except_T
{
  const struct Except_T *type; /**< Exception type for matching in EXCEPT */
  const char *reason;          /**< Human-readable error description */
} Except_T;

/**
 * @brief Stack frame for exception handling context.
 *
 * Managed by TRY/END_TRY macros. Access Except_frame.exception in handlers.
 */
typedef struct Except_Frame Except_Frame;
struct Except_Frame
{
  Except_Frame *prev;        /**< Previous frame in stack */
  jmp_buf env;               /**< setjmp/longjmp context */
  const char *file;          /**< Source file of RAISE */
  int line;                  /**< Source line of RAISE */
  const Except_T *exception; /**< Raised exception */
};

/** Exception handling states (internal use) */
enum
{
  Except_entered = 0, /**< TRY block entered */
  Except_raised,      /**< Exception raised */
  Except_handled,     /**< Exception handled */
  Except_finalized    /**< FINALLY executed */
};

/** Thread-local exception stack head */
#ifdef _WIN32
extern __declspec (thread) Except_Frame *Except_stack;
#else
extern __thread Except_Frame *Except_stack;
#endif

/** Base exception for assertion failures */
extern const Except_T Assert_Failed;

#ifdef TESTING
/**
 * @brief Test-only wrapper for except_basename (internal testing).
 *
 * Exposes the static except_basename function for unit testing.
 * Only available when compiled with -DTESTING flag.
 *
 * @param path File path to extract basename from
 * @return Basename of path, or "unknown" if path is NULL
 */
extern const char *except_basename_test_wrapper (const char *path);
#endif

/**
 * @brief Raise an exception (internal - use RAISE macro).
 *
 * Performs longjmp to nearest TRY block. Does not return.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
extern _Noreturn void
Except_raise (const Except_T *e, const char *file, int line);
#elif defined(__GNUC__) || defined(__clang__)
extern void Except_raise (const Except_T *e, const char *file, int line)
    __attribute__ ((noreturn));
#elif defined(_MSC_VER)
extern __declspec (noreturn) void
Except_raise (const Except_T *e, const char *file, int line);
#else
extern void Except_raise (const Except_T *e, const char *file, int line);
#endif

/** Raise exception with file/line info */
#define RAISE(e) Except_raise (&(e), __FILE__, __LINE__)

/** Re-raise current exception to outer handler */
#define RERAISE                                           \
  Except_raise ((const Except_T *)Except_frame.exception, \
                Except_frame.file,                        \
                Except_frame.line)

/** Return from function, cleaning up exception stack */
#define RETURN                                                    \
  switch (Except_stack = ((Except_Frame *)Except_stack)->prev, 0) \
  default:                                                        \
    return

/* Internal: pop frame if entered normally */
#define EXCEPT_POP_FRAME_IF_ENTERED      \
  if (Except_flag == Except_entered)     \
    {                                    \
      Except_Frame *prev_frame = NULL;   \
      if (Except_stack != NULL)          \
        prev_frame = Except_stack->prev; \
      Except_stack = prev_frame;         \
    }

/**
 * @brief Begin exception handling block.
 *
 * Use volatile for variables modified in TRY that are read after exception.
 */
#define TRY                                            \
  do                                                   \
    {                                                  \
      volatile int Except_flag;                        \
      volatile Except_Frame Except_frame;              \
      jmp_buf *env_ptr = (jmp_buf *)&Except_frame.env; \
      Except_frame.prev = Except_stack;                \
      Except_frame.file = NULL;                        \
      Except_frame.line = 0;                           \
      Except_frame.exception = NULL;                   \
      Except_stack = (Except_Frame *)&Except_frame;    \
      Except_flag = setjmp (*env_ptr);                 \
      if (Except_flag == Except_entered)               \
        {
/** Catch specific exception type */
#define EXCEPT(e)                                                          \
  EXCEPT_POP_FRAME_IF_ENTERED                                              \
  }                                                                        \
  else if (Except_frame.exception && Except_frame.exception->type == &(e)) \
  {                                                                        \
    Except_flag = Except_handled;

/** Catch any unhandled exception */
#define ELSE                  \
  EXCEPT_POP_FRAME_IF_ENTERED \
  }                           \
  else                        \
  {                           \
    Except_flag = Except_handled;

/** Cleanup block - always executes */
#define FINALLY                        \
  EXCEPT_POP_FRAME_IF_ENTERED          \
  }                                    \
  {                                    \
    if (Except_flag == Except_entered) \
      Except_flag = Except_finalized;

/** End exception block, re-raise if unhandled */
#define END_TRY                     \
  EXCEPT_POP_FRAME_IF_ENTERED       \
  }                                 \
  if (Except_flag == Except_raised) \
    RERAISE;                        \
  }                                 \
  while (0)

#undef T
#endif
