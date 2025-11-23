#ifndef EXCEPT_INCLUDED
#define EXCEPT_INCLUDED

#include <setjmp.h>

/**
 * Exception Handling for C
 *
 * IMPORTANT: Do NOT compile with -DNDEBUG in production code. The exception
 * system relies on runtime checks that are critical for safety. While assert()
 * statements will be disabled, the explicit NULL checks will remain active.
 *
 * This module provides structured exception handling similar to try/catch
 * in other languages. It uses setjmp/longjmp for non-local control flow.
 * Features:
 * - TRY/EXCEPT/FINALLY blocks
 * - Thread-safe implementation (thread-local exception stack)
 * - Named exceptions with reason strings
 * - Exception propagation with RERAISE
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
 */

typedef struct Except_T {
  const struct Except_T *type;
  const char *reason; /**< Human-readable error description */
} Except_T;

typedef struct Except_Frame Except_Frame;
struct Except_Frame
{
  Except_Frame *prev;
  jmp_buf env;
  const char *file;
  int line;
  const Except_T *exception;
};

enum
{
  Except_entered = 0,
  Except_raised,
  Except_handled,
  Except_finalized
};

/* Thread-local exception stack */
#ifdef _WIN32
extern __declspec (thread) Except_Frame *Except_stack;
#else
extern __thread Except_Frame *Except_stack;
#endif
extern const Except_T Assert_Failed;

void Except_raise (const Except_T *e, const char *file, int line);

#define RAISE(e) Except_raise (&(e), __FILE__, __LINE__)
#define RERAISE                                                               \
  Except_raise ((const Except_T *)Except_frame.exception, Except_frame.file,  \
                Except_frame.line)

/**
 * RETURN macro - Returns from function while cleaning up exception stack
 * WARNING: This macro uses the comma operator to modify Except_stack as a side
 * effect before returning. This is intentional but subtle. Use only within
 * TRY blocks when you need to return early while properly cleaning up the
 * exception stack.
 * The switch/default pattern is necessary because:
 * 1. The comma operator evaluates left-to-right: (expr1, expr2) evaluates
 * expr1, discards result, evaluates expr2, returns result of expr2.
 * 2. switch(expr1, 0) executes the assignment, then switches on 0.
 * 3. default: always matches, allowing "return" to work as a statement.
 * 4. This prevents issues with return values containing commas (e.g., function
 * calls).
 * Usage examples:
 *   RETURN;              // For void functions
 *   RETURN value;        // For functions returning a value
 *   RETURN func(a, b);   // Works with function calls containing commas
 */
#define RETURN                                                                \
  switch (Except_stack = ((Except_Frame *)Except_stack)->prev, 0)             \
  default:                                                                    \
    return

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

#define EXCEPT(e)                                                             \
  if (Except_flag == Except_entered)                                          \
    {                                                                         \
      Except_Frame *prev_frame = NULL;                                        \
      if (Except_stack != NULL)                                               \
        prev_frame = Except_stack->prev;                                      \
      Except_stack = prev_frame;                                              \
    }                                                                         \
  }                                                                           \
  else if (Except_frame.exception && Except_frame.exception->type == &(e)) \
  {                                                                           \
    Except_flag = Except_handled;

#define ELSE                                                                  \
  if (Except_flag == Except_entered)                                          \
    {                                                                         \
      Except_Frame *prev_frame = NULL;                                        \
      if (Except_stack != NULL)                                               \
        prev_frame = Except_stack->prev;                                      \
      Except_stack = prev_frame;                                              \
    }                                                                         \
  }                                                                           \
  else                                                                        \
  {                                                                           \
    Except_flag = Except_handled;

#define FINALLY                                                               \
  if (Except_flag == Except_entered)                                          \
    {                                                                         \
      Except_Frame *prev_frame = NULL;                                        \
      if (Except_stack != NULL)                                               \
        prev_frame = Except_stack->prev;                                      \
      Except_stack = prev_frame;                                              \
    }                                                                         \
  }                                                                           \
  {                                                                           \
    if (Except_flag == Except_entered)                                        \
      Except_flag = Except_finalized;

#define END_TRY                                                               \
  if (Except_flag == Except_entered)                                          \
    {                                                                         \
      Except_Frame *prev_frame = NULL;                                        \
      if (Except_stack != NULL)                                               \
        prev_frame = Except_stack->prev;                                      \
      Except_stack = prev_frame;                                              \
    }                                                                         \
  }                                                                           \
  if (Except_flag == Except_raised)                                           \
    RERAISE;                                                                  \
  }                                                                           \
  while (0)

#undef T
#endif
