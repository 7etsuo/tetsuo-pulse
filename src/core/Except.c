/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */



#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/Except.h"

/* Mark function as never returning */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define EXCEPT_NORETURN _Noreturn
#elif defined(__GNUC__) || defined(__clang__)
#define EXCEPT_NORETURN __attribute__ ((noreturn))
#elif defined(_MSC_VER)
#define EXCEPT_NORETURN __declspec (noreturn)
#else
#define EXCEPT_NORETURN
#endif

/* Mark function as unlikely to be called */
#if defined(__GNUC__) || defined(__clang__)
#define EXCEPT_COLD __attribute__ ((cold))
#else
#define EXCEPT_COLD
#endif

/* Mark pointer parameters as non-null */
#if defined(__GNUC__) || defined(__clang__)
#define EXCEPT_NONNULL(...) __attribute__ ((nonnull (__VA_ARGS__)))
#else
#define EXCEPT_NONNULL(...)
#endif

#define EXCEPT_UNKNOWN_FILE "unknown"

/* In release builds, only log basename to prevent leaking directory structure */
#ifndef SOCKET_EXCEPT_VERBOSE_UNCAUGHT
#ifdef NDEBUG
#define SOCKET_EXCEPT_VERBOSE_UNCAUGHT 0
#else
#define SOCKET_EXCEPT_VERBOSE_UNCAUGHT 1
#endif
#endif

#define EXCEPT_UNCAUGHT_FMT "Uncaught exception"
#define EXCEPT_NULL_PTR_FMT                                                   \
  "FATAL: Except_raise called with NULL exception pointer"
#define EXCEPT_PROG_ERROR_FMT                                                 \
  "This indicates a programming error in exception usage"
#define EXCEPT_ABORTING_FMT "aborting..."

/* Thread-local exception stack - each thread maintains its own */
#ifdef _WIN32
__declspec (thread) Except_Frame *Except_stack = NULL;
#else
__thread Except_Frame *Except_stack = NULL;
#endif

const Except_T Assert_Failed = { &Assert_Failed, "Assertion failed" };

static inline void
except_flush_stderr (void)
{
  fflush (stderr);
}

EXCEPT_NONNULL (1)
static void
except_emit_fatal (const char *message)
{
  assert (message != NULL);
  fprintf (stderr, "%s\n", message);
}

EXCEPT_NONNULL (1)
static void
except_emit_reason (const Except_T *e)
{
  assert (e != NULL);
  fprintf (stderr, ": %s",
           e->reason != NULL ? e->reason : "(no reason provided)");
}

/* Extract filename from full path to prevent leaking directory structure */
static const char *
except_basename (const char *path)
{
  const char *last_sep = NULL;
  const char *p;

  if (path == NULL)
    return EXCEPT_UNKNOWN_FILE;

  for (p = path; *p != '\0'; p++)
    {
      if (*p == '/' || *p == '\\')
        last_sep = p;
    }

  return (last_sep != NULL) ? (last_sep + 1) : path;
}

static void
except_emit_location (const char *file, int line)
{
#if SOCKET_EXCEPT_VERBOSE_UNCAUGHT
  const char *display_file = file;
#else
  const char *display_file = except_basename (file);
#endif

  if (display_file != NULL && line > 0)
    fprintf (stderr, " raised at %s:%d\n", display_file, line);
  else if (display_file != NULL)
    fprintf (stderr, " raised at %s\n", display_file);
  else if (line > 0)
    fprintf (stderr, " raised at line %d\n", line);
  else
    fprintf (stderr, " (location unknown)\n");
}

EXCEPT_COLD EXCEPT_NORETURN static void
except_finish_abort (void)
{
  except_emit_fatal (EXCEPT_ABORTING_FMT);
  except_flush_stderr ();
  abort ();
}


EXCEPT_COLD static void
except_validate_not_null (const Except_T *e)
{
  if (e != NULL)
    return;

  except_emit_fatal (EXCEPT_NULL_PTR_FMT);
  except_emit_fatal (EXCEPT_PROG_ERROR_FMT);
  except_finish_abort ();
}


EXCEPT_COLD EXCEPT_NORETURN EXCEPT_NONNULL (1)
static void
except_abort_uncaught (const Except_T *e, const char *file, int line)
{
  fprintf (stderr, "%s", EXCEPT_UNCAUGHT_FMT);
  except_emit_reason (e);
  except_emit_location (file, line);
  except_finish_abort ();
}

EXCEPT_NONNULL (1, 2)
static inline void
except_store_exception (Except_Frame *frame, const Except_T *e,
                        const char *file, int line)
{
  assert (frame != NULL);
  assert (e != NULL);

  frame->exception = e;
  frame->file = (file != NULL) ? file : EXCEPT_UNKNOWN_FILE;
  frame->line = (line > 0) ? line : 0;
}

EXCEPT_NONNULL (1)
static inline void
except_pop_frame (Except_Frame *frame)
{
  assert (frame != NULL);
  Except_stack = frame->prev;
}

EXCEPT_NORETURN EXCEPT_NONNULL (1)
static void
except_jump_to_handler (Except_Frame *frame)
{
  assert (frame != NULL);

  /* Cast away volatile - jmp_buf contents already saved by setjmp */
  longjmp (*(jmp_buf *)&frame->env, Except_raised);
}

EXCEPT_NORETURN void
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
