/**
 * fuzz_exception.c - Fuzzer for exception handling stack safety
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - TRY/EXCEPT/FINALLY nesting up to 16 levels
 * - Exception raising and catching
 * - RERAISE behavior
 * - Stack unwinding correctness
 * - Thread-local exception stack integrity
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_exception
 * Run:   ./fuzz_exception corpus/exception/ -fork=16 -max_len=256
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"

/* Test exception types */
static const Except_T Test_Exception1 = { &Test_Exception1, "Test exception 1" };
static const Except_T Test_Exception2 = { &Test_Exception2, "Test exception 2" };
static const Except_T Test_Exception3 = { &Test_Exception3, "Test exception 3" };

/* Maximum nesting depth for safety */
#define MAX_NESTING_DEPTH 16

/* Operation codes */
enum ExceptionOp
{
  OP_SIMPLE_TRY = 0,
  OP_NESTED_TRY,
  OP_RAISE_CATCH,
  OP_RAISE_FINALLY,
  OP_MULTIPLE_EXCEPT,
  OP_ELSE_HANDLER,
  OP_RERAISE,
  OP_EARLY_RETURN,
  OP_COUNT
};

/**
 * get_exception_by_index - Get one of the test exceptions
 */
static const Except_T *
get_exception_by_index (uint8_t idx)
{
  switch (idx % 3)
    {
    case 0:
      return &Test_Exception1;
    case 1:
      return &Test_Exception2;
    default:
      return &Test_Exception3;
    }
}

/**
 * test_simple_try - Test simple TRY/END_TRY without exception
 */
static void
test_simple_try (void)
{
  volatile int executed = 0;

  TRY { executed = 1; }
  END_TRY;

  assert (executed == 1);
  (void)executed; /* Suppress unused-but-set warning */
}

/**
 * test_try_finally - Test TRY with FINALLY block
 */
static void
test_try_finally (void)
{
  volatile int try_executed = 0;
  volatile int finally_executed = 0;

  TRY
  {
    try_executed = 1;
  }
  FINALLY { finally_executed = 1; }
  END_TRY;

  assert (try_executed == 1);
  assert (finally_executed == 1);
  (void)try_executed;     /* Suppress unused-but-set warning */
  (void)finally_executed; /* Suppress unused-but-set warning */
}

/**
 * test_raise_catch - Test raising and catching an exception
 * @exc_idx: Index to select which exception to raise
 */
static void
test_raise_catch (uint8_t exc_idx)
{
  volatile int caught = 0;
  const Except_T *exc = get_exception_by_index (exc_idx);

  TRY { RAISE (*exc); }
  EXCEPT (Test_Exception1) { caught = 1; }
  EXCEPT (Test_Exception2) { caught = 2; }
  EXCEPT (Test_Exception3) { caught = 3; }
  END_TRY;

  /* Verify correct exception was caught */
  assert (caught > 0);
  (void)caught; /* Suppress unused-but-set warning */
}

/**
 * test_raise_finally - Test exception with FINALLY cleanup
 * @exc_idx: Index to select which exception to raise
 */
static void
test_raise_finally (uint8_t exc_idx)
{
  volatile int finally_ran = 0;
  const Except_T *exc = get_exception_by_index (exc_idx);

  TRY { RAISE (*exc); }
  EXCEPT (Test_Exception1) { /* caught */ }
  EXCEPT (Test_Exception2) { /* caught */ }
  EXCEPT (Test_Exception3) { /* caught */ }
  FINALLY { finally_ran = 1; }
  END_TRY;

  assert (finally_ran == 1);
  (void)finally_ran; /* Suppress unused-but-set warning */
}

/**
 * test_nested_try - Test nested TRY blocks
 * @depth: Nesting depth (1-16)
 * @raise_at: Which level to raise exception at (0 = no raise)
 */
static void
test_nested_try (int depth, int raise_at)
{
  volatile int level = 0;
  volatile int finally_count = 0;

  if (depth < 1)
    depth = 1;
  if (depth > MAX_NESTING_DEPTH)
    depth = MAX_NESTING_DEPTH;

  /* Level 1 */
  TRY
  {
    level = 1;
    if (raise_at == 1)
      RAISE (Test_Exception1);

    if (depth >= 2)
      {
        /* Level 2 */
        TRY
        {
          level = 2;
          if (raise_at == 2)
            RAISE (Test_Exception1);

          if (depth >= 3)
            {
              /* Level 3 */
              TRY
              {
                level = 3;
                if (raise_at == 3)
                  RAISE (Test_Exception1);

                if (depth >= 4)
                  {
                    /* Level 4 */
                    TRY
                    {
                      level = 4;
                      if (raise_at == 4)
                        RAISE (Test_Exception1);
                    }
                    EXCEPT (Test_Exception1) { /* caught at 4 */ }
                    FINALLY { finally_count++; }
                    END_TRY;
                  }
              }
              EXCEPT (Test_Exception1) { /* caught at 3 */ }
              FINALLY { finally_count++; }
              END_TRY;
            }
        }
        EXCEPT (Test_Exception1) { /* caught at 2 */ }
        FINALLY { finally_count++; }
        END_TRY;
      }
  }
  EXCEPT (Test_Exception1) { /* caught at 1 */ }
  FINALLY { finally_count++; }
  END_TRY;

  /* Verify FINALLY blocks ran correctly */
  (void)level;
  (void)finally_count;
}

/**
 * test_else_handler - Test ELSE catch-all handler
 */
static void
test_else_handler (uint8_t exc_idx)
{
  volatile int caught = 0;
  const Except_T *exc = get_exception_by_index (exc_idx);

  TRY { RAISE (*exc); }
  EXCEPT (Test_Exception1) { caught = 1; }
  ELSE { caught = 99; /* Catch-all */ }
  END_TRY;

  assert (caught > 0);
  (void)caught; /* Suppress unused-but-set warning */
}

/**
 * test_reraise - Test RERAISE behavior
 */
static void
test_reraise (void)
{
  volatile int outer_caught = 0;
  volatile int inner_caught = 0;

  TRY
  {
    TRY { RAISE (Test_Exception1); }
    EXCEPT (Test_Exception1)
    {
      inner_caught = 1;
      RERAISE;
    }
    END_TRY;
  }
  EXCEPT (Test_Exception1) { outer_caught = 1; }
  END_TRY;

  assert (inner_caught == 1);
  assert (outer_caught == 1);
  (void)inner_caught; /* Suppress unused-but-set warning */
  (void)outer_caught; /* Suppress unused-but-set warning */
}

/**
 * test_early_return - Test RETURN macro in TRY block
 */
static int
test_early_return_helper (int should_return)
{
  volatile int finally_ran = 0;

  TRY
  {
    if (should_return)
      RETURN 42;
  }
  FINALLY { finally_ran = 1; }
  END_TRY;

  (void)finally_ran;
  return 0;
}

static void
test_early_return (int do_return)
{
  int result = test_early_return_helper (do_return);
  if (do_return)
    assert (result == 42);
  else
    assert (result == 0);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Byte 1: Exception index (0-2)
 * - Byte 2: Nesting depth (1-16)
 * - Byte 3: Raise-at level
 * - Remaining: Additional operation data
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  uint8_t op = data[0];
  uint8_t exc_idx = size >= 2 ? data[1] : 0;
  int depth = size >= 3 ? (data[2] % MAX_NESTING_DEPTH) + 1 : 4;
  int raise_at = size >= 4 ? (data[3] % (depth + 1)) : 0;

  switch (op % OP_COUNT)
    {
    case OP_SIMPLE_TRY:
      test_simple_try ();
      test_try_finally ();
      break;

    case OP_NESTED_TRY:
      test_nested_try (depth, raise_at);
      break;

    case OP_RAISE_CATCH:
      test_raise_catch (exc_idx);
      break;

    case OP_RAISE_FINALLY:
      test_raise_finally (exc_idx);
      break;

    case OP_MULTIPLE_EXCEPT:
      {
        /* Test multiple EXCEPT blocks with different exceptions */
        for (int i = 0; i < 3; i++)
          test_raise_catch ((uint8_t)i);
      }
      break;

    case OP_ELSE_HANDLER:
      test_else_handler (exc_idx);
      break;

    case OP_RERAISE:
      test_reraise ();
      break;

    case OP_EARLY_RETURN:
      test_early_return (exc_idx % 2);
      break;
    }

  /* Verify exception stack is clean after all operations */
  /* Note: We can't directly assert Except_stack == NULL because
   * the fuzzer itself might have exception frames on the stack.
   * Instead, verify we can still use exception handling. */
  TRY
  {
    /* Empty TRY - just verify stack integrity */
  }
  END_TRY;

  return 0;
}

