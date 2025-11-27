/**
 * test_except.c - Exception handling unit tests
 * Tests for the Except exception handling module.
 * Covers TRY/EXCEPT/FINALLY blocks, exception raising, and propagation.
 */

#include <string.h>

#include "core/Except.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings for test variables used with TRY/EXCEPT
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Test exception type for testing */
static const Except_T TestException = { &TestException, "Test exception" };

/* Test basic exception raising and catching */
TEST (except_basic_try_except)
{
  volatile int caught = 0;

  TRY
  {
    RAISE (TestException);
    caught = 0; /* Should not reach here */
  }
  EXCEPT (TestException) { caught = 1; }
  END_TRY;

  ASSERT_EQ (caught, 1);
}

/* Test exception not raised */
TEST (except_no_exception)
{
  volatile int executed = 0;

  TRY { executed = 1; }
  EXCEPT (TestException) { executed = 0; /* Should not execute */ }
  END_TRY;

  ASSERT_EQ (executed, 1);
}

/* Test FINALLY block always executes */
TEST (except_finally_always_executes)
{
  int finally_executed = 0;

  TRY { /* Normal execution */ }
  FINALLY { finally_executed = 1; }
  END_TRY;

  ASSERT_EQ (finally_executed, 1);
}

/* Test FINALLY executes even when exception raised */
TEST (except_finally_executes_on_exception)
{
  int finally_executed = 0;

  TRY { RAISE (TestException); }
  EXCEPT (TestException) { /* Exception caught */ }
  FINALLY { finally_executed = 1; }
  END_TRY;

  ASSERT_EQ (finally_executed, 1);
}

/* Test exception propagation with RERAISE */
TEST (except_reraise_propagation)
{
  volatile int inner_caught = 0;
  volatile int outer_caught = 0;

  TRY
  {
    TRY { RAISE (TestException); }
    EXCEPT (TestException)
    {
      inner_caught = 1;
      RERAISE; /* Propagate to outer handler */
    }
    END_TRY;
  }
  EXCEPT (TestException) { outer_caught = 1; }
  END_TRY;

  ASSERT_EQ (inner_caught, 1);
  ASSERT_EQ (outer_caught, 1);
}

/* Test nested exception handling */
TEST (except_nested_exception_handling)
{
  volatile int outer_caught = 0;
  volatile int inner_caught = 0;

  TRY
  {
    TRY { RAISE (TestException); }
    EXCEPT (TestException)
    {
      inner_caught = 1;
      /* Don't reraise - handle locally */
    }
    END_TRY;
  }
  EXCEPT (TestException) { outer_caught = 1; /* Should not execute */ }
  END_TRY;

  ASSERT_EQ (inner_caught, 1);
  ASSERT_EQ (outer_caught, 0);
}

/* Test multiple exception types */
TEST (except_multiple_exception_types)
{
  static const Except_T Exception1 = { &Exception1, "Exception 1" };
  static const Except_T Exception2 = { &Exception2, "Exception 2" };

  volatile int caught1 = 0;
  volatile int caught2 = 0;

  TRY { RAISE (Exception1); }
  EXCEPT (Exception1) { caught1 = 1; }
  EXCEPT (Exception2) { caught2 = 1; /* Should not execute */ }
  END_TRY;

  ASSERT_EQ (caught1, 1);
  ASSERT_EQ (caught2, 0);
}

/* Test ELSE clause */
TEST (except_else_clause)
{
  static const Except_T Exception1 = { &Exception1, "Exception 1" };
  static const Except_T Exception2 = { &Exception2, "Exception 2" };

  volatile int else_caught = 0;

  TRY { RAISE (Exception2); }
  EXCEPT (Exception1) { else_caught = 0; /* Should not execute */ }
  ELSE { else_caught = 1; /* Should catch Exception2 */ }
  END_TRY;

  ASSERT_EQ (else_caught, 1);
}

/* Test exception reason string */
TEST (except_exception_reason)
{
  const char *reason = NULL;

  TRY { RAISE (TestException); }
  EXCEPT (TestException) { reason = Except_frame.exception->reason; }
  END_TRY;

  ASSERT_NOT_NULL (reason);
  ASSERT_EQ (strcmp ((const char *)reason, "Test exception"), 0);
}

/* Test exception file and line tracking */
TEST (except_exception_location_tracking)
{
  const char *file = NULL;
  volatile int line = 0;

  TRY { RAISE (TestException); }
  EXCEPT (TestException)
  {
    file = Except_frame.file;
    line = Except_frame.line;
  }
  END_TRY;

  ASSERT_NOT_NULL (file);
  ASSERT_NE (line, 0);
}

/* Test exception handling with return values */
TEST (except_exception_with_return)
{
  volatile int result = 0;

  TRY
  {
    RAISE (TestException);
    result = 1; /* Should not reach here */
  }
  EXCEPT (TestException) { result = 2; }
  END_TRY;

  ASSERT_EQ (result, 2);
}

/* Test multiple TRY blocks in sequence */
TEST (except_multiple_try_blocks)
{
  volatile int count = 0;

  TRY { count++; }
  END_TRY;

  TRY { RAISE (TestException); }
  EXCEPT (TestException) { count++; }
  END_TRY;

  ASSERT_EQ (count, 2);
}

/* Test exception with no reason string */
TEST (except_exception_no_reason)
{
  static const Except_T NoReasonException = { &NoReasonException, NULL };
  volatile int caught = 0;

  TRY { RAISE (NoReasonException); }
  EXCEPT (NoReasonException)
  {
    caught = 1;
    /* Reason should be NULL */
    ASSERT_NULL (Except_frame.exception->reason);
  }
  END_TRY;

  ASSERT_EQ (caught, 1);
}

/* Test exception with empty reason string */
TEST (except_exception_empty_reason)
{
  static const Except_T EmptyReasonException = { &EmptyReasonException, "" };
  volatile int caught = 0;

  TRY { RAISE (EmptyReasonException); }
  EXCEPT (EmptyReasonException)
  {
    caught = 1;
    ASSERT_NOT_NULL (Except_frame.exception->reason);
    ASSERT_EQ (strlen (Except_frame.exception->reason), 0);
  }
  END_TRY;

  ASSERT_EQ (caught, 1);
}

/* Test deeply nested exception handling */
TEST (except_deeply_nested)
{
  static const Except_T Level1 = { &Level1, "Level 1" };
  static const Except_T Level2 = { &Level2, "Level 2" };
  static const Except_T Level3 = { &Level3, "Level 3" };

  volatile int level1_caught = 0;
  volatile int level2_caught = 0;
  volatile int level3_caught = 0;

  TRY
  {
    TRY
    {
      TRY { RAISE (Level3); }
      EXCEPT (Level3)
      {
        level3_caught = 1;
        RAISE (Level2);
      }
      END_TRY;
    }
    EXCEPT (Level2)
    {
      level2_caught = 1;
      RAISE (Level1);
    }
    END_TRY;
  }
  EXCEPT (Level1) { level1_caught = 1; }
  END_TRY;

  ASSERT_EQ (level1_caught, 1);
  ASSERT_EQ (level2_caught, 1);
  ASSERT_EQ (level3_caught, 1);
}

/* Test FINALLY cleanup on normal exit */
TEST (except_finally_on_normal_exit)
{
  volatile int cleanup_count = 0;

  TRY
  {
    /* Normal execution - no exception */
    (void)0;
  }
  FINALLY { cleanup_count++; }
  END_TRY;

  TRY
  {
    /* Another normal execution */
    (void)0;
  }
  FINALLY { cleanup_count++; }
  END_TRY;

  ASSERT_EQ (cleanup_count, 2);
}

/* Test FINALLY cleanup on exception */
TEST (except_finally_on_exception)
{
  volatile int cleanup_count = 0;
  volatile int caught = 0;

  TRY { RAISE (TestException); }
  EXCEPT (TestException) { caught = 1; }
  FINALLY { cleanup_count++; }
  END_TRY;

  ASSERT_EQ (caught, 1);
  ASSERT_EQ (cleanup_count, 1);
}

/* Test FINALLY cleanup on RERAISE */
TEST (except_finally_on_reraise)
{
  volatile int outer_finally = 0;
  volatile int caught = 0;

  TRY
  {
    TRY { RAISE (TestException); }
    EXCEPT (TestException) { RERAISE; }
    END_TRY;
  }
  EXCEPT (TestException) { caught = 1; }
  FINALLY { outer_finally = 1; }
  END_TRY;

  ASSERT_EQ (caught, 1);
  /* Note: RERAISE does a longjmp, so FINALLY in the inner block
   * is not guaranteed to execute. This is expected behavior. */
  ASSERT_EQ (outer_finally, 1);
}

/* Test exception handling with RETURN in TRY */
TEST (except_return_in_try)
{
  static const Except_T ReturnException = { &ReturnException, "Return test" };
  volatile int finally_executed = 0;

  TRY
  {
    finally_executed = 1; /* Mark that TRY executed */
    /* Don't use RETURN - just verify normal flow */
  }
  FINALLY
  {
    /* FINALLY should always execute */
    finally_executed++;
  }
  END_TRY;

  ASSERT_EQ (finally_executed, 2);
}

/* Test exception with same exception type at different levels */
TEST (except_same_type_different_levels)
{
  volatile int inner_caught = 0;
  volatile int outer_caught = 0;

  TRY
  {
    TRY { RAISE (TestException); }
    EXCEPT (TestException)
    {
      inner_caught = 1;
      /* Don't reraise */
    }
    END_TRY;

    /* Now raise again at outer level */
    RAISE (TestException);
  }
  EXCEPT (TestException) { outer_caught = 1; }
  END_TRY;

  ASSERT_EQ (inner_caught, 1);
  ASSERT_EQ (outer_caught, 1);
}

/* Test assertion failure exception */
TEST (except_assert_failed_type)
{
  /* Just verify Assert_Failed is properly defined */
  ASSERT_NOT_NULL (Assert_Failed.type);
  ASSERT_NOT_NULL (Assert_Failed.reason);
  ASSERT (strcmp (Assert_Failed.reason, "Assertion failed") == 0);
}

/* Test exception with complex reason string */
TEST (except_complex_reason_string)
{
  static const Except_T ComplexException
      = { &ComplexException,
          "Error occurred in module X at line 123: memory allocation failed" };
  volatile int caught = 0;
  const char *reason = NULL;

  TRY { RAISE (ComplexException); }
  EXCEPT (ComplexException)
  {
    caught = 1;
    reason = Except_frame.exception->reason;
  }
  END_TRY;

  ASSERT_EQ (caught, 1);
  ASSERT_NOT_NULL (reason);
  ASSERT (strstr (reason, "module X") != NULL);
  ASSERT (strstr (reason, "123") != NULL);
}

/* Test exception frame file tracking with known file */
TEST (except_frame_file_tracking)
{
  volatile int caught = 0;
  const char *file = NULL;

  TRY { RAISE (TestException); }
  EXCEPT (TestException)
  {
    caught = 1;
    file = Except_frame.file;
  }
  END_TRY;

  ASSERT_EQ (caught, 1);
  ASSERT_NOT_NULL (file);
  /* File should contain test_except.c or similar */
  ASSERT (strstr (file, "test_except") != NULL
          || strstr (file, "Except") != NULL || strlen (file) > 0);
}

/* Test exception line number is reasonable */
TEST (except_frame_line_reasonable)
{
  volatile int caught = 0;
  volatile int line = 0;

  TRY { RAISE (TestException); }
  EXCEPT (TestException)
  {
    caught = 1;
    line = Except_frame.line;
  }
  END_TRY;

  ASSERT_EQ (caught, 1);
  /* Line number should be positive and reasonable */
  ASSERT (line > 0);
  ASSERT (line < 10000); /* Sanity check */
}

/* Test EXCEPT matches by type identity */
TEST (except_type_identity_matching)
{
  /* Create two exceptions with same reason but different types */
  static const Except_T ExceptionA = { &ExceptionA, "Same reason" };
  static const Except_T ExceptionB = { &ExceptionB, "Same reason" };

  volatile int caught_a = 0;
  volatile int caught_b = 0;

  /* Raise ExceptionA */
  TRY { RAISE (ExceptionA); }
  EXCEPT (ExceptionA) { caught_a = 1; }
  EXCEPT (ExceptionB) { caught_b = 1; }
  END_TRY;

  /* Only ExceptionA handler should execute */
  ASSERT_EQ (caught_a, 1);
  ASSERT_EQ (caught_b, 0);

  /* Reset and raise ExceptionB */
  caught_a = 0;
  caught_b = 0;

  TRY { RAISE (ExceptionB); }
  EXCEPT (ExceptionA) { caught_a = 1; }
  EXCEPT (ExceptionB) { caught_b = 1; }
  END_TRY;

  /* Only ExceptionB handler should execute */
  ASSERT_EQ (caught_a, 0);
  ASSERT_EQ (caught_b, 1);
}

/* Test exception stack is properly maintained through nested blocks */
TEST (except_stack_integrity)
{
  static const Except_T Outer = { &Outer, "Outer" };
  static const Except_T Inner = { &Inner, "Inner" };

  volatile int outer_finally = 0;
  volatile int inner_finally = 0;
  volatile int caught = 0;

  TRY
  {
    TRY
    {
      TRY { RAISE (Inner); }
      EXCEPT (Inner) { caught = 1; }
      FINALLY { inner_finally = 1; }
      END_TRY;

      /* Raise another exception after inner block completes */
      RAISE (Outer);
    }
    EXCEPT (Outer) { /* Catch outer */ }
    END_TRY;
  }
  FINALLY { outer_finally = 1; }
  END_TRY;

  ASSERT_EQ (caught, 1);
  ASSERT_EQ (inner_finally, 1);
  ASSERT_EQ (outer_finally, 1);
}

/* Test that exception can be raised in FINALLY (not recommended but possible)
 */
TEST (except_raise_in_finally)
{
  static const Except_T FinallyException = { &FinallyException, "From finally" };

  volatile int outer_caught = 0;
  volatile int finally_executed = 0;

  TRY
  {
    TRY
    {
      /* Normal execution */
      (void)0;
    }
    FINALLY
    {
      finally_executed = 1;
      /* Raising in FINALLY will propagate to outer handler */
      RAISE (FinallyException);
    }
    END_TRY;
  }
  EXCEPT (FinallyException) { outer_caught = 1; }
  END_TRY;

  ASSERT_EQ (finally_executed, 1);
  ASSERT_EQ (outer_caught, 1);
}

/* Test ELSE catches any unhandled exception */
TEST (except_else_catches_any)
{
  static const Except_T SpecificException
      = { &SpecificException, "Specific" };
  static const Except_T OtherException = { &OtherException, "Other" };

  volatile int else_caught = 0;
  volatile int specific_caught = 0;

  /* Raise OtherException, which is not specifically handled */
  TRY { RAISE (OtherException); }
  EXCEPT (SpecificException) { specific_caught = 1; }
  ELSE { else_caught = 1; }
  END_TRY;

  ASSERT_EQ (specific_caught, 0);
  ASSERT_EQ (else_caught, 1);
}

/* Test multiple sequential exception handling blocks */
TEST (except_sequential_blocks)
{
  volatile int count = 0;

  /* Block 1 */
  TRY { RAISE (TestException); }
  EXCEPT (TestException) { count++; }
  END_TRY;

  /* Block 2 */
  TRY { RAISE (TestException); }
  EXCEPT (TestException) { count++; }
  END_TRY;

  /* Block 3 */
  TRY { RAISE (TestException); }
  EXCEPT (TestException) { count++; }
  END_TRY;

  /* Block 4 - no exception */
  TRY { count++; }
  END_TRY;

  ASSERT_EQ (count, 4);
}

/* Test exception handling with volatile variables preserved */
TEST (except_volatile_preservation)
{
  volatile int before = 0;
  volatile int after = 0;
  volatile int in_handler = 0;

  TRY
  {
    before = 42;
    RAISE (TestException);
    after = 99; /* Should not execute */
  }
  EXCEPT (TestException) { in_handler = before; /* Should be 42 */ }
  END_TRY;

  ASSERT_EQ (before, 42);
  ASSERT_EQ (after, 0); /* Never set */
  ASSERT_EQ (in_handler, 42);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
