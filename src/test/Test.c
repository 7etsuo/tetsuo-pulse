/**
 * @file Test.c
 * @brief Implementation of the exception-based test framework.
 * @ingroup test_framework
 *
 * Provides the core implementation of the test framework including test registration,
 * execution, failure reporting, and result tracking. Designed to work with the
 * exception-based error handling system for robust test cleanup.
 *
 * @see Test.h for the public API.
 * @see @ref foundation for exception handling infrastructure.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "test/Test.h"

#define T Test_T

/* Test function structure */
struct TestFunction
{
  const char *name;
  void (*func) (void);
  struct TestFunction *next;
};

/* Test registry - linked list of test functions */
static struct TestFunction *test_list = NULL;

/* Test statistics */
static volatile int test_count = 0;
static volatile int test_passed = 0;
static volatile int test_failed = 0;
static volatile int last_failure_count
    = 0; /* Preserve failure count after Test_run_all() */

/* Test failure flag and message - avoids exception nesting issues */
static volatile int test_failure_flag = 0;
static char test_failure_message[512];

/* Exception type for test failures - kept for compatibility but not used for
 * failures */
const Except_T Test_Failed = { &Test_Failed, "Test assertion failed" };

/**
 * @brief Register a test function with the framework.
 * @ingroup test_framework
 * @param name Test name for reporting purposes.
 * @param func Test function pointer to register.
 *
 * Called automatically by the TEST() macro via GCC constructor attribute.
 * Maintains an internal linked list of registered test functions.
 *
 * @note Thread Safety: Not thread-safe (called at program startup before threads).
 * @see TEST() macro for automatic registration.
 * @see Test_run_all() for test execution.
 */
void
Test_register (const char *name, void (*func) (void))
{
  struct TestFunction *test;

  assert (name != NULL);
  assert (func != NULL);

  /* Allocate test function node */
  test = malloc (sizeof (struct TestFunction));
  if (test == NULL)
    {
      fprintf (stderr,
               "FATAL: Failed to allocate memory for test registration\n");
      abort ();
    }

  test->name = name;
  test->func = func;
  test->next = test_list;
  test_list = test;
}

/**
 * @brief Report a test failure with detailed error information.
 * @ingroup test_framework
 * @param message Failure message describing what went wrong.
 * @param file Source file where the failure occurred.
 * @param line Line number where the failure occurred.
 *
 * Sets an internal failure flag with formatted error information including
 * file and line details. This avoids exception nesting issues by using a flag
 * instead of raising exceptions directly from within failure reporting.
 *
 * @see ASSERT() macro that calls this function.
 * @see Test_run_all() for how failures are detected and reported.
 */
void
Test_fail (const char *message, const char *file, int line)
{
  /* Format detailed error message */
  snprintf (test_failure_message, sizeof (test_failure_message), "%s at %s:%d",
            message ? message : "Test failed", file ? file : "unknown", line);

  /* Set failure flag - avoids exception nesting issues */
  test_failure_flag = 1;
}

/**
 * @brief Report an equality assertion failure.
 * @ingroup test_framework
 * @param expected_str String representation of the expected value.
 * @param actual_str String representation of the actual value.
 * @param file Source file where the failure occurred.
 * @param line Line number where the failure occurred.
 *
 * Formats and reports a detailed failure message for ASSERT_EQ() macro failures,
 * showing both expected and actual values with file/line location.
 *
 * @see ASSERT_EQ() macro that calls this function.
 * @see Test_fail() for the base failure reporting mechanism.
 */
void
Test_fail_eq (const char *expected_str, const char *actual_str,
              const char *file, int line)
{
  snprintf (test_failure_message, sizeof (test_failure_message),
            "Assertion failed: expected %s == %s at %s:%d", expected_str,
            actual_str, file ? file : "unknown", line);

  test_failure_flag = 1;
}

/**
 * @brief Report an inequality assertion failure.
 * @ingroup test_framework
 * @param expected_str String representation of the expected value.
 * @param actual_str String representation of the actual value.
 * @param file Source file where the failure occurred.
 * @param line Line number where the failure occurred.
 *
 * Formats and reports a detailed failure message for ASSERT_NE() macro failures,
 * showing both expected and actual values with file/line location.
 *
 * @see ASSERT_NE() macro that calls this function.
 * @see Test_fail() for the base failure reporting mechanism.
 */
void
Test_fail_ne (const char *expected_str, const char *actual_str,
              const char *file, int line)
{
  snprintf (test_failure_message, sizeof (test_failure_message),
            "Assertion failed: expected %s != %s at %s:%d", expected_str,
            actual_str, file ? file : "unknown", line);

  test_failure_flag = 1;
}

/**
 * @brief Execute all registered tests and display results.
 * @ingroup test_framework
 *
 * Runs each registered test function in registration order, catching Test_Failed
 * exceptions raised by ASSERT macros. This allows FINALLY blocks in tests to
 * execute for proper resource cleanup even when assertions fail.
 *
 * Prints detailed progress and summary of test results including pass/fail counts.
 *
 * @note Thread Safety: Not thread-safe (intended for single-threaded test execution).
 * @see TEST() macro for registering tests.
 * @see ASSERT() macros for test assertions.
 * @see Test_get_failures() for programmatic result checking.
 */
void
Test_run_all (void)
{
  volatile int total_tests = 0;

  /* Count total tests */
  for (struct TestFunction *test = test_list; test != NULL; test = test->next)
    {
      total_tests++;
    }

  if (total_tests == 0)
    {
      printf ("No tests registered.\n");
      return;
    }

  printf ("Running %d test%s...\n\n", total_tests,
          total_tests == 1 ? "" : "s");

  /* Run each test */
  volatile struct TestFunction *volatile current_test = test_list;
  while (current_test != NULL)
    {
      test_count++;
      printf ("[%d/%d] %s ... ", test_count, total_tests, current_test->name);
      fflush (stdout);

      /* Store next pointer before test execution */
      volatile struct TestFunction *next_test = current_test->next;

      /* Clear failure flag before test */
      test_failure_flag = 0;

      /* Run test function with exception handling.
       * Test_Failed is caught to allow FINALLY blocks to execute in tests,
       * ensuring proper cleanup of resources even when assertions fail.
       * ELSE catches any other uncaught exceptions to prevent crashes. */
      TRY { current_test->func (); }
      EXCEPT (Test_Failed)
      {
        /* Test_Failed was raised by ASSERT macro - failure already recorded
         * via test_failure_flag. This catch allows FINALLY blocks in the
         * test to execute before we get here. */
      }
      ELSE
      {
        /* Catch any other unhandled exceptions to prevent test framework crash.
         * Mark the test as failed with the exception reason. */
        if (!test_failure_flag)
          {
            test_failure_flag = 1;
            const Except_T *exc = Except_stack ? Except_stack->exception : NULL;
            snprintf (test_failure_message, sizeof (test_failure_message),
                      "Unhandled exception: %s",
                      exc && exc->reason ? exc->reason : "Unknown");
          }
      }
      END_TRY;

      /* Check if test failed via assertion flag */
      if (test_failure_flag)
        {
          test_failed++;
          printf ("FAIL\n");
          printf ("  %s\n", test_failure_message);
        }
      else
        {
          test_passed++;
          printf ("PASS\n");
        }

      current_test = next_test;
    }

  /* Print summary */
  printf ("\n");
  printf ("Results: %d passed, %d failed, %d total\n", test_passed,
          test_failed, test_count);

  /* Preserve failure count for Test_get_failures() */
  last_failure_count = test_failed;

  /* Reset counters for potential future runs */
  test_count = 0;
  test_passed = 0;
  test_failed = 0;
}

/**
 * @brief Get the number of failed tests from the last test run.
 * @ingroup test_framework
 *
 * Returns the count of tests that failed during the most recent execution
 * of Test_run_all(). Returns 0 if all tests passed or if no tests have been run yet.
 *
 * @return Number of failed tests (0 indicates success).
 * @see Test_run_all() for executing the test suite.
 */
int
Test_get_failures (void)
{
  return last_failure_count;
}

#undef T
