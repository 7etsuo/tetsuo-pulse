/**
 * Test.c - Test framework
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
 * Test_register - Register a test function
 * @name: Test name (for reporting)
 * @func: Test function to register
 * Called automatically by TEST() macro via constructor attribute.
 * Thread Safety: Not thread-safe (called at program startup before threads).
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
 * Test_fail - Report a test failure
 * @message: Failure message
 * @file: Source file where failure occurred
 * @line: Line number where failure occurred
 * This function sets a failure flag with detailed error information.
 * The test runner checks the flag after test execution and records the
 * failure.
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
 * Test_fail_eq - Report equality assertion failure
 * @expected_str: String representation of expected value
 * @actual_str: String representation of actual value
 * @file: Source file where failure occurred
 * @line: Line number where failure occurred
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
 * Test_fail_ne - Report inequality assertion failure
 * @expected_str: String representation of expected value
 * @actual_str: String representation of actual value
 * @file: Source file where failure occurred
 * @line: Line number where failure occurred
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
 * Test_run_all - Run all registered tests
 * Executes each registered test function in registration order.
 * Checks test failure flags set by assertion macros and records assertion
 * failures. Tests are expected to handle their own exceptions; uncaught
 * exceptions will terminate the runner. Prints summary of test results. Thread
 * Safety: Not thread-safe (intended for single-threaded test execution).
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

      /* Run test function */
      current_test->func ();

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
 * Test_get_failures - Get number of failed tests
 * Returns: Number of tests that failed in the last Test_run_all() call.
 * Returns 0 if no tests have been run yet or if all tests passed.
 */
int
Test_get_failures (void)
{
  return last_failure_count;
}

#undef T
