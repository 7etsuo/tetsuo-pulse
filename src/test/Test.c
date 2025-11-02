/**
 * Test.c - Test framework implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test/Test.h"
#include "core/Except.h"

#define T Test_T

/* Test function structure */
struct TestFunction
{
    const char *name;
    void (*func)(void);
    struct TestFunction *next;
};

/* Test registry - linked list of test functions */
static struct TestFunction *test_list = NULL;

/* Test statistics */
static int test_count = 0;
static int test_passed = 0;
static int test_failed = 0;
static int last_failure_count = 0; /* Preserve failure count after Test_run_all() */

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec(thread) Except_T Test_DetailedException;
#else
static __thread Except_T Test_DetailedException;
#endif

/* Exception type for test failures */
Except_T Test_Failed = {"Test assertion failed"};

/* Error message buffer for detailed failures */
static char test_error_buf[512];

/**
 * Test_register - Register a test function
 * @name: Test name (for reporting)
 * @func: Test function to register
 *
 * Called automatically by TEST() macro via constructor attribute.
 * Thread Safety: Not thread-safe (called at program startup before threads).
 */
void Test_register(const char *name, void (*func)(void))
{
    struct TestFunction *test;

    assert(name != NULL);
    assert(func != NULL);

    /* Allocate test function node */
    test = malloc(sizeof(struct TestFunction));
    if (test == NULL)
    {
        fprintf(stderr, "FATAL: Failed to allocate memory for test registration\n");
        abort();
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
 *
 * This function raises Test_Failed exception with detailed error information.
 * The exception is caught by the test runner, which records the failure.
 */
void Test_fail(const char *message, const char *file, int line)
{
    /* Format detailed error message */
    snprintf(test_error_buf, sizeof(test_error_buf), "%s at %s:%d", message ? message : "Test failed",
             file ? file : "unknown", line);

    /* Raise exception with detailed message */
    Test_DetailedException = Test_Failed;
    Test_DetailedException.reason = test_error_buf;
    RAISE(Test_DetailedException);
}

/**
 * Test_fail_eq - Report equality assertion failure
 * @expected_str: String representation of expected value
 * @actual_str: String representation of actual value
 * @file: Source file where failure occurred
 * @line: Line number where failure occurred
 */
void Test_fail_eq(const char *expected_str, const char *actual_str, const char *file, int line)
{
    snprintf(test_error_buf, sizeof(test_error_buf), "Assertion failed: expected %s == %s at %s:%d", expected_str,
             actual_str, file ? file : "unknown", line);

    Test_DetailedException = Test_Failed;
    Test_DetailedException.reason = test_error_buf;
    RAISE(Test_DetailedException);
}

/**
 * Test_fail_ne - Report inequality assertion failure
 * @expected_str: String representation of expected value
 * @actual_str: String representation of actual value
 * @file: Source file where failure occurred
 * @line: Line number where failure occurred
 */
void Test_fail_ne(const char *expected_str, const char *actual_str, const char *file, int line)
{
    snprintf(test_error_buf, sizeof(test_error_buf), "Assertion failed: expected %s != %s at %s:%d", expected_str,
             actual_str, file ? file : "unknown", line);

    Test_DetailedException = Test_Failed;
    Test_DetailedException.reason = test_error_buf;
    RAISE(Test_DetailedException);
}

/**
 * Test_run_all - Run all registered tests
 *
 * Executes each registered test function in registration order.
 * Catches Test_Failed exceptions and records failures.
 * Prints summary of test results.
 *
 * Thread Safety: Not thread-safe (intended for single-threaded test execution).
 */
void Test_run_all(void)
{
    volatile int total_tests = 0;

    /* Count total tests */
    for (struct TestFunction *test = test_list; test != NULL; test = test->next)
    {
        total_tests++;
    }

    if (total_tests == 0)
    {
        printf("No tests registered.\n");
        return;
    }

    printf("Running %d test%s...\n\n", total_tests, total_tests == 1 ? "" : "s");

    /* Run each test */
    struct TestFunction *current_test = test_list;
    while (current_test != NULL)
    {
        test_count++;
        printf("[%d/%d] %s ... ", test_count, total_tests, current_test->name);
        fflush(stdout);

        TRY
        {
            current_test->func();
            test_passed++;
            printf("PASS\n");
        }
        EXCEPT(Test_Failed)
        {
            test_failed++;
            printf("FAIL\n");
            if (Except_frame.exception && Except_frame.exception->reason)
            {
                printf("  %s\n", Except_frame.exception->reason);
            }
        }
        ELSE
        {
            /* Catch any other exception (Socket_Failed, Arena_Failed, etc.) */
            test_failed++;
            printf("FAIL\n");
            if (Except_frame.exception)
            {
                printf("  Unexpected exception: %s", 
                       Except_frame.exception->reason ? Except_frame.exception->reason : "(no reason)");
                if (Except_frame.file)
                    printf(" at %s:%d", Except_frame.file, Except_frame.line);
                printf("\n");
            }
        }
        END_TRY;

        current_test = current_test->next;
    }

    /* Print summary */
    printf("\n");
    printf("Results: %d passed, %d failed, %d total\n", test_passed, test_failed, test_count);

    /* Preserve failure count for Test_get_failures() */
    last_failure_count = test_failed;

    /* Reset counters for potential future runs */
    test_count = 0;
    test_passed = 0;
    test_failed = 0;
}

/**
 * Test_get_failures - Get number of failed tests
 *
 * Returns: Number of tests that failed in the last Test_run_all() call.
 * Returns 0 if no tests have been run yet or if all tests passed.
 */
int Test_get_failures(void)
{
    return last_failure_count;
}

#undef T

