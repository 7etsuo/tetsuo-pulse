/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef TEST_INCLUDED
#define TEST_INCLUDED

#include "core/Except.h"
#include <stddef.h>

/**
 * @defgroup test_framework Test Framework
 * @brief Exception-based testing framework for unit and integration testing.
 * @{
 * Provides automatic test registration, comprehensive assertion macros, and
 * detailed failure reporting. Designed specifically for the socket library's
 * testing needs.
 * @see @ref utilities for other helper modules.
 * @see @ref foundation for core infrastructure this framework builds upon.
 */

/**
 * @file Test.h
 * @brief Exception-based test framework for unit and integration testing.
 * @ingroup test_framework
 *
 * Provides a minimal, exception-based testing framework designed for the
 * socket library. Features automatic test registration, comprehensive
 * assertion macros, and detailed failure reporting with file/line information.
 *
 * @see TEST() macro for test registration.
 * @see ASSERT() macros for test assertions.
 * @see Test_run_all() for executing test suites.
 * @see @ref foundation for core infrastructure components.
 */

/**
 * @brief Opaque test framework type.
 * @ingroup test_framework
 *
 * Internal test framework state - use the provided macros and functions
 * for all test operations.
 *
 * @see TEST() macro for creating test functions.
 * @see Test_run_all() for executing tests.
 */
#define T Test_T
typedef struct T *T;

/**
 * @brief Exception raised when test assertions fail.
 * @ingroup test_framework
 *
 * This exception is raised by ASSERT() macros when test conditions are not
 * met. Test functions should be wrapped in TRY/EXCEPT blocks to handle
 * failures gracefully, allowing FINALLY blocks to execute for proper resource
 * cleanup.
 *
 * @see ASSERT() macros for assertion functions that raise this exception.
 * @see Except_T for exception handling patterns.
 * @see TRY/EXCEPT constructs for handling test failures.
 */
extern const Except_T Test_Failed;

/**
 * @brief Execute all registered tests and display results.
 * @ingroup test_framework
 *
 * Runs all tests that have been registered using the TEST() macro in
 * registration order. Prints detailed results including pass/fail counts, test
 * names, and failure details. Tests are executed sequentially - if one test
 * fails, subsequent tests still run.
 *
 * @see TEST() macro for registering tests.
 * @see Test_get_failures() for checking results programmatically.
 * @see Test_Failed for the exception raised by failed assertions.
 */
extern void Test_run_all (void);

/**
 * @brief Get the number of failed tests from the last test run.
 * @ingroup test_framework
 *
 * Returns the count of tests that failed during the most recent execution of
 * Test_run_all(). Returns 0 if all tests passed or if no tests have been run
 * yet.
 *
 * @return Number of failed tests (0 indicates success).
 * @see Test_run_all() for executing the test suite.
 */
extern int Test_get_failures (void);

/**
 * @brief Macro for declaring and registering test functions.
 * @ingroup test_framework
 *
 * Automatically registers a test function with the test framework using GCC
 * constructor attributes. Tests are executed in registration order when
 * Test_run_all() is called.
 *
 * Example usage:
 * @code
 * TEST(test_memory_allocation)
 * {
 *     Arena_T arena = Arena_new();
 *     ASSERT_NOT_NULL(arena);
 *     void *ptr = Arena_alloc(arena, 1024, __FILE__, __LINE__);
 *     ASSERT_NOT_NULL(ptr);
 *     Arena_free(&arena);
 * }
 * @endcode
 *
 * @param name Test function name (without quotes).
 * @see Test_run_all() for executing registered tests.
 * @see ASSERT() macros for test assertions.
 * @see Test_register() for internal registration mechanism.
 */
#define TEST(name)                                                            \
  static void test_##name (void);                                             \
  static void __attribute__ ((constructor)) test_register_##name (void)       \
  {                                                                           \
    Test_register (#name, test_##name);                                       \
  }                                                                           \
  static void test_##name (void)

/**
 * @brief Internal function for registering test functions.
 * @ingroup test_framework
 *
 * This function is called automatically by the TEST() macro and should not be
 * invoked directly by user code. It maintains the internal registry of test
 * functions.
 *
 * @param name Test name string.
 * @param func Test function pointer.
 * @internal This is an internal implementation detail.
 * @see TEST() macro for the public registration interface.
 */
extern void Test_register (const char *name, void (*func) (void));

/**
 * @brief Assert that a condition evaluates to true.
 * @ingroup test_framework
 *
 * Evaluates the given condition and raises Test_Failed if it is false (0).
 * The test function is aborted immediately, but FINALLY blocks in TRY/EXCEPT
 * constructs will still execute for proper resource cleanup.
 *
 * @param condition Boolean expression that must evaluate to true.
 * @throws Test_Failed if condition is false.
 * @see ASSERT_EQ() for equality assertions.
 * @see ASSERT_NULL() for NULL pointer assertions.
 * @see Test_Failed for the exception type raised.
 */
#define ASSERT(condition)                                                     \
  do                                                                          \
    {                                                                         \
      if (!(condition))                                                       \
        {                                                                     \
          Test_fail ("Assertion failed: " #condition, __FILE__, __LINE__);    \
          RAISE (Test_Failed);                                                \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @brief Assert that two values are equal.
 * @ingroup test_framework
 *
 * Compares expected and actual values using != operator. Raises Test_Failed
 * if they are not equal, aborting the current test but ensuring FINALLY blocks
 * execute for proper resource cleanup.
 *
 * @param expected The expected value.
 * @param actual The actual value to compare against expected.
 * @throws Test_Failed if values are not equal.
 * @see ASSERT_NE() for inequality assertions.
 * @see ASSERT() for general boolean assertions.
 */
#define ASSERT_EQ(expected, actual)                                           \
  do                                                                          \
    {                                                                         \
      if ((expected) != (actual))                                             \
        {                                                                     \
          Test_fail_eq (#expected, #actual, __FILE__, __LINE__);              \
          RAISE (Test_Failed);                                                \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @brief Assert that two values are not equal.
 * @ingroup test_framework
 *
 * Compares expected and actual values using == operator. Raises Test_Failed
 * if they are equal (when they should not be), aborting the current test but
 * ensuring FINALLY blocks execute for proper resource cleanup.
 *
 * @param expected The value that should not equal actual.
 * @param actual The actual value to compare against expected.
 * @throws Test_Failed if values are equal.
 * @see ASSERT_EQ() for equality assertions.
 * @see ASSERT() for general boolean assertions.
 */
#define ASSERT_NE(expected, actual)                                           \
  do                                                                          \
    {                                                                         \
      if ((expected) == (actual))                                             \
        {                                                                     \
          Test_fail_ne (#expected, #actual, __FILE__, __LINE__);              \
          RAISE (Test_Failed);                                                \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @brief Assert that a pointer is NULL.
 * @ingroup test_framework
 *
 * Verifies that the given pointer is NULL. Raises Test_Failed if the pointer
 * is not NULL, aborting the current test but ensuring FINALLY blocks execute
 * for proper resource cleanup.
 *
 * @param ptr Pointer that must be NULL.
 * @throws Test_Failed if pointer is not NULL.
 * @see ASSERT_NOT_NULL() for non-NULL assertions.
 * @see ASSERT() for general boolean assertions.
 */
#define ASSERT_NULL(ptr)                                                      \
  do                                                                          \
    {                                                                         \
      if ((ptr) != NULL)                                                      \
        {                                                                     \
          Test_fail ("Assertion failed: " #ptr " is not NULL", __FILE__,      \
                     __LINE__);                                               \
          RAISE (Test_Failed);                                                \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @brief Assert that a pointer is not NULL.
 * @ingroup test_framework
 *
 * Verifies that the given pointer is not NULL. Raises Test_Failed if the
 * pointer is NULL, aborting the current test but ensuring FINALLY blocks
 * execute for proper resource cleanup.
 *
 * @param ptr Pointer that must not be NULL.
 * @throws Test_Failed if pointer is NULL.
 * @see ASSERT_NULL() for NULL assertions.
 * @see ASSERT() for general boolean assertions.
 */
#define ASSERT_NOT_NULL(ptr)                                                  \
  do                                                                          \
    {                                                                         \
      if ((ptr) == NULL)                                                      \
        {                                                                     \
          Test_fail ("Assertion failed: " #ptr " is NULL", __FILE__,          \
                     __LINE__);                                               \
          RAISE (Test_Failed);                                                \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @brief Internal function for reporting test failures.
 * @ingroup test_framework
 *
 * Called by ASSERT() macros to report failure details. Should not be called
 * directly.
 *
 * @param message Failure message.
 * @param file Source file where failure occurred.
 * @param line Line number where failure occurred.
 * @internal Implementation detail of assertion macros.
 * @see ASSERT() macro for public assertion interface.
 */
extern void Test_fail (const char *message, const char *file, int line);

/**
 * @brief Internal function for reporting equality assertion failures.
 * @ingroup test_framework
 *
 * Called by ASSERT_EQ() macro to report detailed equality failure information.
 *
 * @param expected_str String representation of expected value.
 * @param actual_str String representation of actual value.
 * @param file Source file where failure occurred.
 * @param line Line number where failure occurred.
 * @internal Implementation detail of assertion macros.
 * @see ASSERT_EQ() macro for public assertion interface.
 */
extern void Test_fail_eq (const char *expected_str, const char *actual_str,
                          const char *file, int line);

/**
 * @brief Internal function for reporting inequality assertion failures.
 * @ingroup test_framework
 *
 * Called by ASSERT_NE() macro to report detailed inequality failure
 * information.
 *
 * @param expected_str String representation of expected value.
 * @param actual_str String representation of actual value.
 * @param file Source file where failure occurred.
 * @param line Line number where failure occurred.
 * @internal Implementation detail of assertion macros.
 * @see ASSERT_NE() macro for public assertion interface.
 */
extern void Test_fail_ne (const char *expected_str, const char *actual_str,
                          const char *file, int line);

#undef T

/** @} */ // Close test_framework group
#endif
