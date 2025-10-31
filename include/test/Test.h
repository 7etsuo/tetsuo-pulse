#ifndef TEST_INCLUDED
#define TEST_INCLUDED

#include "core/Except.h"
#include <stddef.h>

/**
 * Test Framework
 *
 * Minimal unit test framework following C Interfaces and Implementations patterns.
 * Integrates with the exception handling system for consistent error reporting.
 *
 * Features:
 * - Exception-based test assertions
 * - Automatic test registration
 * - Test result reporting (pass/fail counts)
 * - File/line tracking for failures
 * - Minimal API surface
 *
 * Usage:
 *   TEST(test_name)
 *   {
 *       ASSERT(condition);
 *       ASSERT_EQ(expected, actual);
 *       ASSERT_NULL(ptr);
 *   }
 *
 *   int main(void)
 *   {
 *       Test_run_all();
 *       return Test_get_failures() > 0 ? 1 : 0;
 *   }
 */

#define T Test_T
typedef struct T *T;

/* Exception type for test failures */
extern Except_T Test_Failed;

/**
 * Test_run_all - Run all registered tests
 *
 * Executes all tests registered via TEST() macro and prints summary.
 * Tests are executed in registration order.
 */
extern void Test_run_all(void);

/**
 * Test_get_failures - Get number of failed tests
 *
 * Returns: Number of tests that failed (0 if all passed)
 */
extern int Test_get_failures(void);

/**
 * Test registration macro - declares and registers a test function
 *
 * Usage:
 *   TEST(test_arena_allocation)
 *   {
 *       // test code
 *   }
 */
#define TEST(name)                                                                                                      \
    static void test_##name(void);                                                                                      \
    static void __attribute__((constructor)) test_register_##name(void)                                                 \
    {                                                                                                                    \
        Test_register(#name, test_##name);                                                                              \
    }                                                                                                                    \
    static void test_##name(void)

/* Internal registration function - do not call directly */
extern void Test_register(const char *name, void (*func)(void));

/**
 * ASSERT - Basic assertion macro
 * @condition: Condition that must be true
 *
 * Raises Test_Failed if condition is false.
 */
#define ASSERT(condition)                                                                                               \
    do                                                                                                                   \
    {                                                                                                                    \
        if (!(condition))                                                                                                \
        {                                                                                                                \
            Test_fail("Assertion failed: " #condition, __FILE__, __LINE__);                                             \
        }                                                                                                                \
    } while (0)

/**
 * ASSERT_EQ - Equality assertion macro
 * @expected: Expected value
 * @actual: Actual value
 *
 * Raises Test_Failed if values are not equal.
 * Works with any comparable types.
 */
#define ASSERT_EQ(expected, actual)                                                                                     \
    do                                                                                                                   \
    {                                                                                                                    \
        if ((expected) != (actual))                                                                                      \
        {                                                                                                                \
            Test_fail_eq(#expected, #actual, __FILE__, __LINE__);                                                        \
        }                                                                                                                \
    } while (0)

/**
 * ASSERT_NE - Inequality assertion macro
 * @expected: Value that should not equal actual
 * @actual: Actual value
 *
 * Raises Test_Failed if values are equal.
 */
#define ASSERT_NE(expected, actual)                                                                                     \
    do                                                                                                                   \
    {                                                                                                                    \
        if ((expected) == (actual))                                                                                      \
        {                                                                                                                \
            Test_fail_ne(#expected, #actual, __FILE__, __LINE__);                                                       \
        }                                                                                                                \
    } while (0)

/**
 * ASSERT_NULL - NULL pointer assertion macro
 * @ptr: Pointer that must be NULL
 *
 * Raises Test_Failed if pointer is not NULL.
 */
#define ASSERT_NULL(ptr)                                                                                                \
    do                                                                                                                   \
    {                                                                                                                    \
        if ((ptr) != NULL)                                                                                               \
        {                                                                                                                \
            Test_fail("Assertion failed: " #ptr " is not NULL", __FILE__, __LINE__);                                   \
        }                                                                                                                \
    } while (0)

/**
 * ASSERT_NOT_NULL - Non-NULL pointer assertion macro
 * @ptr: Pointer that must not be NULL
 *
 * Raises Test_Failed if pointer is NULL.
 */
#define ASSERT_NOT_NULL(ptr)                                                                                           \
    do                                                                                                                   \
    {                                                                                                                    \
        if ((ptr) == NULL)                                                                                               \
        {                                                                                                                \
            Test_fail("Assertion failed: " #ptr " is NULL", __FILE__, __LINE__);                                       \
        }                                                                                                                \
    } while (0)

/* Internal failure reporting functions - do not call directly */
extern void Test_fail(const char *message, const char *file, int line);
extern void Test_fail_eq(const char *expected_str, const char *actual_str, const char *file, int line);
extern void Test_fail_ne(const char *expected_str, const char *actual_str, const char *file, int line);

#undef T
#endif

