/**
 * test_except.c - Exception handling unit tests
 * Tests for the Except exception handling module.
 * Covers TRY/EXCEPT/FINALLY blocks, exception raising, and propagation.
 */

#include <string.h>

#include "test/Test.h"
#include "core/Except.h"

/* Suppress longjmp clobbering warnings for test variables used with TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Test exception type for testing */
static const Except_T TestException = {"Test exception"};

/* Test basic exception raising and catching */
TEST(except_basic_try_except)
{
    volatile int caught = 0;

    TRY
    {
        RAISE(TestException);
        caught = 0; /* Should not reach here */
    }
    EXCEPT(TestException)
    {
        caught = 1;
    }
    END_TRY;

    ASSERT_EQ(caught, 1);
}

/* Test exception not raised */
TEST(except_no_exception)
{
    volatile int executed = 0;

    TRY
    {
        executed = 1;
    }
    EXCEPT(TestException)
    {
        executed = 0; /* Should not execute */
    }
    END_TRY;

    ASSERT_EQ(executed, 1);
}

/* Test FINALLY block always executes */
TEST(except_finally_always_executes)
{
    int finally_executed = 0;

    TRY
    {
        /* Normal execution */
    }
    FINALLY
    {
        finally_executed = 1;
    }
    END_TRY;

    ASSERT_EQ(finally_executed, 1);
}

/* Test FINALLY executes even when exception raised */
TEST(except_finally_executes_on_exception)
{
    int finally_executed = 0;

    TRY
    {
        RAISE(TestException);
    }
    EXCEPT(TestException)
    {
        /* Exception caught */
    }
    FINALLY
    {
        finally_executed = 1;
    }
    END_TRY;

    ASSERT_EQ(finally_executed, 1);
}

/* Test exception propagation with RERAISE */
TEST(except_reraise_propagation)
{
    volatile int inner_caught = 0;
    volatile int outer_caught = 0;

    TRY
    {
        TRY
        {
            RAISE(TestException);
        }
        EXCEPT(TestException)
        {
            inner_caught = 1;
            RERAISE; /* Propagate to outer handler */
        }
        END_TRY;
    }
    EXCEPT(TestException)
    {
        outer_caught = 1;
    }
    END_TRY;

    ASSERT_EQ(inner_caught, 1);
    ASSERT_EQ(outer_caught, 1);
}

/* Test nested exception handling */
TEST(except_nested_exception_handling)
{
    volatile int outer_caught = 0;
    volatile int inner_caught = 0;

    TRY
    {
        TRY
        {
            RAISE(TestException);
        }
        EXCEPT(TestException)
        {
            inner_caught = 1;
            /* Don't reraise - handle locally */
        }
        END_TRY;
    }
    EXCEPT(TestException)
    {
        outer_caught = 1; /* Should not execute */
    }
    END_TRY;

    ASSERT_EQ(inner_caught, 1);
    ASSERT_EQ(outer_caught, 0);
}

/* Test multiple exception types */
TEST(except_multiple_exception_types)
{
    static const Except_T Exception1 = {"Exception 1"};
    static const Except_T Exception2 = {"Exception 2"};

    volatile int caught1 = 0;
    volatile int caught2 = 0;

    TRY
    {
        RAISE(Exception1);
    }
    EXCEPT(Exception1)
    {
        caught1 = 1;
    }
    EXCEPT(Exception2)
    {
        caught2 = 1; /* Should not execute */
    }
    END_TRY;

    ASSERT_EQ(caught1, 1);
    ASSERT_EQ(caught2, 0);
}

/* Test ELSE clause */
TEST(except_else_clause)
{
    static const Except_T Exception1 = {"Exception 1"};
    static const Except_T Exception2 = {"Exception 2"};

    volatile int else_caught = 0;

    TRY
    {
        RAISE(Exception2);
    }
    EXCEPT(Exception1)
    {
        else_caught = 0; /* Should not execute */
    }
    ELSE
    {
        else_caught = 1; /* Should catch Exception2 */
    }
    END_TRY;

    ASSERT_EQ(else_caught, 1);
}

/* Test exception reason string */
TEST(except_exception_reason)
{
    const char *reason = NULL;

    TRY
    {
        RAISE(TestException);
    }
    EXCEPT(TestException)
    {
        reason = Except_frame.exception->reason;
    }
    END_TRY;

    ASSERT_NOT_NULL(reason);
    ASSERT_EQ(strcmp((const char *)reason, "Test exception"), 0);
}

/* Test exception file and line tracking */
TEST(except_exception_location_tracking)
{
    const char *file = NULL;
    volatile int line = 0;

    TRY
    {
        RAISE(TestException);
    }
    EXCEPT(TestException)
    {
        file = Except_frame.file;
        line = Except_frame.line;
    }
    END_TRY;

    ASSERT_NOT_NULL(file);
    ASSERT_NE(line, 0);
}

/* Test exception handling with return values */
TEST(except_exception_with_return)
{
    volatile int result = 0;

    TRY
    {
        RAISE(TestException);
        result = 1; /* Should not reach here */
    }
    EXCEPT(TestException)
    {
        result = 2;
    }
    END_TRY;

    ASSERT_EQ(result, 2);
}

/* Test multiple TRY blocks in sequence */
TEST(except_multiple_try_blocks)
{
    volatile int count = 0;

    TRY
    {
        count++;
    }
    END_TRY;

    TRY
    {
        RAISE(TestException);
    }
    EXCEPT(TestException)
    {
        count++;
    }
    END_TRY;

    ASSERT_EQ(count, 2);
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}
