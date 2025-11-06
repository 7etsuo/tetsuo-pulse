/**
 * test_socketerror.c - SocketError module unit tests
 * Tests for the SocketError thread-local error message handling module.
 * Covers error message retrieval and thread-local storage behavior.
 */

#include <stdio.h>
#include <string.h>

#include "test/Test.h"
#include "core/SocketError.h"
#include "core/SocketLog.h"

typedef struct
{
    int called;
    SocketLogLevel level;
    const char *component;
    char message[SOCKET_ERROR_BUFSIZE];
} LogProbe;

static void log_capture_callback(void *userdata, SocketLogLevel level, const char *component, const char *message)
{
    LogProbe *probe = (LogProbe *)userdata;

    if (!probe)
        return;

    probe->called++;
    probe->level = level;
    probe->component = component;

    if (message)
        strncpy(probe->message, message, sizeof(probe->message) - 1);
}

TEST(socketlog_custom_callback_receives_errors)
{
    LogProbe probe = {0};

    SocketLog_setcallback(log_capture_callback, &probe);
    SOCKET_ERROR_MSG("Observability logging test message");

    ASSERT_EQ(1, probe.called);
    ASSERT_EQ(SOCKET_LOG_ERROR, probe.level);
    ASSERT_NOT_NULL(probe.component);
    ASSERT(strstr(probe.message, "Observability logging test message") != NULL);

    SocketLog_setcallback(NULL, NULL);
}

/* Test that Socket_GetLastError returns empty string initially */
TEST(socketerror_initial_empty)
{
    const char *error = Socket_GetLastError();
    ASSERT_NOT_NULL(error);
    ASSERT_EQ(strlen(error), 0);
}

/* Test that error buffer is thread-local
 * Note: This test verifies the basic functionality. True thread-local
 * behavior would require execution in multiple threads, which is
 * tested in test_threadsafety.c */
TEST(socketerror_returns_buffer)
{
    const char *error1 = Socket_GetLastError();
    const char *error2 = Socket_GetLastError();

    /* Should return same buffer pointer */
    ASSERT_EQ(error1, error2);

    /* Should be empty initially */
    ASSERT_EQ(strlen(error1), 0);
}

/* Test that Socket_GetLastError returns valid pointer */
TEST(socketerror_valid_pointer)
{
    const char *error = Socket_GetLastError();

    /* Should not be NULL */
    ASSERT_NOT_NULL(error);

    /* Should be a valid string (may be empty) */
    /* Reading from the buffer should not crash */
    size_t len = strlen(error);
    ASSERT(len < SOCKET_ERROR_BUFSIZE);
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}
