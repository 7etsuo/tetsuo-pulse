/**
 * SocketError.c - Thread-local error message handling
 */

#include "core/SocketError.h"

/* Thread-local error buffer for detailed error messages */
#ifdef _WIN32
__declspec(thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE] = {0};
#else
__thread char socket_error_buf[SOCKET_ERROR_BUFSIZE] = {0};
#endif

/* Get the last error message */
const char *Socket_GetLastError(void)
{
    return socket_error_buf;
}
