#ifndef SOCKETERROR_H
#define SOCKETERROR_H

#include <errno.h>
#include <string.h>

/* Error buffer size - increased for safety */
#define SOCKET_ERROR_BUFSIZE 1024

/* Truncation marker for error messages - size calculated from marker itself */
#define SOCKET_ERROR_TRUNCATION_MARKER "... (truncated)"
#define SOCKET_ERROR_TRUNCATION_SIZE (sizeof(SOCKET_ERROR_TRUNCATION_MARKER))

/* Maximum field sizes for error messages to prevent truncation */
#define SOCKET_ERROR_MAX_HOSTNAME 255
#define SOCKET_ERROR_MAX_MESSAGE 512

/* Thread-local error buffer for detailed messages */
#ifdef _WIN32
extern __declspec(thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE];
#else
extern __thread char socket_error_buf[SOCKET_ERROR_BUFSIZE];
#endif

/* Macro to format error messages with errno information - with truncation protection */
#define SOCKET_ERROR_FMT(fmt, ...)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        int _socket_error_ret = snprintf(socket_error_buf, SOCKET_ERROR_BUFSIZE, fmt " (errno: %d - %s)",              \
                                         ##__VA_ARGS__, errno, strerror(errno));                                       \
        if (_socket_error_ret >= (int)SOCKET_ERROR_BUFSIZE)                                                            \
        {                                                                                                              \
            /* Message was truncated - add truncation marker */                                                        \
            socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                                                         \
            if (SOCKET_ERROR_BUFSIZE >= SOCKET_ERROR_TRUNCATION_SIZE + 1)                                              \
            {                                                                                                          \
                memcpy(socket_error_buf + SOCKET_ERROR_BUFSIZE - SOCKET_ERROR_TRUNCATION_SIZE,                         \
                       SOCKET_ERROR_TRUNCATION_MARKER, SOCKET_ERROR_TRUNCATION_SIZE - 1);                              \
                socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                                                     \
            }                                                                                                          \
        }                                                                                                              \
        (void)_socket_error_ret; /* Suppress unused warning */                                                         \
    } while (0)

/* Macro to format error messages without errno - with truncation protection */
#define SOCKET_ERROR_MSG(fmt, ...)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        int _socket_error_ret = snprintf(socket_error_buf, SOCKET_ERROR_BUFSIZE, fmt, ##__VA_ARGS__);                  \
        if (_socket_error_ret >= (int)SOCKET_ERROR_BUFSIZE)                                                            \
        {                                                                                                              \
            /* Message was truncated - add truncation marker */                                                        \
            socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                                                         \
            if (SOCKET_ERROR_BUFSIZE >= SOCKET_ERROR_TRUNCATION_SIZE + 1)                                              \
            {                                                                                                          \
                memcpy(socket_error_buf + SOCKET_ERROR_BUFSIZE - SOCKET_ERROR_TRUNCATION_SIZE,                         \
                       SOCKET_ERROR_TRUNCATION_MARKER, SOCKET_ERROR_TRUNCATION_SIZE - 1);                              \
                socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                                                     \
            }                                                                                                          \
        }                                                                                                              \
        (void)_socket_error_ret; /* Suppress unused warning */                                                         \
    } while (0)

/* Get the last error message - declared here, defined in SocketError.c */
extern const char *Socket_GetLastError(void);

/* Common error conditions with descriptive messages */
#define SOCKET_ENOMEM "Out of memory"
#define SOCKET_EINVAL "Invalid argument"
#define SOCKET_ECONNREFUSED "Connection refused"
#define SOCKET_ETIMEDOUT "Operation timed out"
#define SOCKET_EADDRINUSE "Address already in use"
#define SOCKET_ENETUNREACH "Network unreachable"
#define SOCKET_EHOSTUNREACH "Host unreachable"
#define SOCKET_EPIPE "Broken pipe"
#define SOCKET_ECONNRESET "Connection reset by peer"

#endif /* SOCKETERROR_H */