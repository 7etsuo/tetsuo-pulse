/**
 * SocketError.c - Thread-local error message handling
 */

#include "core/SocketError.h"

/* Map errno value to SocketErrorCode enum */
static SocketErrorCode socket_errno_to_errorcode(int errno_val)
{
    switch (errno_val)
    {
    case 0:
        return SOCKET_ERROR_NONE;
    case EINVAL:
        return SOCKET_ERROR_EINVAL;
    case EACCES:
        return SOCKET_ERROR_EACCES;
    case EADDRINUSE:
        return SOCKET_ERROR_EADDRINUSE;
    case EADDRNOTAVAIL:
        return SOCKET_ERROR_EADDRNOTAVAIL;
    case EAFNOSUPPORT:
        return SOCKET_ERROR_EAFNOSUPPORT;
    case EAGAIN:
        return SOCKET_ERROR_EAGAIN;
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
        return SOCKET_ERROR_EWOULDBLOCK;
#endif
    case EALREADY:
        return SOCKET_ERROR_EALREADY;
    case EBADF:
        return SOCKET_ERROR_EBADF;
    case ECONNREFUSED:
        return SOCKET_ERROR_ECONNREFUSED;
    case ECONNRESET:
        return SOCKET_ERROR_ECONNRESET;
    case EFAULT:
        return SOCKET_ERROR_EFAULT;
    case EHOSTUNREACH:
        return SOCKET_ERROR_EHOSTUNREACH;
    case EINPROGRESS:
        return SOCKET_ERROR_EINPROGRESS;
    case EINTR:
        return SOCKET_ERROR_EINTR;
    case EISCONN:
        return SOCKET_ERROR_EISCONN;
    case EMFILE:
        return SOCKET_ERROR_EMFILE;
    case ENETUNREACH:
        return SOCKET_ERROR_ENETUNREACH;
    case ENOBUFS:
        return SOCKET_ERROR_ENOBUFS;
    case ENOMEM:
        return SOCKET_ERROR_ENOMEM;
    case ENOTCONN:
        return SOCKET_ERROR_ENOTCONN;
    case ENOTSOCK:
        return SOCKET_ERROR_ENOTSOCK;
    case EOPNOTSUPP:
        return SOCKET_ERROR_EOPNOTSUPP;
    case EPIPE:
        return SOCKET_ERROR_EPIPE;
    case EPROTONOSUPPORT:
        return SOCKET_ERROR_EPROTONOSUPPORT;
    case ETIMEDOUT:
        return SOCKET_ERROR_ETIMEDOUT;
    default:
        return SOCKET_ERROR_UNKNOWN;
    }
}

/* Thread-local error buffer for detailed error messages */
#ifdef _WIN32
__declspec(thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE] = {0};
__declspec(thread) int socket_last_errno = 0;
#else
__thread char socket_error_buf[SOCKET_ERROR_BUFSIZE] = {0};
__thread int socket_last_errno = 0;
#endif

/* Get the last error message */
const char *
Socket_GetLastError(void)
{
    return socket_error_buf;
}

/* Get the last captured errno value */
int
Socket_geterrno(void)
{
    return socket_last_errno;
}

/* Get the last error as a SocketErrorCode enum */
SocketErrorCode
Socket_geterrorcode(void)
{
    return socket_errno_to_errorcode(socket_last_errno);
}

/**
 * Socket_safe_strerror - Get thread-safe error string
 * @errnum: Error number
 * Returns: Pointer to thread-local error description string
 * Thread-safe: Uses __thread buffer and strerror_r
 */
const char *
Socket_safe_strerror(int errnum)
{
    static __thread char errbuf[128] = {0};

    if (errnum == 0) {
        strcpy(errbuf, "No error");
        return errbuf;
    }

#ifdef _GNU_SOURCE
    // GNU extension: returns char*
    return strerror_r(errnum, errbuf, sizeof(errbuf));
#else
    // POSIX: returns int, 0 on success
    if (strerror_r(errnum, errbuf, sizeof(errbuf)) != 0) {
        strcpy(errbuf, "Unknown error");
    }
    return errbuf;
#endif
}
