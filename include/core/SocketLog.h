#ifndef SOCKETLOG_INCLUDED
#define SOCKETLOG_INCLUDED

#include <stdarg.h>

typedef enum SocketLogLevel
{
    SOCKET_LOG_TRACE = 0,
    SOCKET_LOG_DEBUG,
    SOCKET_LOG_INFO,
    SOCKET_LOG_WARN,
    SOCKET_LOG_ERROR,
    SOCKET_LOG_FATAL
} SocketLogLevel;

typedef void (*SocketLogCallback)(void *userdata, SocketLogLevel level, const char *component, const char *message);

void SocketLog_setcallback(SocketLogCallback callback, void *userdata);
SocketLogCallback SocketLog_getcallback(void **userdata);
const char *SocketLog_levelname(SocketLogLevel level);
void SocketLog_emit(SocketLogLevel level, const char *component, const char *message);
void SocketLog_emitf(SocketLogLevel level, const char *component, const char *fmt, ...);
void SocketLog_emitfv(SocketLogLevel level, const char *component, const char *fmt, va_list args);

#endif /* SOCKETLOG_INCLUDED */

