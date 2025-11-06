#include <assert.h>
#include <pthread.h>
#include <string.h>

#include "core/SocketEvents.h"
#include "core/SocketLog.h"

#define SOCKET_EVENT_MAX_HANDLERS 8

typedef struct SocketEventHandler
{
    SocketEventCallback callback;
    void *userdata;
} SocketEventHandler;

static pthread_mutex_t socketevent_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketEventHandler socketevent_handlers[SOCKET_EVENT_MAX_HANDLERS];
static size_t socketevent_handler_count = 0;

static void
socketevent_dispatch(const SocketEventRecord *event)
{
    SocketEventHandler local_handlers[SOCKET_EVENT_MAX_HANDLERS];
    size_t count;
    size_t i;

    assert(event);

    pthread_mutex_lock(&socketevent_mutex);
    count = socketevent_handler_count;
    memcpy(local_handlers, socketevent_handlers, sizeof(SocketEventHandler) * count);
    pthread_mutex_unlock(&socketevent_mutex);

    for (i = 0; i < count; i++)
    {
        if (local_handlers[i].callback)
        {
            local_handlers[i].callback(local_handlers[i].userdata, event);
        }
    }
}

void
SocketEvent_register(SocketEventCallback callback, void *userdata)
{
    size_t i;

    assert(callback);

    pthread_mutex_lock(&socketevent_mutex);

    for (i = 0; i < socketevent_handler_count; i++)
    {
        if (socketevent_handlers[i].callback == callback && socketevent_handlers[i].userdata == userdata)
        {
            pthread_mutex_unlock(&socketevent_mutex);
            return;
        }
    }

    if (socketevent_handler_count >= SOCKET_EVENT_MAX_HANDLERS)
    {
        pthread_mutex_unlock(&socketevent_mutex);
        SocketLog_emit(SOCKET_LOG_WARN, "SocketEvents", "Handler limit reached; ignoring registration");
        return;
    }

    socketevent_handlers[socketevent_handler_count].callback = callback;
    socketevent_handlers[socketevent_handler_count].userdata = userdata;
    socketevent_handler_count++;

    pthread_mutex_unlock(&socketevent_mutex);
}

void
SocketEvent_unregister(SocketEventCallback callback, void *userdata)
{
    size_t i;

    assert(callback);

    pthread_mutex_lock(&socketevent_mutex);
    for (i = 0; i < socketevent_handler_count; i++)
    {
        if (socketevent_handlers[i].callback == callback && socketevent_handlers[i].userdata == userdata)
        {
            size_t remaining = socketevent_handler_count - i - 1;
            if (remaining > 0)
            {
                memmove(&socketevent_handlers[i], &socketevent_handlers[i + 1], remaining * sizeof(SocketEventHandler));
            }
            socketevent_handler_count--;
            break;
        }
    }
    pthread_mutex_unlock(&socketevent_mutex);
}

void
SocketEvent_emit_accept(int fd, const char *peer_addr, int peer_port, const char *local_addr, int local_port)
{
    SocketEventRecord event;

    event.type = SOCKET_EVENT_ACCEPTED;
    event.component = "Socket";
    event.data.connection.fd = fd;
    event.data.connection.peer_addr = peer_addr;
    event.data.connection.peer_port = peer_port;
    event.data.connection.local_addr = local_addr;
    event.data.connection.local_port = local_port;

    socketevent_dispatch(&event);
}

void
SocketEvent_emit_connect(int fd, const char *peer_addr, int peer_port, const char *local_addr, int local_port)
{
    SocketEventRecord event;

    event.type = SOCKET_EVENT_CONNECTED;
    event.component = "Socket";
    event.data.connection.fd = fd;
    event.data.connection.peer_addr = peer_addr;
    event.data.connection.peer_port = peer_port;
    event.data.connection.local_addr = local_addr;
    event.data.connection.local_port = local_port;

    socketevent_dispatch(&event);
}

void
SocketEvent_emit_dns_timeout(const char *host, int port)
{
    SocketEventRecord event;

    event.type = SOCKET_EVENT_DNS_TIMEOUT;
    event.component = "SocketDNS";
    event.data.dns.host = host;
    event.data.dns.port = port;

    socketevent_dispatch(&event);
}

void
SocketEvent_emit_poll_wakeup(int nfds, int timeout_ms)
{
    SocketEventRecord event;

    event.type = SOCKET_EVENT_POLL_WAKEUP;
    event.component = "SocketPoll";
    event.data.poll.nfds = nfds;
    event.data.poll.timeout_ms = timeout_ms;

    socketevent_dispatch(&event);
}

