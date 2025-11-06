#ifndef SOCKETEVENTS_INCLUDED
#define SOCKETEVENTS_INCLUDED

#include <stddef.h>

typedef enum SocketEventType
{
    SOCKET_EVENT_ACCEPTED = 0,
    SOCKET_EVENT_CONNECTED,
    SOCKET_EVENT_DNS_TIMEOUT,
    SOCKET_EVENT_POLL_WAKEUP
} SocketEventType;

typedef struct SocketEventRecord
{
    SocketEventType type;
    const char *component;
    union
    {
        struct
        {
            int fd;
            const char *peer_addr;
            int peer_port;
            const char *local_addr;
            int local_port;
        } connection;
        struct
        {
            const char *host;
            int port;
        } dns;
        struct
        {
            int nfds;
            int timeout_ms;
        } poll;
    } data;
} SocketEventRecord;

typedef void (*SocketEventCallback)(void *userdata, const SocketEventRecord *event);

void SocketEvent_register(SocketEventCallback callback, void *userdata);
void SocketEvent_unregister(SocketEventCallback callback, void *userdata);

void SocketEvent_emit_accept(int fd, const char *peer_addr, int peer_port,
                             const char *local_addr, int local_port);
void SocketEvent_emit_connect(int fd, const char *peer_addr, int peer_port,
                              const char *local_addr, int local_port);
void SocketEvent_emit_dns_timeout(const char *host, int port);
void SocketEvent_emit_poll_wakeup(int nfds, int timeout_ms);

#endif /* SOCKETEVENTS_INCLUDED */

