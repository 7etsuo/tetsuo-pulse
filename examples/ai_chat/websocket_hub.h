#ifndef WEBSOCKET_HUB_H
#define WEBSOCKET_HUB_H

#include "socket/SocketWS.h"
#include <stddef.h>

#define MAX_CLIENTS 64
#define MAX_NICK_LEN 32

typedef struct WebSocketHub *WebSocketHub_T;

WebSocketHub_T WebSocketHub_new(void);
void WebSocketHub_free(WebSocketHub_T *hub);

int WebSocketHub_add(WebSocketHub_T hub, SocketWS_T ws);
void WebSocketHub_remove(WebSocketHub_T hub, SocketWS_T ws);

void WebSocketHub_set_nick(WebSocketHub_T hub, SocketWS_T ws, const char *nick);
const char *WebSocketHub_get_nick(WebSocketHub_T hub, SocketWS_T ws);

void WebSocketHub_broadcast(WebSocketHub_T hub, const char *message, size_t len);
void WebSocketHub_broadcast_json(WebSocketHub_T hub,
                                  const char *type,
                                  const char *agent,
                                  const char *avatar,
                                  const char *text);
void WebSocketHub_broadcast_userlist(WebSocketHub_T hub);
void WebSocketHub_broadcast_userjoin(WebSocketHub_T hub, const char *nick);
void WebSocketHub_broadcast_userpart(WebSocketHub_T hub, const char *nick);

int WebSocketHub_count(WebSocketHub_T hub);

typedef void (*WebSocketHub_Iterator)(SocketWS_T ws, void *userdata);
void WebSocketHub_foreach(WebSocketHub_T hub, WebSocketHub_Iterator fn, void *userdata);

#endif /* WEBSOCKET_HUB_H */
