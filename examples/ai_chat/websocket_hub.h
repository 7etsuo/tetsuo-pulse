#ifndef WEBSOCKET_HUB_H
#define WEBSOCKET_HUB_H

#include "socket/SocketWS.h"
#include <stddef.h>

#define MAX_CLIENTS 64

typedef struct WebSocketHub *WebSocketHub_T;

WebSocketHub_T WebSocketHub_new(void);
void WebSocketHub_free(WebSocketHub_T *hub);

int WebSocketHub_add(WebSocketHub_T hub, SocketWS_T ws);
void WebSocketHub_remove(WebSocketHub_T hub, SocketWS_T ws);

void WebSocketHub_broadcast(WebSocketHub_T hub, const char *message, size_t len);
void WebSocketHub_broadcast_json(WebSocketHub_T hub,
                                  const char *type,
                                  const char *agent,
                                  const char *avatar,
                                  const char *text);

int WebSocketHub_count(WebSocketHub_T hub);

typedef void (*WebSocketHub_Iterator)(SocketWS_T ws, void *userdata);
void WebSocketHub_foreach(WebSocketHub_T hub, WebSocketHub_Iterator fn, void *userdata);

#endif /* WEBSOCKET_HUB_H */
