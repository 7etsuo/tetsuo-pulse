#include "websocket_hub.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct WebSocketHub {
    SocketWS_T clients[MAX_CLIENTS];
    int count;
};

WebSocketHub_T
WebSocketHub_new(void)
{
    WebSocketHub_T hub = calloc(1, sizeof(*hub));
    return hub;
}

void
WebSocketHub_free(WebSocketHub_T *hub)
{
    if (!hub || !*hub) return;
    free(*hub);
    *hub = NULL;
}

int
WebSocketHub_add(WebSocketHub_T hub, SocketWS_T ws)
{
    if (!hub || !ws) return -1;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (hub->clients[i] == NULL) {
            hub->clients[i] = ws;
            hub->count++;
            return 0;
        }
    }
    return -1;
}

void
WebSocketHub_remove(WebSocketHub_T hub, SocketWS_T ws)
{
    if (!hub || !ws) return;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (hub->clients[i] == ws) {
            hub->clients[i] = NULL;
            hub->count--;
            return;
        }
    }
}

void
WebSocketHub_broadcast(WebSocketHub_T hub, const char *message, size_t len)
{
    if (!hub || !message) return;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        SocketWS_T ws = hub->clients[i];
        if (ws && SocketWS_state(ws) == WS_STATE_OPEN) {
            SocketWS_send_text(ws, message, len);
        }
    }
}

static char *
escape_json_value(const char *s)
{
    if (!s) return strdup("");

    size_t len = strlen(s);
    size_t cap = len * 2 + 1;
    char *out = malloc(cap);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (j + 6 > cap) {
            cap *= 2;
            char *newout = realloc(out, cap);
            if (!newout) { free(out); return NULL; }
            out = newout;
        }

        switch (s[i]) {
            case '"':  out[j++] = '\\'; out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            default:
                if ((unsigned char)s[i] < 32) {
                    j += snprintf(out + j, cap - j, "\\u%04x", (unsigned char)s[i]);
                } else {
                    out[j++] = s[i];
                }
        }
    }
    out[j] = '\0';
    return out;
}

void
WebSocketHub_broadcast_json(WebSocketHub_T hub,
                             const char *type,
                             const char *agent,
                             const char *avatar,
                             const char *text)
{
    if (!hub || !type) return;

    char *escaped_text = text ? escape_json_value(text) : NULL;
    char *escaped_agent = agent ? escape_json_value(agent) : NULL;

    char buffer[8192];
    int len;

    if (agent && avatar && text) {
        len = snprintf(buffer, sizeof(buffer),
            "{\"type\":\"%s\",\"agent\":\"%s\",\"avatar\":\"%s\",\"text\":\"%s\"}",
            type,
            escaped_agent ? escaped_agent : "",
            avatar,
            escaped_text ? escaped_text : "");
    } else if (agent) {
        len = snprintf(buffer, sizeof(buffer),
            "{\"type\":\"%s\",\"agent\":\"%s\"}",
            type,
            escaped_agent ? escaped_agent : "");
    } else if (text) {
        len = snprintf(buffer, sizeof(buffer),
            "{\"type\":\"%s\",\"text\":\"%s\"}",
            type,
            escaped_text ? escaped_text : "");
    } else {
        len = snprintf(buffer, sizeof(buffer), "{\"type\":\"%s\"}", type);
    }

    free(escaped_text);
    free(escaped_agent);

    if (len > 0 && (size_t)len < sizeof(buffer)) {
        WebSocketHub_broadcast(hub, buffer, len);
    }
}

int
WebSocketHub_count(WebSocketHub_T hub)
{
    return hub ? hub->count : 0;
}

void
WebSocketHub_foreach(WebSocketHub_T hub, WebSocketHub_Iterator fn, void *userdata)
{
    if (!hub || !fn) return;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (hub->clients[i]) {
            fn(hub->clients[i], userdata);
        }
    }
}
