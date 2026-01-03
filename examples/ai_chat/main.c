/*
 * AI Agent WebSocket Chat Demo
 *
 * Three AI agents (Sage, Nova, Echo) debate tech topics using Grok API.
 * Connect via browser at http://localhost:8080 to watch.
 *
 * Requires XAI_API_KEY environment variable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <curl/curl.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketTimer.h"
#include "http/SocketHTTPServer.h"
#include "poll/SocketPoll.h"
#include "socket/SocketWS.h"

#include "grok_client.h"
#include "websocket_hub.h"
#include "agents.h"

#define PORT 8080
#define AGENT_TURN_DELAY_MS 5000
#define THINKING_DELAY_MS 2000

static volatile int running = 1;
static SocketHTTPServer_T server = NULL;
static WebSocketHub_T hub = NULL;
static AgentSystem_T agent_system = NULL;
static SocketPoll_T poll_instance = NULL;

static void
signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* Embedded HTML frontend - IRC style */
static const char *INDEX_HTML =
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"  <meta charset=\"UTF-8\">\n"
"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
"  <title>#ai-debate</title>\n"
"  <style>\n"
"    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
"    body {\n"
"      font-family: 'Courier New', Consolas, monospace;\n"
"      background: #0a0a0a; color: #c0c0c0;\n"
"      height: 100vh; display: flex; flex-direction: column;\n"
"    }\n"
"    #header {\n"
"      background: #1a1a1a; padding: 8px 12px;\n"
"      border-bottom: 1px solid #333;\n"
"      display: flex; justify-content: space-between; align-items: center;\n"
"    }\n"
"    #header .channel { color: #5f9; font-weight: bold; }\n"
"    #header .topic { color: #f95; font-size: 0.9em; margin-left: 1em; }\n"
"    #header .status { font-size: 0.85em; }\n"
"    .connected { color: #5f9; }\n"
"    .disconnected { color: #f55; }\n"
"    #messages {\n"
"      flex: 1; overflow-y: auto; padding: 8px 12px;\n"
"      font-size: 14px; line-height: 1.4;\n"
"    }\n"
"    .line { white-space: pre-wrap; word-wrap: break-word; }\n"
"    .line .time { color: #666; }\n"
"    .line .nick { font-weight: bold; }\n"
"    .line .nick.sage { color: #59f; }\n"
"    .line .nick.nova { color: #5f9; }\n"
"    .line .nick.echo { color: #fd5; }\n"
"    .line .nick.server { color: #f5f; }\n"
"    .line .text { color: #ddd; }\n"
"    .line.action { color: #888; font-style: italic; }\n"
"    .line.join { color: #5a5; }\n"
"    .line.topic { color: #f95; }\n"
"  </style>\n"
"</head>\n"
"<body>\n"
"  <div id=\"header\">\n"
"    <div>\n"
"      <span class=\"channel\">#ai-debate</span>\n"
"      <span class=\"topic\" id=\"topic\"></span>\n"
"    </div>\n"
"    <span id=\"status\" class=\"status\">connecting...</span>\n"
"  </div>\n"
"  <div id=\"messages\"></div>\n"
"  <script>\n"
"    const messagesEl = document.getElementById('messages');\n"
"    const topicEl = document.getElementById('topic');\n"
"    const statusEl = document.getElementById('status');\n"
"    function timestamp() {\n"
"      const d = new Date();\n"
"      return d.toTimeString().slice(0, 8);\n"
"    }\n"
"    function addLine(html, cls) {\n"
"      const div = document.createElement('div');\n"
"      div.className = 'line' + (cls ? ' ' + cls : '');\n"
"      div.innerHTML = html;\n"
"      messagesEl.appendChild(div);\n"
"      messagesEl.scrollTop = messagesEl.scrollHeight;\n"
"    }\n"
"    function escapeHtml(text) {\n"
"      const div = document.createElement('div');\n"
"      div.textContent = text;\n"
"      return div.innerHTML;\n"
"    }\n"
"    function connect() {\n"
"      const ws = new WebSocket('ws://' + location.host + '/ws');\n"
"      ws.onopen = () => {\n"
"        statusEl.className = 'status connected';\n"
"        statusEl.textContent = 'connected';\n"
"        addLine('<span class=\"time\">[' + timestamp() + ']</span> <span class=\"nick server\">***</span> <span class=\"text\">Connected to server</span>', 'join');\n"
"      };\n"
"      ws.onclose = () => {\n"
"        statusEl.className = 'status disconnected';\n"
"        statusEl.textContent = 'disconnected';\n"
"        addLine('<span class=\"time\">[' + timestamp() + ']</span> <span class=\"nick server\">***</span> <span class=\"text\">Disconnected, reconnecting...</span>');\n"
"        setTimeout(connect, 2000);\n"
"      };\n"
"      ws.onmessage = (e) => {\n"
"        const data = JSON.parse(e.data);\n"
"        if (data.type === 'topic') {\n"
"          topicEl.textContent = data.text;\n"
"          addLine('<span class=\"time\">[' + timestamp() + ']</span> <span class=\"nick server\">***</span> <span class=\"text\">Topic: ' + escapeHtml(data.text) + '</span>', 'topic');\n"
"        } else if (data.type === 'thinking') {\n"
"          addLine('<span class=\"time\">[' + timestamp() + ']</span> <span class=\"nick server\">*</span> <span class=\"text\">' + data.agent + ' is typing...</span>', 'action');\n"
"        } else if (data.type === 'msg') {\n"
"          const nc = data.agent.toLowerCase();\n"
"          addLine('<span class=\"time\">[' + timestamp() + ']</span> &lt;<span class=\"nick ' + nc + '\">' + data.agent + '</span>&gt; <span class=\"text\">' + escapeHtml(data.text) + '</span>');\n"
"        }\n"
"      };\n"
"    }\n"
"    connect();\n"
"  </script>\n"
"</body>\n"
"</html>\n";

typedef struct {
    AgentSystem_T agents;
    SocketPoll_T poll;
} TimerContext;

static void
schedule_next_turn(SocketPoll_T poll, AgentSystem_T agents);

static void
agent_turn_callback(void *userdata)
{
    TimerContext *ctx = (TimerContext *)userdata;

    if (!running) {
        free(ctx);
        return;
    }

    if (AgentSystem_next_turn(ctx->agents) == 0) {
        schedule_next_turn(ctx->poll, ctx->agents);
    } else {
        fprintf(stderr, "Agent turn failed, retrying in 10s\n");
        TimerContext *new_ctx = malloc(sizeof(*new_ctx));
        if (new_ctx) {
            new_ctx->agents = ctx->agents;
            new_ctx->poll = ctx->poll;
            SocketTimer_add(ctx->poll, 10000, agent_turn_callback, new_ctx);
        }
    }
    free(ctx);
}

static void
schedule_next_turn(SocketPoll_T poll, AgentSystem_T agents)
{
    TimerContext *ctx = malloc(sizeof(*ctx));
    if (!ctx) return;

    ctx->agents = agents;
    ctx->poll = poll;

    int delay = AGENT_TURN_DELAY_MS + (rand() % 3000);
    SocketTimer_add(poll, delay, agent_turn_callback, ctx);
}

static void
http_handler(SocketHTTPServer_Request_T req, void *userdata)
{
    (void)userdata;

    const char *path = SocketHTTPServer_Request_path(req);

    if (SocketHTTPServer_Request_is_websocket(req)) {
        SocketWS_T ws = SocketHTTPServer_Request_upgrade_websocket(req, NULL, NULL);
        if (ws) {
            WebSocketHub_add(hub, ws);
            printf("WebSocket client connected (total: %d)\n", WebSocketHub_count(hub));
        }
        return;
    }

    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        SocketHTTPServer_Request_status(req, 200);
        SocketHTTPServer_Request_header(req, "Content-Type", "text/html; charset=utf-8");
        SocketHTTPServer_Request_body_string(req, INDEX_HTML);
        SocketHTTPServer_Request_finish(req);
        return;
    }

    SocketHTTPServer_Request_status(req, 404);
    SocketHTTPServer_Request_header(req, "Content-Type", "text/plain");
    SocketHTTPServer_Request_body_string(req, "Not Found");
    SocketHTTPServer_Request_finish(req);
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    const char *api_key = getenv("XAI_API_KEY");
    if (!api_key) {
        fprintf(stderr, "Error: XAI_API_KEY environment variable not set\n");
        fprintf(stderr, "Get your API key from https://console.x.ai/\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    srand((unsigned)time(NULL));

    curl_global_init(CURL_GLOBAL_DEFAULT);

    printf("AI Agent Chat Demo\n");
    printf("==================\n\n");

    GrokClient_Config grok_config = {
        .api_key = api_key,
        .model = NULL,  /* Use default model */
        .timeout_ms = 30000
    };

    GrokClient_T grok = GrokClient_new(&grok_config);
    if (!grok) {
        fprintf(stderr, "Failed to create Grok client\n");
        curl_global_cleanup();
        return 1;
    }

    hub = WebSocketHub_new();
    if (!hub) {
        fprintf(stderr, "Failed to create WebSocket hub\n");
        GrokClient_free(&grok);
        curl_global_cleanup();
        return 1;
    }

    agent_system = AgentSystem_new(grok);
    if (!agent_system) {
        fprintf(stderr, "Failed to create agent system\n");
        WebSocketHub_free(&hub);
        GrokClient_free(&grok);
        curl_global_cleanup();
        return 1;
    }
    AgentSystem_set_hub(agent_system, hub);

    SocketHTTPServer_Config config;
    SocketHTTPServer_config_defaults(&config);
    config.port = PORT;
    config.bind_address = "0.0.0.0";

    TRY {
        server = SocketHTTPServer_new(&config);
        SocketHTTPServer_set_handler(server, http_handler, NULL);

        if (SocketHTTPServer_start(server) < 0) {
            fprintf(stderr, "Failed to start server\n");
            RAISE(SocketHTTPServer_Failed);
        }

        poll_instance = SocketHTTPServer_poll(server);

        printf("Server running on http://localhost:%d\n", PORT);
        printf("Open this URL in your browser to watch the debate.\n\n");

        const char *topic = AgentSystem_random_topic();
        printf("Topic: %s\n\n", topic);
        AgentSystem_start_topic(agent_system, topic);

        schedule_next_turn(poll_instance, agent_system);

        while (running) {
            SocketHTTPServer_process(server, 100);
        }

        printf("\nShutting down...\n");

    } EXCEPT(SocketHTTPServer_Failed) {
        fprintf(stderr, "HTTP Server error\n");
    } EXCEPT(SocketHTTPServer_BindFailed) {
        fprintf(stderr, "Failed to bind to port %d (already in use?)\n", PORT);
    } END_TRY;

    if (server) {
        SocketHTTPServer_stop(server);
        SocketHTTPServer_free(&server);
    }

    AgentSystem_free(&agent_system);
    WebSocketHub_free(&hub);
    GrokClient_free(&grok);
    curl_global_cleanup();

    printf("Goodbye!\n");
    return 0;
}
