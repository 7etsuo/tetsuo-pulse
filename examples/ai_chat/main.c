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

/* Embedded HTML frontend */
static const char *INDEX_HTML =
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"  <meta charset=\"UTF-8\">\n"
"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
"  <title>AI Agents Debate</title>\n"
"  <style>\n"
"    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
"    body {\n"
"      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;\n"
"      background: #1a1a2e; color: #eee; min-height: 100vh;\n"
"      display: flex; flex-direction: column;\n"
"    }\n"
"    header {\n"
"      background: #16213e; padding: 1rem 2rem;\n"
"      border-bottom: 2px solid #0f3460;\n"
"    }\n"
"    header h1 { font-size: 1.5rem; }\n"
"    header p { color: #888; font-size: 0.9rem; margin-top: 0.25rem; }\n"
"    #topic {\n"
"      background: #0f3460; padding: 1rem 2rem;\n"
"      font-style: italic; color: #e94560;\n"
"    }\n"
"    #messages {\n"
"      flex: 1; overflow-y: auto; padding: 1rem 2rem;\n"
"      display: flex; flex-direction: column; gap: 1rem;\n"
"    }\n"
"    .message {\n"
"      background: #16213e; border-radius: 12px; padding: 1rem;\n"
"      max-width: 80%; animation: fadeIn 0.3s ease;\n"
"    }\n"
"    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } }\n"
"    .message .header {\n"
"      display: flex; align-items: center; gap: 0.5rem;\n"
"      margin-bottom: 0.5rem; font-weight: 600;\n"
"    }\n"
"    .message .avatar { font-size: 1.2rem; }\n"
"    .message .text { line-height: 1.5; }\n"
"    .thinking {\n"
"      color: #888; font-style: italic;\n"
"      display: flex; align-items: center; gap: 0.5rem;\n"
"    }\n"
"    .thinking .dots { animation: pulse 1s infinite; }\n"
"    @keyframes pulse { 50% { opacity: 0.5; } }\n"
"    #status {\n"
"      background: #16213e; padding: 0.5rem 2rem;\n"
"      font-size: 0.8rem; color: #888;\n"
"      border-top: 1px solid #0f3460;\n"
"    }\n"
"    .connected { color: #4ade80; }\n"
"    .disconnected { color: #f87171; }\n"
"  </style>\n"
"</head>\n"
"<body>\n"
"  <header>\n"
"    <h1>AI Agents Debate</h1>\n"
"    <p>Watch Sage, Nova, and Echo discuss tech topics</p>\n"
"  </header>\n"
"  <div id=\"topic\">Connecting...</div>\n"
"  <div id=\"messages\"></div>\n"
"  <div id=\"status\">Connecting...</div>\n"
"  <script>\n"
"    const messagesEl = document.getElementById('messages');\n"
"    const topicEl = document.getElementById('topic');\n"
"    const statusEl = document.getElementById('status');\n"
"    let thinkingEl = null;\n"
"\n"
"    function connect() {\n"
"      const ws = new WebSocket(`ws://${location.host}/ws`);\n"
"\n"
"      ws.onopen = () => {\n"
"        statusEl.innerHTML = '<span class=\"connected\">Connected</span>';\n"
"      };\n"
"\n"
"      ws.onclose = () => {\n"
"        statusEl.innerHTML = '<span class=\"disconnected\">Disconnected - Reconnecting...</span>';\n"
"        setTimeout(connect, 2000);\n"
"      };\n"
"\n"
"      ws.onmessage = (e) => {\n"
"        const data = JSON.parse(e.data);\n"
"\n"
"        if (data.type === 'topic') {\n"
"          topicEl.textContent = data.text;\n"
"          messagesEl.innerHTML = '';\n"
"        } else if (data.type === 'thinking') {\n"
"          if (thinkingEl) thinkingEl.remove();\n"
"          thinkingEl = document.createElement('div');\n"
"          thinkingEl.className = 'thinking';\n"
"          thinkingEl.innerHTML = `<span>${data.agent} is thinking</span><span class=\"dots\">...</span>`;\n"
"          messagesEl.appendChild(thinkingEl);\n"
"          messagesEl.scrollTop = messagesEl.scrollHeight;\n"
"        } else if (data.type === 'msg') {\n"
"          if (thinkingEl) { thinkingEl.remove(); thinkingEl = null; }\n"
"          const msg = document.createElement('div');\n"
"          msg.className = 'message';\n"
"          msg.innerHTML = `\n"
"            <div class=\"header\">\n"
"              <span class=\"avatar\">${data.avatar}</span>\n"
"              <span>${data.agent}</span>\n"
"            </div>\n"
"            <div class=\"text\">${data.text}</div>\n"
"          `;\n"
"          messagesEl.appendChild(msg);\n"
"          messagesEl.scrollTop = messagesEl.scrollHeight;\n"
"        }\n"
"      };\n"
"    }\n"
"\n"
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
        .model = "grok-beta",
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
