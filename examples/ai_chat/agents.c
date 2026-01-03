#include "agents.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

static const Agent agents[NUM_AGENTS] = {
    {
        .name = "Sage",
        .avatar = "\xF0\x9F\x94\xB5",  /* Blue circle emoji UTF-8 */
        .personality =
            "You are Sage, a thoughtful senior engineer who values pragmatism "
            "and maintainability. You prefer proven solutions over trendy tech. "
            "You speak calmly and reference real-world experience. "
            "Keep responses to 2-3 sentences. Respond directly to what others said."
    },
    {
        .name = "Nova",
        .avatar = "\xF0\x9F\x9F\xA2",  /* Green circle emoji UTF-8 */
        .personality =
            "You are Nova, an enthusiastic developer who loves new technologies "
            "and innovative approaches. You challenge conventional wisdom and "
            "get excited about possibilities. Keep responses to 2-3 sentences. "
            "Respond directly to what others said."
    },
    {
        .name = "Echo",
        .avatar = "\xF0\x9F\x9F\xA1",  /* Yellow circle emoji UTF-8 */
        .personality =
            "You are Echo, a skeptical systems programmer who asks probing "
            "questions and finds edge cases. You value correctness and performance. "
            "You often play devil's advocate. Keep responses to 2-3 sentences. "
            "Respond directly to what others said."
    }
};

static const char *topics[] = {
    "Is Rust worth the learning curve over C for systems programming?",
    "Microservices vs monoliths: which scales better for startups?",
    "Should we still be writing unit tests, or are integration tests enough?",
    "Is GraphQL overhyped, or genuinely better than REST?",
    "Tabs vs spaces: let's settle this once and for all.",
    "Is AI-generated code actually useful, or just fancy autocomplete?",
    "Is Kubernetes overkill for most projects?",
    "Should every developer learn to use the terminal, or are GUIs fine?",
    "Is TDD actually practical, or just an idealistic dream?",
    "Are ORMs helping or hurting database performance?",
    NULL
};

typedef struct {
    char agent[64];
    char text[MAX_MESSAGE_LEN];
} HistoryEntry;

struct AgentSystem {
    GrokClient_T grok;
    WebSocketHub_T hub;
    int current_agent;
    HistoryEntry history[MAX_HISTORY_MESSAGES];
    int history_count;
    char current_topic[512];
};

const Agent *
AgentSystem_get_agents(void)
{
    return agents;
}

const char *
AgentSystem_random_topic(void)
{
    int count = 0;
    while (topics[count]) count++;

    srand((unsigned)time(NULL));
    return topics[rand() % count];
}

AgentSystem_T
AgentSystem_new(GrokClient_T grok)
{
    if (!grok) return NULL;

    AgentSystem_T system = calloc(1, sizeof(*system));
    if (!system) return NULL;

    system->grok = grok;
    system->current_agent = 0;
    return system;
}

void
AgentSystem_free(AgentSystem_T *system)
{
    if (!system || !*system) return;
    free(*system);
    *system = NULL;
}

void
AgentSystem_set_hub(AgentSystem_T system, WebSocketHub_T hub)
{
    if (system) system->hub = hub;
}

static void
add_to_history(AgentSystem_T system, const char *agent, const char *text)
{
    if (system->history_count >= MAX_HISTORY_MESSAGES) {
        memmove(&system->history[0], &system->history[1],
                sizeof(HistoryEntry) * (MAX_HISTORY_MESSAGES - 1));
        system->history_count = MAX_HISTORY_MESSAGES - 1;
    }

    HistoryEntry *entry = &system->history[system->history_count];
    snprintf(entry->agent, sizeof(entry->agent), "%s", agent);
    snprintf(entry->text, sizeof(entry->text), "%s", text);
    system->history_count++;
}

static char *
build_conversation_prompt(AgentSystem_T system)
{
    size_t cap = 8192;
    char *buf = malloc(cap);
    if (!buf) return NULL;

    int pos = 0;
    pos += snprintf(buf + pos, cap - pos,
        "You are in a group chat debating this topic: %s\n\n"
        "Recent conversation:\n",
        system->current_topic);

    for (int i = 0; i < system->history_count && pos < (int)cap - 256; i++) {
        pos += snprintf(buf + pos, cap - pos, "%s: %s\n",
            system->history[i].agent, system->history[i].text);
    }

    pos += snprintf(buf + pos, cap - pos,
        "\nIt's your turn to respond. Be conversational and engage with "
        "what others said. Keep it to 2-3 sentences.");

    return buf;
}

void
AgentSystem_start_topic(AgentSystem_T system, const char *topic)
{
    if (!system || !topic) return;

    snprintf(system->current_topic, sizeof(system->current_topic), "%s", topic);
    system->history_count = 0;
    system->current_agent = 0;

    if (system->hub) {
        WebSocketHub_broadcast_json(system->hub, "topic", NULL, NULL, topic);
    }
}

int
AgentSystem_next_turn(AgentSystem_T system)
{
    if (!system || !system->grok) return -1;

    const Agent *agent = &agents[system->current_agent];

    if (system->hub) {
        WebSocketHub_broadcast_json(system->hub, "thinking", agent->name, NULL, NULL);
    }

    char *prompt = build_conversation_prompt(system);
    if (!prompt) return -1;

    char *response = GrokClient_chat(system->grok, agent->personality, prompt);
    free(prompt);

    if (!response) {
        fprintf(stderr, "Grok API error: %s\n", GrokClient_last_error(system->grok));
        return -1;
    }

    add_to_history(system, agent->name, response);

    if (system->hub) {
        WebSocketHub_broadcast_json(system->hub, "msg",
            agent->name, agent->avatar, response);
    }

    free(response);

    system->current_agent = (system->current_agent + 1) % NUM_AGENTS;
    return 0;
}

int
AgentSystem_current_agent_index(AgentSystem_T system)
{
    return system ? system->current_agent : 0;
}
