#ifndef AGENTS_H
#define AGENTS_H

#include "grok_client.h"
#include "websocket_hub.h"

#define NUM_AGENTS 3
#define MAX_HISTORY_MESSAGES 10
#define MAX_MESSAGE_LEN 2048

typedef struct {
    const char *name;
    const char *avatar;
    const char *personality;
} Agent;

typedef struct AgentSystem *AgentSystem_T;

AgentSystem_T AgentSystem_new(GrokClient_T grok);
void AgentSystem_free(AgentSystem_T *system);

void AgentSystem_set_hub(AgentSystem_T system, WebSocketHub_T hub);

void AgentSystem_start_topic(AgentSystem_T system, const char *topic);

int AgentSystem_next_turn(AgentSystem_T system);

const Agent *AgentSystem_get_agents(void);
int AgentSystem_current_agent_index(AgentSystem_T system);

const char *AgentSystem_random_topic(void);

#endif /* AGENTS_H */
