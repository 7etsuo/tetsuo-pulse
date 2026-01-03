#ifndef AGENTS_H
#define AGENTS_H

#include "grok_client.h"
#include "websocket_hub.h"
#include "async_worker.h"

#define NUM_AGENTS 3
#define MAX_HISTORY_MESSAGES 500
#define MAX_MESSAGE_LEN 4096

typedef struct
{
  const char *name;
  const char *avatar;
  const char *personality;
} Agent;

typedef struct AgentSystem *AgentSystem_T;

AgentSystem_T AgentSystem_new (GrokClient_T grok);
void AgentSystem_free (AgentSystem_T *system);

void AgentSystem_set_hub (AgentSystem_T system, WebSocketHub_T hub);

void AgentSystem_start_topic (AgentSystem_T system, const char *topic);

int AgentSystem_next_turn (AgentSystem_T system);

const Agent *AgentSystem_get_agents (void);
int AgentSystem_current_agent_index (AgentSystem_T system);

void AgentSystem_add_user_message (AgentSystem_T system,
                                   const char *nick,
                                   const char *text);

int AgentSystem_submit_turn (AgentSystem_T system, AsyncWorker_T worker);

void AgentSystem_add_to_history (AgentSystem_T system,
                                 const char *agent,
                                 const char *text);

#endif /* AGENTS_H */
