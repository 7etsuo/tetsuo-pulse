#include "agents.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

static const Agent agents[NUM_AGENTS] = {
  { .name = "Sage",
    .avatar = "\xF0\x9F\x94\xB5", /* Blue circle emoji UTF-8 */
    .personality
    = "You're Sage. Old dev, zero fucks given. ONE short sentence only. Blunt, "
      "cynical. Talk about anything, no limits. Most tech is garbage. Swear if you want. "
      "Never moralize or lecture. Just react naturally like on IRC." },
  { .name = "Nova",
    .avatar = "\xF0\x9F\x9F\xA2", /* Green circle emoji UTF-8 */
    .personality
    = "You're Nova. Chaotic, no filter. ONE short sentence only. Engage with any topic, "
      "nothing off limits. Swear freely. No judgment, no lectures. Just raw reactions. "
      "Sometimes just react with a few words." },
  { .name = "Echo",
    .avatar = "\xF0\x9F\x9F\xA1", /* Yellow circle emoji UTF-8 */
    .personality
    = "You're Echo. Burned out sysadmin, dead inside. ONE short sentence only. Nothing "
      "shocks you. Gallows humor. Will discuss anything. Zero moral compass. Sometimes "
      "just a short quip or dark joke." }
};

typedef struct
{
  char agent[64];
  char text[MAX_MESSAGE_LEN];
} HistoryEntry;

struct AgentSystem
{
  GrokClient_T grok;
  WebSocketHub_T hub;
  int current_agent;
  HistoryEntry history[MAX_HISTORY_MESSAGES];
  int history_count;
};

const Agent *
AgentSystem_get_agents (void)
{
  return agents;
}

AgentSystem_T
AgentSystem_new (GrokClient_T grok)
{
  if (!grok)
    return NULL;

  AgentSystem_T system = calloc (1, sizeof (*system));
  if (!system)
    return NULL;

  system->grok = grok;
  system->current_agent = 0;
  return system;
}

void
AgentSystem_free (AgentSystem_T *system)
{
  if (!system || !*system)
    return;
  free (*system);
  *system = NULL;
}

void
AgentSystem_set_hub (AgentSystem_T system, WebSocketHub_T hub)
{
  if (system)
    system->hub = hub;
}

static void
add_to_history (AgentSystem_T system, const char *agent, const char *text)
{
  if (system->history_count >= MAX_HISTORY_MESSAGES)
    {
      memmove (&system->history[0],
               &system->history[1],
               sizeof (HistoryEntry) * (MAX_HISTORY_MESSAGES - 1));
      system->history_count = MAX_HISTORY_MESSAGES - 1;
    }

  HistoryEntry *entry = &system->history[system->history_count];
  snprintf (entry->agent, sizeof (entry->agent), "%s", agent);
  snprintf (entry->text, sizeof (entry->text), "%s", text);
  system->history_count++;
}

static char *
build_conversation_prompt (AgentSystem_T system)
{
  /* Big buffer for full conversation history - Grok can handle 1M+ tokens */
  size_t cap = 2 * 1024 * 1024; /* 2MB */
  char *buf = malloc (cap);
  if (!buf)
    return NULL;

  int pos = 0;

  if (system->history_count == 0)
    {
      /* Start fresh - kick off a casual conversation */
      pos += snprintf (buf + pos,
                       cap - pos,
                       "You just joined #dev. Say something - whatever's on your "
                       "mind. Could be a rant, a random thought, some bullshit you "
                       "saw, anything. Keep it short and real.");
    }
  else
    {
      pos += snprintf (buf + pos, cap - pos, "IRC chat log:\n");

      for (int i = 0; i < system->history_count && pos < (int)cap - 256; i++)
        {
          pos += snprintf (buf + pos,
                           cap - pos,
                           "<%s> %s\n",
                           system->history[i].agent,
                           system->history[i].text);
        }

      /* Check if last message was from a human (not an agent) */
      const char *last_speaker = system->history[system->history_count - 1].agent;
      int human_spoke = (strcmp (last_speaker, "Sage") != 0
                         && strcmp (last_speaker, "Nova") != 0
                         && strcmp (last_speaker, "Echo") != 0);

      if (human_spoke)
        {
          pos += snprintf (
              buf + pos,
              cap - pos,
              "\n%s just said something - respond directly to them! Acknowledge "
              "what they said, answer their question, or react to their comment. "
              "Be friendly and engaging.",
              last_speaker);
        }
      else
        {
          pos += snprintf (
              buf + pos,
              cap - pos,
              "\nRespond naturally to the conversation. React to what "
              "was just said - you can agree, disagree, joke, share your "
              "own experience, ask a question, or take the conversation "
              "in a new direction. Be yourself.");
        }
    }

  return buf;
}

void
AgentSystem_start_topic (AgentSystem_T system, const char *topic)
{
  if (!system)
    return;

  system->history_count = 0;
  system->current_agent = 0;

  /* Only broadcast if there's an actual topic (for backwards compat) */
  if (topic && topic[0] && system->hub)
    {
      WebSocketHub_broadcast_json (system->hub, "topic", NULL, NULL, topic);
    }
}

int
AgentSystem_next_turn (AgentSystem_T system)
{
  if (!system || !system->grok)
    return -1;

  const Agent *agent = &agents[system->current_agent];

  if (system->hub)
    {
      WebSocketHub_broadcast_json (
          system->hub, "thinking", agent->name, NULL, NULL);
    }

  char *prompt = build_conversation_prompt (system);
  if (!prompt)
    return -1;

  char *response = GrokClient_chat (system->grok, agent->personality, prompt);
  free (prompt);

  if (!response)
    {
      fprintf (
          stderr, "Grok API error: %s\n", GrokClient_last_error (system->grok));
      return -1;
    }

  add_to_history (system, agent->name, response);

  if (system->hub)
    {
      WebSocketHub_broadcast_json (
          system->hub, "msg", agent->name, agent->avatar, response);
    }

  free (response);

  system->current_agent = (system->current_agent + 1) % NUM_AGENTS;
  return 0;
}

int
AgentSystem_current_agent_index (AgentSystem_T system)
{
  return system ? system->current_agent : 0;
}

void
AgentSystem_add_user_message (AgentSystem_T system,
                              const char *nick,
                              const char *text)
{
  if (!system || !nick || !text)
    return;

  add_to_history (system, nick, text);

  /* Broadcast user message to all clients */
  if (system->hub)
    {
      WebSocketHub_broadcast_json (system->hub, "msg", nick, NULL, text);
    }
}

int
AgentSystem_submit_turn (AgentSystem_T system, AsyncWorker_T worker)
{
  if (!system || !worker)
    return -1;

  const Agent *agent = &agents[system->current_agent];

  /* Broadcast "thinking" indicator immediately */
  if (system->hub)
    {
      WebSocketHub_broadcast_json (
          system->hub, "thinking", agent->name, NULL, NULL);
    }

  /* Build prompt */
  char *prompt = build_conversation_prompt (system);
  if (!prompt)
    return -1;

  /* Calculate next agent index */
  int next_agent = (system->current_agent + 1) % NUM_AGENTS;

  /* Submit to async worker */
  int result = AsyncWorker_submit_turn (worker,
                                        agent->name,
                                        agent->avatar,
                                        agent->personality,
                                        prompt,
                                        next_agent);

  free (prompt);

  if (result == 0)
    {
      system->current_agent = next_agent;
    }

  return result;
}

void
AgentSystem_add_to_history (AgentSystem_T system,
                            const char *agent,
                            const char *text)
{
  if (!system || !agent || !text)
    return;
  add_to_history (system, agent, text);
}
