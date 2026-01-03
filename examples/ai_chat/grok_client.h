#ifndef GROK_CLIENT_H
#define GROK_CLIENT_H

#include <stddef.h>

typedef struct GrokClient *GrokClient_T;

typedef struct {
    const char *api_key;
    const char *model;
    int timeout_ms;
} GrokClient_Config;

GrokClient_T GrokClient_new(const GrokClient_Config *config);
void GrokClient_free(GrokClient_T *client);

char *GrokClient_chat(GrokClient_T client,
                      const char *system_prompt,
                      const char *conversation_history);

const char *GrokClient_last_error(GrokClient_T client);

#endif /* GROK_CLIENT_H */
