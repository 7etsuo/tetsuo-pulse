#ifndef ASYNC_WORKER_H
#define ASYNC_WORKER_H

#include "grok_client.h"

#define ASYNC_MAX_RESPONSE_LEN 8192

typedef struct AsyncWorker *AsyncWorker_T;

typedef struct
{
  int success;
  char agent_name[64];
  char agent_avatar[16];
  char response[ASYNC_MAX_RESPONSE_LEN];
  int next_agent_index;
} AsyncResult;

AsyncWorker_T AsyncWorker_new (GrokClient_T grok);
void AsyncWorker_free (AsyncWorker_T *worker);

int AsyncWorker_completion_fd (AsyncWorker_T worker);

int AsyncWorker_submit_turn (AsyncWorker_T worker,
                             const char *agent_name,
                             const char *agent_avatar,
                             const char *personality,
                             const char *prompt,
                             int next_agent_idx);

int AsyncWorker_read_result (AsyncWorker_T worker, AsyncResult *result);

#endif /* ASYNC_WORKER_H */
