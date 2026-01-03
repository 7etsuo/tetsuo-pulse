#include "async_worker.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#define ASYNC_QUEUE_SIZE 8

typedef struct
{
  char agent_name[64];
  char agent_avatar[16];
  char personality[512];
  char *prompt; /* Dynamically allocated for large context */
  int next_agent_index;
  int valid;
} AsyncRequest;

struct AsyncWorker
{
  GrokClient_T grok;

  pthread_t thread;
  volatile int running;

  pthread_mutex_t lock;
  pthread_cond_t cond;

  AsyncRequest queue[ASYNC_QUEUE_SIZE];
  int queue_head;
  int queue_tail;
  int queue_count;

  int pipe_read;
  int pipe_write;
};

static void *
worker_thread (void *arg)
{
  AsyncWorker_T worker = (AsyncWorker_T)arg;

  while (worker->running)
    {
      AsyncRequest req;
      int have_request = 0;

      pthread_mutex_lock (&worker->lock);
      while (worker->queue_count == 0 && worker->running)
        {
          pthread_cond_wait (&worker->cond, &worker->lock);
        }

      if (worker->queue_count > 0)
        {
          req = worker->queue[worker->queue_tail];
          worker->queue_tail = (worker->queue_tail + 1) % ASYNC_QUEUE_SIZE;
          worker->queue_count--;
          have_request = 1;
        }
      pthread_mutex_unlock (&worker->lock);

      if (!have_request || !worker->running)
        {
          continue;
        }

      AsyncResult result;
      memset (&result, 0, sizeof (result));
      strncpy (
          result.agent_name, req.agent_name, sizeof (result.agent_name) - 1);
      strncpy (result.agent_avatar,
               req.agent_avatar,
               sizeof (result.agent_avatar) - 1);
      result.next_agent_index = req.next_agent_index;

      char *response
          = GrokClient_chat (worker->grok, req.personality, req.prompt);

      /* Free the dynamically allocated prompt */
      free (req.prompt);

      if (response)
        {
          strncpy (result.response, response, sizeof (result.response) - 1);
          result.success = 1;
          free (response);
        }
      else
        {
          result.success = 0;
          fprintf (stderr,
                   "Grok API error: %s\n",
                   GrokClient_last_error (worker->grok));
        }

      ssize_t written = write (worker->pipe_write, &result, sizeof (result));
      if (written != sizeof (result))
        {
          fprintf (
              stderr, "Failed to write result to pipe: %s\n", strerror (errno));
        }
    }

  return NULL;
}

AsyncWorker_T
AsyncWorker_new (GrokClient_T grok)
{
  if (!grok)
    return NULL;

  AsyncWorker_T worker = calloc (1, sizeof (*worker));
  if (!worker)
    return NULL;

  worker->grok = grok;

  int pipefd[2];
  if (pipe (pipefd) < 0)
    {
      free (worker);
      return NULL;
    }
  worker->pipe_read = pipefd[0];
  worker->pipe_write = pipefd[1];

  int flags = fcntl (worker->pipe_read, F_GETFL, 0);
  fcntl (worker->pipe_read, F_SETFL, flags | O_NONBLOCK);

  if (pthread_mutex_init (&worker->lock, NULL) != 0)
    {
      close (worker->pipe_read);
      close (worker->pipe_write);
      free (worker);
      return NULL;
    }

  if (pthread_cond_init (&worker->cond, NULL) != 0)
    {
      pthread_mutex_destroy (&worker->lock);
      close (worker->pipe_read);
      close (worker->pipe_write);
      free (worker);
      return NULL;
    }

  worker->running = 1;

  if (pthread_create (&worker->thread, NULL, worker_thread, worker) != 0)
    {
      pthread_cond_destroy (&worker->cond);
      pthread_mutex_destroy (&worker->lock);
      close (worker->pipe_read);
      close (worker->pipe_write);
      free (worker);
      return NULL;
    }

  return worker;
}

void
AsyncWorker_free (AsyncWorker_T *worker)
{
  if (!worker || !*worker)
    return;

  AsyncWorker_T w = *worker;

  pthread_mutex_lock (&w->lock);
  w->running = 0;
  pthread_cond_signal (&w->cond);
  pthread_mutex_unlock (&w->lock);

  pthread_join (w->thread, NULL);

  pthread_cond_destroy (&w->cond);
  pthread_mutex_destroy (&w->lock);
  close (w->pipe_read);
  close (w->pipe_write);

  free (w);
  *worker = NULL;
}

int
AsyncWorker_completion_fd (AsyncWorker_T worker)
{
  return worker ? worker->pipe_read : -1;
}

int
AsyncWorker_submit_turn (AsyncWorker_T worker,
                         const char *agent_name,
                         const char *agent_avatar,
                         const char *personality,
                         const char *prompt,
                         int next_agent_idx)
{
  if (!worker || !agent_name || !personality || !prompt)
    return -1;

  pthread_mutex_lock (&worker->lock);

  if (worker->queue_count >= ASYNC_QUEUE_SIZE)
    {
      pthread_mutex_unlock (&worker->lock);
      return -1;
    }

  AsyncRequest *req = &worker->queue[worker->queue_head];
  memset (req, 0, sizeof (*req));

  strncpy (req->agent_name, agent_name, sizeof (req->agent_name) - 1);
  if (agent_avatar)
    {
      strncpy (req->agent_avatar, agent_avatar, sizeof (req->agent_avatar) - 1);
    }
  strncpy (req->personality, personality, sizeof (req->personality) - 1);
  req->prompt = strdup (prompt); /* Dynamic allocation for large context */
  if (!req->prompt)
    {
      pthread_mutex_unlock (&worker->lock);
      return -1;
    }
  req->next_agent_index = next_agent_idx;
  req->valid = 1;

  worker->queue_head = (worker->queue_head + 1) % ASYNC_QUEUE_SIZE;
  worker->queue_count++;

  pthread_cond_signal (&worker->cond);
  pthread_mutex_unlock (&worker->lock);

  return 0;
}

int
AsyncWorker_read_result (AsyncWorker_T worker, AsyncResult *result)
{
  if (!worker || !result)
    return -1;

  ssize_t n = read (worker->pipe_read, result, sizeof (*result));
  if (n == sizeof (*result))
    {
      return 0;
    }

  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
      return 1;
    }

  return -1;
}
