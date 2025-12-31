/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

// libevent echo server
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LE_PORT 8082

static void
read_cb (struct bufferevent *bev, void *ctx)
{
  (void)ctx;
  struct evbuffer *input = bufferevent_get_input (bev);
  struct evbuffer *output = bufferevent_get_output (bev);

  // Move data from input to output (echo)
  evbuffer_add_buffer (output, input);
}

static void
event_cb (struct bufferevent *bev, short events, void *ctx)
{
  (void)ctx;
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
      bufferevent_free (bev);
    }
}

static void
accept_conn_cb (struct evconnlistener *listener,
                int fd,
                struct sockaddr *addr,
                int socklen,
                void *arg)
{
  (void)addr;
  (void)socklen;
  (void)arg;
  struct event_base *base = evconnlistener_get_base (listener);
  struct bufferevent *bev
      = bufferevent_socket_new (base, fd, BEV_OPT_CLOSE_ON_FREE);

  bufferevent_setcb (bev, read_cb, NULL, event_cb, NULL);
  bufferevent_enable (bev, EV_READ | EV_WRITE);
}

static void
signal_cb (evutil_socket_t sig, short events, void *user_data)
{
  (void)sig;
  (void)events;
  struct event_base *base = user_data;
  event_base_loopbreak (base);
}

int
main ()
{
  struct event_base *base = event_base_new ();
  struct evconnlistener *listener;
  struct sockaddr_in sin = { .sin_family = AF_INET,
                             .sin_addr.s_addr = 0,
                             .sin_port = htons (LE_PORT) };

  signal (SIGPIPE, SIG_IGN);

  listener = evconnlistener_new_bind (base,
                                      accept_conn_cb,
                                      base,
                                      LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                      -1,
                                      (struct sockaddr *)&sin,
                                      sizeof (sin));

  if (!listener)
    {
      fprintf (stderr, "Could not create listener\n");
      return 1;
    }

  // Handle SIGINT and SIGTERM for graceful shutdown
  struct event *sigint_event = evsignal_new (base, SIGINT, signal_cb, base);
  struct event *sigterm_event = evsignal_new (base, SIGTERM, signal_cb, base);
  evsignal_add (sigint_event, NULL);
  evsignal_add (sigterm_event, NULL);

  printf ("libevent server on port %d\n", LE_PORT);
  event_base_dispatch (base);

  evconnlistener_free (listener);
  event_base_free (base);
  return 0;
}
