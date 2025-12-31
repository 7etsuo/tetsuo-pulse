/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_simple_poll_udp.c - UDP socket validation in poll functions
 * Tests for issue #2292: Consistent UDP socket validation across poll functions
 */

#include <stdlib.h>
#include <string.h>

#include "simple/SocketSimple-poll.h"
#include "simple/SocketSimple.h"
#include "socket/Socket.h"
#include "socket/SocketDgram.h"
#include "test/Test.h"

/* Internal structure for testing (from SocketSimple-internal.h) */
struct SocketSimple_Socket
{
  void *socket; /* Socket_T */
  void *dgram;  /* SocketDgram_T */
#ifdef SOCKET_HAS_TLS
  void *tls_ctx; /* SocketTLSContext_T */
#endif
  int is_tls;
  int is_server;
  int is_connected;
  int is_udp;
};

/* Helper to create a fake UDP socket for testing */
static struct SocketSimple_Socket *
create_fake_udp_socket (void)
{
  struct SocketSimple_Socket *sock
      = calloc (1, sizeof (struct SocketSimple_Socket));
  if (!sock)
    return NULL;

  /* Fake dgram pointer (non-NULL to trigger dgram check) */
  sock->dgram = (void *)0x1; /* Non-NULL fake pointer */
  sock->socket = NULL;
  sock->is_udp = 1;

  return sock;
}

/* Test that poll_add rejects UDP sockets */
static void
test_simple_poll_add_rejects_udp (void)
{
  SocketSimple_Poll_T poll = Socket_simple_poll_new (10);
  ASSERT_NOT_NULL (poll);

  struct SocketSimple_Socket *udp_sock = create_fake_udp_socket ();
  ASSERT_NOT_NULL (udp_sock);

  /* Try to add UDP socket to poll - should fail */
  int result = Socket_simple_poll_add (
      poll, (SocketSimple_Socket_T)udp_sock, SOCKET_SIMPLE_POLL_READ, NULL);
  ASSERT_EQ (-1, result);

  /* Verify error message */
  const char *error = Socket_simple_error ();
  ASSERT_NOT_NULL (error);
  ASSERT_NOT_NULL (strstr (error, "UDP sockets not supported"));

  free (udp_sock);
  Socket_simple_poll_free (&poll);
}

/* Test that poll_mod rejects UDP sockets */
static void
test_simple_poll_mod_rejects_udp (void)
{
  SocketSimple_Poll_T poll = Socket_simple_poll_new (10);
  ASSERT_NOT_NULL (poll);

  struct SocketSimple_Socket *udp_sock = create_fake_udp_socket ();
  ASSERT_NOT_NULL (udp_sock);

  /* Try to modify UDP socket in poll - should fail */
  int result = Socket_simple_poll_mod (
      poll, (SocketSimple_Socket_T)udp_sock, SOCKET_SIMPLE_POLL_WRITE, NULL);
  ASSERT_EQ (-1, result);

  /* Verify error message */
  const char *error = Socket_simple_error ();
  ASSERT_NOT_NULL (error);
  ASSERT_NOT_NULL (strstr (error, "UDP sockets not supported"));

  free (udp_sock);
  Socket_simple_poll_free (&poll);
}

/* Test that poll_del rejects UDP sockets */
static void
test_simple_poll_del_rejects_udp (void)
{
  SocketSimple_Poll_T poll = Socket_simple_poll_new (10);
  ASSERT_NOT_NULL (poll);

  struct SocketSimple_Socket *udp_sock = create_fake_udp_socket ();
  ASSERT_NOT_NULL (udp_sock);

  /* Try to delete UDP socket from poll - should fail */
  int result = Socket_simple_poll_del (poll, (SocketSimple_Socket_T)udp_sock);
  ASSERT_EQ (-1, result);

  /* Verify error message */
  const char *error = Socket_simple_error ();
  ASSERT_NOT_NULL (error);
  ASSERT_NOT_NULL (strstr (error, "UDP sockets not supported"));

  free (udp_sock);
  Socket_simple_poll_free (&poll);
}

/* Test that poll_modify_events rejects UDP sockets */
static void
test_simple_poll_modify_events_rejects_udp (void)
{
  SocketSimple_Poll_T poll = Socket_simple_poll_new (10);
  ASSERT_NOT_NULL (poll);

  struct SocketSimple_Socket *udp_sock = create_fake_udp_socket ();
  ASSERT_NOT_NULL (udp_sock);

  /* Try to modify events for UDP socket - should fail */
  int result
      = Socket_simple_poll_modify_events (poll,
                                          (SocketSimple_Socket_T)udp_sock,
                                          SOCKET_SIMPLE_POLL_READ,
                                          SOCKET_SIMPLE_POLL_WRITE);
  ASSERT_EQ (-1, result);

  /* Verify error message */
  const char *error = Socket_simple_error ();
  ASSERT_NOT_NULL (error);
  ASSERT_NOT_NULL (strstr (error, "UDP sockets not supported"));

  free (udp_sock);
  Socket_simple_poll_free (&poll);
}

/* Test that error message is consistent across all poll functions */
static void
test_simple_poll_consistent_error_message (void)
{
  SocketSimple_Poll_T poll = Socket_simple_poll_new (10);
  ASSERT_NOT_NULL (poll);

  struct SocketSimple_Socket *udp_sock = create_fake_udp_socket ();
  ASSERT_NOT_NULL (udp_sock);

  /* Test add */
  Socket_simple_poll_add (
      poll, (SocketSimple_Socket_T)udp_sock, SOCKET_SIMPLE_POLL_READ, NULL);
  const char *error1 = Socket_simple_error ();
  ASSERT_NOT_NULL (error1);
  ASSERT_NOT_NULL (strstr (error1, "UDP sockets not supported"));

  /* Test mod */
  Socket_simple_poll_mod (
      poll, (SocketSimple_Socket_T)udp_sock, SOCKET_SIMPLE_POLL_WRITE, NULL);
  const char *error2 = Socket_simple_error ();
  ASSERT_NOT_NULL (error2);
  ASSERT_NOT_NULL (strstr (error2, "UDP sockets not supported"));

  /* Test del */
  Socket_simple_poll_del (poll, (SocketSimple_Socket_T)udp_sock);
  const char *error3 = Socket_simple_error ();
  ASSERT_NOT_NULL (error3);
  ASSERT_NOT_NULL (strstr (error3, "UDP sockets not supported"));

  /* Test modify_events */
  Socket_simple_poll_modify_events (poll,
                                    (SocketSimple_Socket_T)udp_sock,
                                    SOCKET_SIMPLE_POLL_READ,
                                    SOCKET_SIMPLE_POLL_WRITE);
  const char *error4 = Socket_simple_error ();
  ASSERT_NOT_NULL (error4);
  ASSERT_NOT_NULL (strstr (error4, "UDP sockets not supported"));

  free (udp_sock);
  Socket_simple_poll_free (&poll);
}

int
main (void)
{
  test_simple_poll_add_rejects_udp ();
  test_simple_poll_mod_rejects_udp ();
  test_simple_poll_del_rejects_udp ();
  test_simple_poll_modify_events_rejects_udp ();
  test_simple_poll_consistent_error_message ();

  printf ("All tests passed!\n");
  return 0;
}
