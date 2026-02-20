/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_migration.c
 * @brief Unit tests for QUIC Connection Migration (RFC 9000 Section 9).
 */

#include "quic/SocketQUICMigration.h"
#include "quic/SocketQUICConnection.h"
#include "core/Arena.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name (void)
#define RUN_TEST(name)                        \
  do                                          \
    {                                         \
      printf ("Running test_%s...\n", #name); \
      test_##name ();                         \
      tests_passed++;                         \
    }                                         \
  while (0)

#define ASSERT(cond)                                \
  do                                                \
    {                                               \
      if (!(cond))                                  \
        {                                           \
          fprintf (stderr,                          \
                   "ASSERTION FAILED: %s:%d: %s\n", \
                   __FILE__,                        \
                   __LINE__,                        \
                   #cond);                          \
          tests_failed++;                           \
          return;                                   \
        }                                           \
    }                                               \
  while (0)

/* Helper to create IPv4 sockaddr */
static void
make_ipv4_addr (struct sockaddr_storage *addr, const char *ip, uint16_t port)
{
  struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
  memset (addr, 0, sizeof (*addr));
  addr4->sin_family = AF_INET;
  addr4->sin_port = htons (port);
  inet_pton (AF_INET, ip, &addr4->sin_addr);
}

/* Helper to create IPv6 sockaddr */
static void
make_ipv6_addr (struct sockaddr_storage *addr, const char *ip, uint16_t port)
{
  struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
  memset (addr, 0, sizeof (*addr));
  addr6->sin6_family = AF_INET6;
  addr6->sin6_port = htons (port);
  inet_pton (AF_INET6, ip, &addr6->sin6_addr);
}

TEST (migration_new)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);
  ASSERT (migration != NULL);
  ASSERT (migration->connection == conn);
  ASSERT (migration->role == QUIC_MIGRATION_ROLE_INITIATOR);
  ASSERT (migration->path_count == 0);
  ASSERT (migration->active_path_index == 0);
  ASSERT (migration->migration_in_progress == 0);

  Arena_dispose (&arena);
}

TEST (migration_init)
{
  SocketQUICMigration_T migration;
  SocketQUICConnection_T conn = NULL;

  SocketQUICMigration_init (&migration, conn, QUIC_MIGRATION_ROLE_RESPONDER);

  ASSERT (migration.connection == conn);
  ASSERT (migration.role == QUIC_MIGRATION_ROLE_RESPONDER);
  ASSERT (migration.path_count == 0);
  ASSERT (migration.nat_rebinding_detected == 0);
}

TEST (init_path_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr;
  SocketQUICConnectionID_T cid;
  SocketQUICMigration_Result result;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);
  ASSERT (migration != NULL);

  /* Create addresses */
  make_ipv4_addr (&local_addr, "192.168.1.10", 4433);
  make_ipv4_addr (&peer_addr, "192.168.1.20", 8080);

  /* Create connection ID */
  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);
  cid.sequence = 0;

  /* Initialize path */
  result = SocketQUICMigration_init_path (
      migration, &local_addr, &peer_addr, &cid);
  ASSERT (result == QUIC_MIGRATION_OK);
  ASSERT (migration->path_count == 1);
  ASSERT (migration->active_path_index == 0);

  /* Verify path state */
  const SocketQUICPath_T *path
      = SocketQUICMigration_get_active_path (migration);
  ASSERT (path != NULL);
  ASSERT (path->state == QUIC_PATH_VALIDATED);
  ASSERT (path->cwnd == 12000); /* Initial cwnd = 10 * 1200 */
  ASSERT (path->rtt_us > 0);

  Arena_dispose (&arena);
}

TEST (get_active_path)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr;
  SocketQUICConnectionID_T cid;
  const SocketQUICPath_T *path;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  /* No active path initially */
  path = SocketQUICMigration_get_active_path (migration);
  ASSERT (path == NULL);

  /* Initialize a path */
  make_ipv4_addr (&local_addr, "10.0.0.1", 4433);
  make_ipv4_addr (&peer_addr, "10.0.0.2", 8080);
  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);

  SocketQUICMigration_init_path (migration, &local_addr, &peer_addr, &cid);

  /* Now should have active path */
  path = SocketQUICMigration_get_active_path (migration);
  ASSERT (path != NULL);
  ASSERT (path->state == QUIC_PATH_VALIDATED);

  Arena_dispose (&arena);
}

TEST (find_path_by_address)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr1, peer_addr2;
  SocketQUICConnectionID_T cid;
  SocketQUICPath_T *path;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  make_ipv4_addr (&local_addr, "192.168.1.1", 4433);
  make_ipv4_addr (&peer_addr1, "192.168.1.100", 8080);
  make_ipv4_addr (&peer_addr2, "192.168.1.200", 8080);

  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);

  /* Initialize path with peer_addr1 */
  SocketQUICMigration_init_path (migration, &local_addr, &peer_addr1, &cid);

  /* Find path by peer_addr1 - should succeed */
  path = SocketQUICMigration_find_path (migration, &peer_addr1);
  ASSERT (path != NULL);

  /* Find path by peer_addr2 - should fail */
  path = SocketQUICMigration_find_path (migration, &peer_addr2);
  ASSERT (path == NULL);

  Arena_dispose (&arena);
}

TEST (probe_path_new)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr, new_peer_addr;
  SocketQUICConnectionID_T cid;
  SocketQUICMigration_Result result;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  /* Initialize initial path */
  make_ipv4_addr (&local_addr, "192.168.1.1", 4433);
  make_ipv4_addr (&peer_addr, "192.168.1.100", 8080);
  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);
  SocketQUICMigration_init_path (migration, &local_addr, &peer_addr, &cid);

  /* Probe new path */
  make_ipv4_addr (&new_peer_addr, "192.168.1.200", 8080);
  result = SocketQUICMigration_probe_path (migration, &new_peer_addr);

  ASSERT (result == QUIC_MIGRATION_OK);
  ASSERT (migration->path_count == 2);

  /* Find the new path and verify state */
  SocketQUICPath_T *path
      = SocketQUICMigration_find_path (migration, &new_peer_addr);
  ASSERT (path != NULL);
  ASSERT (path->state == QUIC_PATH_VALIDATING);
  ASSERT (path->challenge_count == 1);

  Arena_dispose (&arena);
}

TEST (handle_path_response)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr, new_peer_addr;
  SocketQUICConnectionID_T cid;
  SocketQUICMigration_Result result;
  SocketQUICPath_T *path;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  /* Initialize initial path */
  make_ipv4_addr (&local_addr, "10.0.0.1", 4433);
  make_ipv4_addr (&peer_addr, "10.0.0.2", 8080);
  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);
  SocketQUICMigration_init_path (migration, &local_addr, &peer_addr, &cid);

  /* Probe new path */
  make_ipv4_addr (&new_peer_addr, "10.0.0.3", 8080);
  result = SocketQUICMigration_probe_path (migration, &new_peer_addr);
  ASSERT (result == QUIC_MIGRATION_OK);

  /* Get the challenge data */
  path = SocketQUICMigration_find_path (migration, &new_peer_addr);
  ASSERT (path != NULL);
  ASSERT (path->state == QUIC_PATH_VALIDATING);

  uint8_t challenge[8];
  memcpy (challenge, path->challenge, sizeof (challenge));

  /* Handle PATH_RESPONSE with matching challenge */
  result = SocketQUICMigration_handle_path_response (migration, challenge);
  ASSERT (result == QUIC_MIGRATION_OK);
  ASSERT (path->state == QUIC_PATH_VALIDATED);

  Arena_dispose (&arena);
}

TEST (handle_path_challenge)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  SocketQUICMigration_T *migration;
  uint8_t challenge[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  uint8_t response[8];
  SocketQUICMigration_Result result;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_RESPONDER);

  /* Handle PATH_CHALLENGE */
  result = SocketQUICMigration_handle_path_challenge (
      migration, challenge, response);
  ASSERT (result == QUIC_MIGRATION_OK);

  /* Response should match challenge (RFC 9000 Section 8.2.2) */
  ASSERT (memcmp (challenge, response, sizeof (challenge)) == 0);

  Arena_dispose (&arena);
}

TEST (path_validation_timeout)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr, new_peer_addr;
  SocketQUICConnectionID_T cid;
  SocketQUICPath_T *path;
  int timeout_count;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  /* Initialize paths */
  make_ipv4_addr (&local_addr, "10.0.0.1", 4433);
  make_ipv4_addr (&peer_addr, "10.0.0.2", 8080);
  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);
  SocketQUICMigration_init_path (migration, &local_addr, &peer_addr, &cid);

  make_ipv4_addr (&new_peer_addr, "10.0.0.3", 8080);
  SocketQUICMigration_probe_path (migration, &new_peer_addr);

  path = SocketQUICMigration_find_path (migration, &new_peer_addr);
  ASSERT (path != NULL);
  ASSERT (path->state == QUIC_PATH_VALIDATING);

  /* Simulate timeout by setting old challenge_sent_time */
  path->challenge_sent_time = 0;
  path->challenge_count = 1; /* Start at 1 (already sent) */

  /* Check timeouts - should trigger retry */
  timeout_count = SocketQUICMigration_check_timeouts (
      migration, QUIC_PATH_VALIDATION_TIMEOUT_MS + 100);
  ASSERT (path->challenge_count == 2);          /* Retry incremented */
  ASSERT (path->state == QUIC_PATH_VALIDATING); /* Still validating */

  /* Exhaust retries - set to max and trigger timeout again */
  path->challenge_sent_time = 0;
  path->challenge_count = QUIC_PATH_MAX_CHALLENGES;
  timeout_count = SocketQUICMigration_check_timeouts (
      migration, QUIC_PATH_VALIDATION_TIMEOUT_MS * 2);
  /* After max retries, path should be marked as failed */
  ASSERT (path->state == QUIC_PATH_FAILED);
  ASSERT (timeout_count >= 0); /* At least not negative */

  Arena_dispose (&arena);
}

TEST (migration_can_migrate_client)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;

  /* Client (initiator) should be able to migrate */
  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);
  ASSERT (SocketQUICMigration_can_migrate (migration) == 1);

  Arena_dispose (&arena);
}

TEST (migration_can_migrate_server)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  SocketQUICMigration_T *migration;

  /* Server (responder) should NOT be able to migrate voluntarily */
  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_RESPONDER);
  ASSERT (SocketQUICMigration_can_migrate (migration) == 0);

  Arena_dispose (&arena);
}

TEST (migration_initiate)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr, new_peer_addr;
  SocketQUICConnectionID_T cid;
  SocketQUICMigration_Result result;
  SocketQUICPath_T *new_path;
  const SocketQUICPath_T *active_path;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  /* Initialize initial path */
  make_ipv4_addr (&local_addr, "192.168.1.1", 4433);
  make_ipv4_addr (&peer_addr, "192.168.1.100", 8080);
  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);
  cid.sequence = 0;
  SocketQUICMigration_init_path (migration, &local_addr, &peer_addr, &cid);

  /* Probe and validate new path */
  make_ipv4_addr (&new_peer_addr, "192.168.1.200", 8080);
  SocketQUICMigration_probe_path (migration, &new_peer_addr);

  new_path = SocketQUICMigration_find_path (migration, &new_peer_addr);
  ASSERT (new_path != NULL);

  /* Simulate validation by handling PATH_RESPONSE */
  SocketQUICMigration_handle_path_response (migration, new_path->challenge);
  ASSERT (new_path->state == QUIC_PATH_VALIDATED);

  /* Initiate migration */
  result = SocketQUICMigration_initiate (migration, new_path);
  ASSERT (result == QUIC_MIGRATION_OK);

  /* Verify active path switched */
  active_path = SocketQUICMigration_get_active_path (migration);
  ASSERT (active_path == new_path);

  /* Verify CID sequence incremented (RFC 9000 Section 9.5) */
  ASSERT (active_path->cid.sequence > 0);

  /* Verify congestion control reset */
  ASSERT (active_path->cwnd == 12000); /* Initial cwnd = 10 * 1200 */
  ASSERT (active_path->bytes_in_flight == 0);

  Arena_dispose (&arena);
}

TEST (nat_rebinding_detection)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr1, peer_addr2;
  SocketQUICConnectionID_T cid;
  SocketQUICMigration_Result result;
  uint64_t current_time_ms = 1000;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  /* Initialize path */
  make_ipv4_addr (&local_addr, "10.0.0.1", 4433);
  make_ipv4_addr (&peer_addr1, "10.0.0.2", 8080);
  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);
  SocketQUICMigration_init_path (migration, &local_addr, &peer_addr1, &cid);

  /* Rapid address change (NAT rebinding) */
  make_ipv4_addr (&peer_addr2, "10.0.0.3", 8080);
  result = SocketQUICMigration_handle_peer_address_change (
      migration, &peer_addr2, current_time_ms);
  ASSERT (result == QUIC_MIGRATION_OK);

  /* Another rapid change within NAT rebind window */
  make_ipv4_addr (&peer_addr1, "10.0.0.4", 8080);
  result = SocketQUICMigration_handle_peer_address_change (
      migration, &peer_addr1, current_time_ms + QUIC_NAT_REBIND_WINDOW_MS / 2);
  ASSERT (result == QUIC_MIGRATION_OK);

  /* NAT rebinding should be detected */
  ASSERT (migration->nat_rebinding_detected == 1);

  Arena_dispose (&arena);
}

TEST (reset_congestion_new_path)
{
  SocketQUICPath_T old_path, new_path;

  memset (&old_path, 0, sizeof (old_path));
  memset (&new_path, 0, sizeof (new_path));

  /* Set old path state */
  old_path.cwnd = 50000;
  old_path.ssthresh = 25000;
  old_path.rtt_us = 100000; /* 100ms */
  old_path.bytes_in_flight = 10000;

  /* Reset congestion for new path */
  SocketQUICMigration_reset_congestion (&new_path, &old_path);

  /* Verify reset values (initial cwnd = 10 * 1200 = 12000) */
  ASSERT (new_path.cwnd == 12000);
  ASSERT (new_path.ssthresh == (1024 * 1024)); /* 1 MB */
  ASSERT (new_path.bytes_in_flight == 0);

  /* RTT may be inherited from old path */
  ASSERT (new_path.rtt_us == old_path.rtt_us);

  /* Statistics should be zero */
  ASSERT (new_path.packets_sent == 0);
  ASSERT (new_path.bytes_sent == 0);
}

TEST (update_rtt)
{
  SocketQUICPath_T path;

  memset (&path, 0, sizeof (path));

  /* First RTT sample */
  SocketQUICMigration_update_rtt (&path, 50000); /* 50ms */
  ASSERT (path.rtt_us == 50000);

  /* Second sample - should smooth */
  SocketQUICMigration_update_rtt (&path, 100000); /* 100ms */
  ASSERT (path.rtt_us > 50000 && path.rtt_us < 100000);
  /* SRTT = 0.875 * 50000 + 0.125 * 100000 = 56250 */
  ASSERT (path.rtt_us == 56250);
}

TEST (ipv6_path_validation)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr;
  SocketQUICConnectionID_T cid;
  SocketQUICMigration_Result result;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  /* IPv6 addresses */
  make_ipv6_addr (&local_addr, "2001:db8::1", 4433);
  make_ipv6_addr (&peer_addr, "2001:db8::2", 8080);

  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);

  result = SocketQUICMigration_init_path (
      migration, &local_addr, &peer_addr, &cid);
  ASSERT (result == QUIC_MIGRATION_OK);

  const SocketQUICPath_T *path
      = SocketQUICMigration_get_active_path (migration);
  ASSERT (path != NULL);

  /* Verify addresses are IPv6 */
  ASSERT (path->local_addr.ss_family == AF_INET6);
  ASSERT (path->peer_addr.ss_family == AF_INET6);

  Arena_dispose (&arena);
}

TEST (state_string)
{
  const char *str;

  str = SocketQUICMigration_state_string (QUIC_PATH_UNKNOWN);
  ASSERT (strcmp (str, "UNKNOWN") == 0);

  str = SocketQUICMigration_state_string (QUIC_PATH_VALIDATING);
  ASSERT (strcmp (str, "VALIDATING") == 0);

  str = SocketQUICMigration_state_string (QUIC_PATH_VALIDATED);
  ASSERT (strcmp (str, "VALIDATED") == 0);

  str = SocketQUICMigration_state_string (QUIC_PATH_FAILED);
  ASSERT (strcmp (str, "FAILED") == 0);
}

TEST (result_string)
{
  const char *str;

  str = SocketQUICMigration_result_string (QUIC_MIGRATION_OK);
  ASSERT (strcmp (str, "OK") == 0);

  str = SocketQUICMigration_result_string (QUIC_MIGRATION_ERROR_NULL);
  ASSERT (strcmp (str, "NULL pointer") == 0);

  str = SocketQUICMigration_result_string (QUIC_MIGRATION_ERROR_TIMEOUT);
  ASSERT (strcmp (str, "Path validation timeout") == 0);
}

TEST (path_to_string)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICMigration_T *migration;
  struct sockaddr_storage local_addr, peer_addr;
  SocketQUICConnectionID_T cid;
  char buf[256];
  int ret;

  migration
      = SocketQUICMigration_new (arena, conn, QUIC_MIGRATION_ROLE_INITIATOR);

  make_ipv4_addr (&local_addr, "192.168.1.1", 4433);
  make_ipv4_addr (&peer_addr, "192.168.1.100", 8080);
  SocketQUICConnectionID_init (&cid);
  SocketQUICConnectionID_generate (&cid, 8);
  SocketQUICMigration_init_path (migration, &local_addr, &peer_addr, &cid);

  const SocketQUICPath_T *path
      = SocketQUICMigration_get_active_path (migration);
  ret = SocketQUICMigration_path_to_string (path, buf, sizeof (buf));

  ASSERT (ret > 0);
  ASSERT (strstr (buf, "192.168.1.1:4433") != NULL);
  ASSERT (strstr (buf, "192.168.1.100:8080") != NULL);
  ASSERT (strstr (buf, "VALIDATED") != NULL);

  Arena_dispose (&arena);
}

int
main (void)
{
  printf ("Running QUIC Connection Migration tests...\n\n");

  /* Lifecycle tests */
  RUN_TEST (migration_new);
  RUN_TEST (migration_init);

  /* Path management tests */
  RUN_TEST (init_path_basic);
  RUN_TEST (get_active_path);
  RUN_TEST (find_path_by_address);

  /* Path validation tests */
  RUN_TEST (probe_path_new);
  RUN_TEST (handle_path_response);
  RUN_TEST (handle_path_challenge);
  RUN_TEST (path_validation_timeout);

  /* Migration tests */
  RUN_TEST (migration_can_migrate_client);
  RUN_TEST (migration_can_migrate_server);
  RUN_TEST (migration_initiate);
  RUN_TEST (nat_rebinding_detection);

  /* Congestion control tests */
  RUN_TEST (reset_congestion_new_path);
  RUN_TEST (update_rtt);

  /* IPv6 tests */
  RUN_TEST (ipv6_path_validation);

  /* Utility tests */
  RUN_TEST (state_string);
  RUN_TEST (result_string);
  RUN_TEST (path_to_string);

  printf ("\n========================================\n");
  printf ("Tests passed: %d\n", tests_passed);
  printf ("Tests failed: %d\n", tests_failed);
  printf ("========================================\n");

  return tests_failed > 0 ? 1 : 0;
}
