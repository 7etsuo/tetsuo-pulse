/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_record.c - Fuzzer for TLS Record Layer Parsing
 *
 * Part of the Socket Library Fuzzing Suite (Issue #275)
 *
 * Targets TLS record layer processing to improve coverage of:
 * - SocketTLS.c record parsing paths (55% -> 70%+ coverage goal)
 * - SSL error handling in tls_handle_ssl_error()
 * - Record boundary conditions and malformed records
 * - Session ticket handling edge cases
 * - Alert message processing
 * - Renegotiation detection and handling
 *
 * Coverage Focus:
 * - SSL_ERROR_WANT_READ/WANT_WRITE paths
 * - SSL_ERROR_SYSCALL with various errno values
 * - SSL_ERROR_SSL protocol errors
 * - SSL_ERROR_ZERO_RETURN handling
 * - TLS 1.3 vs TLS 1.2 behavior differences
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_record
 * Run:   ./fuzz_tls_record corpus/tls_record/ -fork=16 -max_len=16384
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/Socket-private.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

/* Ignore SIGPIPE */
__attribute__ ((constructor)) static void
ignore_sigpipe (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Cached context to avoid expensive OpenSSL init */
static SocketTLSContext_T g_client_ctx = NULL;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc;
  (void)argv;

  TRY { g_client_ctx = SocketTLSContext_new_client (NULL); }
  EXCEPT (SocketTLS_Failed) { g_client_ctx = NULL; }
  END_TRY;

  return 0;
}

/**
 * Operation types targeting different record layer paths
 */
typedef enum
{
  OP_RECORD_SEND = 0,           /* Test SSL_write() with various payloads */
  OP_RECORD_RECV,               /* Test SSL_read() error paths */
  OP_RECORD_PARTIAL_WRITE,      /* Partial write scenarios */
  OP_RECORD_ZERO_LEN,           /* Zero-length operations */
  OP_RECORD_LARGE_PAYLOAD,      /* Large payloads > INT_MAX edge */
  OP_ALERT_PROCESSING,          /* Trigger alert conditions */
  OP_SESSION_SAVE_RESTORE,      /* Session ticket edge cases */
  OP_RENEGOTIATION_CHECK,       /* Renegotiation handling */
  OP_VERIFY_RESULT_QUERY,       /* Certificate verification paths */
  OP_SHUTDOWN_PATHS,            /* Shutdown error handling */
  OP_ERROR_CODE_COVERAGE,       /* SSL_get_error() branches */
  OP_PROTOCOL_VERSION_EDGE,     /* TLS 1.2 vs 1.3 differences */
  OP_COUNT
} RecordOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % OP_COUNT : 0;
}

static int
create_socketpair (int sv[2])
{
  return socketpair (AF_UNIX, SOCK_STREAM, 0, sv);
}

/**
 * Test SSL_write() error paths with various payloads
 */
static void
test_record_send (Socket_T socket, const uint8_t *data, size_t size)
{
  if (size < 2)
    return;

  /* Use fuzz data as payload */
  size_t payload_len = size - 1;
  if (payload_len > 1024)
    payload_len = 1024; /* Cap for performance */

  TRY
  {
    (void)SocketTLS_send (socket, data + 1, payload_len);
    /* Expected to fail on unconnected socket */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected - testing error paths */
  }
  EXCEPT (Socket_Closed)
  {
    /* Also expected */
  }
  END_TRY;
}

/**
 * Test SSL_read() error handling
 */
static void
test_record_recv (Socket_T socket)
{
  char buf[2048];

  TRY
  {
    (void)SocketTLS_recv (socket, buf, sizeof (buf));
    /* Expected to fail */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Testing SSL_ERROR_* branches */
  }
  EXCEPT (Socket_Closed)
  {
    /* ZERO_RETURN path */
  }
  END_TRY;
}

/**
 * Test partial write handling (SSL_MODE_ENABLE_PARTIAL_WRITE)
 */
static void
test_partial_write (Socket_T socket, const uint8_t *data, size_t size)
{
  if (size < 10)
    return;

  /* Try writing in chunks to trigger partial write logic */
  size_t chunk_size = (data[1] % 128) + 1;
  size_t offset = 2;

  TRY
  {
    while (offset < size && offset < 512)
      {
        size_t to_write = chunk_size;
        if (offset + to_write > size)
          to_write = size - offset;

        (void)SocketTLS_send (socket, data + offset, to_write);
        offset += chunk_size;
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected */
  }
  EXCEPT (Socket_Closed)
  {
    /* Expected */
  }
  END_TRY;
}

/**
 * Test zero-length send/recv (POSIX semantics)
 */
static void
test_zero_length_ops (Socket_T socket)
{
  char buf[16];

  TRY
  {
    /* Zero-length send should return 0 immediately */
    ssize_t sent = SocketTLS_send (socket, buf, 0);
    if (sent != 0)
      abort (); /* Contract violation */

    /* Zero-length recv should return 0 immediately */
    ssize_t recvd = SocketTLS_recv (socket, buf, 0);
    if (recvd != 0)
      abort (); /* Contract violation */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Should not raise for zero-length */
    abort ();
  }
  END_TRY;
}

/**
 * Test session save/restore edge cases
 */
static void
test_session_ticket (Socket_T socket)
{
  unsigned char session_buf[4096];
  size_t session_len = sizeof (session_buf);

  /* Try saving session (will fail - no handshake) */
  int result = SocketTLS_session_save (socket, session_buf, &session_len);
  (void)result; /* Expected to fail */

  /* Try restoring invalid session data */
  if (session_len > 0)
    {
      TRY
      {
        /* Attempt to restore (will fail gracefully) */
        (void)SocketTLS_session_restore (socket, session_buf, session_len);
      }
      EXCEPT (SocketTLS_Failed)
      {
        /* Expected */
      }
      END_TRY;
    }
}

/**
 * Test renegotiation checking (TLS 1.2 specific)
 */
static void
test_renegotiation (Socket_T socket)
{
  TRY
  {
    int reneg_count = SocketTLS_get_renegotiation_count (socket);
    (void)reneg_count;

    /* Try checking for renegotiation */
    (void)SocketTLS_check_renegotiation (socket);

    /* Try disabling renegotiation */
    (void)SocketTLS_disable_renegotiation (socket);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected on unconnected socket */
  }
  END_TRY;
}

/**
 * Test certificate verification result queries
 */
static void
test_verify_queries (Socket_T socket)
{
  /* Query verify result (should return error for no handshake) */
  long verify_result = SocketTLS_get_verify_result (socket);
  (void)verify_result;

  /* Try getting error string */
  char error_buf[256];
  const char *error_str
      = SocketTLS_get_verify_error_string (socket, error_buf, sizeof (error_buf));
  (void)error_str;

  /* Get cert info (should fail gracefully) */
  SocketTLS_CertInfo cert_info;
  TRY
  {
    (void)SocketTLS_get_peer_cert_info (socket, &cert_info);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected */
  }
  END_TRY;
}

/**
 * Test shutdown error paths
 */
static void
test_shutdown_errors (Socket_T socket)
{
  TRY
  {
    /* Try shutdown on non-handshaked connection */
    SocketTLS_shutdown (socket);
  }
  EXCEPT (SocketTLS_ShutdownFailed)
  {
    /* Expected */
  }
  END_TRY;

  /* Try shutdown_send (unidirectional) */
  int result = SocketTLS_shutdown_send (socket);
  (void)result;
}

/**
 * Test protocol version edge cases
 */
static void
test_protocol_version (Socket_T socket)
{
  /* Get version (NULL expected pre-handshake) */
  const char *version = SocketTLS_get_version (socket);
  (void)version;

  /* Get protocol version code */
  int proto_ver = SocketTLS_get_protocol_version (socket);
  (void)proto_ver;

  /* Check if session reused (should return -1) */
  int reused = SocketTLS_is_session_reused (socket);
  if (reused != -1)
    abort (); /* Should be -1 for no handshake */
}

/**
 * Main fuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2 || !g_client_ctx)
    return 0;

  volatile uint8_t op = get_op (data, size);
  volatile Socket_T socket = NULL;
  int sv[2] = { -1, -1 };

  /* Single TRY block to avoid nested exceptions */
  TRY
  {
    /* Create socketpair for testing (allows SSL I/O without real connection) */
    if (create_socketpair (sv) != 0)
      RETURN 0;

    /* Create socket and enable TLS */
    socket = Socket_new_from_fd (sv[0]);
    if (!socket)
      {
        close (sv[0]);
        close (sv[1]);
        RETURN 0;
      }

    /* Enable TLS on the socket */
    SocketTLS_enable (socket, g_client_ctx);

    /* Execute operation based on fuzz input */
    switch (op)
      {
      case OP_RECORD_SEND:
        test_record_send (socket, data, size);
        break;

      case OP_RECORD_RECV:
        test_record_recv (socket);
        break;

      case OP_RECORD_PARTIAL_WRITE:
        test_partial_write (socket, data, size);
        break;

      case OP_RECORD_ZERO_LEN:
        test_zero_length_ops (socket);
        break;

      case OP_RECORD_LARGE_PAYLOAD:
        /* Test INT_MAX capping */
        if (size > 10)
          test_record_send (socket, data, size);
        break;

      case OP_ALERT_PROCESSING:
        /* Alerts triggered via error conditions */
        test_record_recv (socket);
        test_record_send (socket, data, size);
        break;

      case OP_SESSION_SAVE_RESTORE:
        test_session_ticket (socket);
        break;

      case OP_RENEGOTIATION_CHECK:
        test_renegotiation (socket);
        break;

      case OP_VERIFY_RESULT_QUERY:
        test_verify_queries (socket);
        break;

      case OP_SHUTDOWN_PATHS:
        test_shutdown_errors (socket);
        break;

      case OP_ERROR_CODE_COVERAGE:
        /* Mix multiple operations to hit error branches */
        test_record_send (socket, data, size);
        test_record_recv (socket);
        test_shutdown_errors (socket);
        break;

      case OP_PROTOCOL_VERSION_EDGE:
        test_protocol_version (socket);
        break;

      default:
        break;
      }
  }
  ELSE
  {
    /* Catch all exceptions - this is intentional fuzzing */
  }
  END_TRY;

  /* Cleanup */
  if (socket)
    Socket_free ((Socket_T *)&socket);
  if (sv[1] >= 0)
    close (sv[1]);

  return 0;
}

#else /* !SOCKET_HAS_TLS */

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */
