/*
 * SPDX-LICENSE-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_alert.c - Fuzzer for TLS Alert Message Processing
 *
 * Part of the Socket Library Fuzzing Suite (Issue #275)
 *
 * Targets TLS alert handling to improve coverage of:
 * - SocketTLS.c alert processing paths
 * - Fatal vs warning alert differentiation
 * - close_notify handling in shutdown
 * - Unexpected alert conditions
 * - Alert during handshake, I/O, and shutdown
 *
 * Coverage Focus:
 * - SSL_ERROR_SSL with alert codes
 * - Graceful vs abrupt connection termination
 * - Alert message propagation through exception system
 * - Post-alert connection state
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_alert
 * Run:   ./fuzz_tls_alert corpus/tls_alert/ -fork=16 -max_len=4096
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

/* Cached context */
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
 * Operation types targeting alert processing
 */
typedef enum
{
  OP_ALERT_DURING_HANDSHAKE = 0,
  OP_ALERT_DURING_IO,
  OP_ALERT_CLOSE_NOTIFY,
  OP_ALERT_UNEXPECTED,
  OP_ALERT_FATAL_VS_WARNING,
  OP_ALERT_POST_SHUTDOWN,
  OP_ALERT_DURING_RENEGOTIATION,
  OP_ALERT_CERTIFICATE_ERROR,
  OP_ALERT_PROTOCOL_VERSION,
  OP_ALERT_DECODE_ERROR,
  OP_COUNT
} AlertOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % OP_COUNT : 0;
}

/**
 * Test alert during handshake
 */
static void
test_alert_during_handshake (Socket_T socket)
{
  TRY
  {
    /* Handshake on unconnected socket will trigger errors */
    TLSHandshakeState state = SocketTLS_handshake (socket);
    (void)state;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    /* Check if alert was involved in failure */
  }
  END_TRY;
}

/**
 * Test alert during I/O operations
 */
static void
test_alert_during_io (Socket_T socket, const uint8_t *data, size_t size)
{
  if (size < 10)
    return;

  char buf[256];

  TRY
  {
    /* Try send - may trigger protocol error alert */
    (void)SocketTLS_send (socket, data, size > 100 ? 100 : size);

    /* Try recv - may receive alert */
    (void)SocketTLS_recv (socket, buf, sizeof (buf));
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Alert-related failure */
  }
  EXCEPT (Socket_Closed)
  {
    /* close_notify received */
  }
  END_TRY;
}

/**
 * Test close_notify alert handling
 */
static void
test_close_notify (Socket_T socket)
{
  TRY
  {
    /* Try graceful shutdown (sends close_notify) */
    SocketTLS_shutdown (socket);
  }
  EXCEPT (SocketTLS_ShutdownFailed)
  {
    /* Expected on unconnected socket */
  }
  END_TRY;

  /* Try unidirectional shutdown */
  int result = SocketTLS_shutdown_send (socket);
  (void)result;
}

/**
 * Test certificate-related alerts
 */
static void
test_cert_alerts (Socket_T socket)
{
  /* Query verification result (may reveal cert alerts) */
  long verify_result = SocketTLS_get_verify_result (socket);
  (void)verify_result;

  /* Get cert chain (may trigger alert if verification failed) */
  X509 **chain = NULL;
  int chain_len = 0;

  TRY
  {
    (void)SocketTLS_get_peer_cert_chain (socket, &chain, &chain_len);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected */
  }
  END_TRY;

  /* Try getting cert expiry */
  time_t expiry = SocketTLS_get_cert_expiry (socket);
  (void)expiry;
}

/**
 * Test OCSP-related alerts
 */
static void
test_ocsp_alerts (Socket_T socket)
{
  /* Query OCSP response (may involve alert processing) */
  int ocsp_status = SocketTLS_get_ocsp_response_status (socket);
  (void)ocsp_status;

  time_t next_update;
  int result = SocketTLS_get_ocsp_next_update (socket, &next_update);
  (void)result;
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

  TRY
  {
    /* Create socketpair */
    if (socketpair (AF_UNIX, SOCK_STREAM, 0, sv) != 0)
      RETURN 0;

    socket = Socket_new_from_fd (sv[0]);
    if (!socket)
      {
        close (sv[0]);
        close (sv[1]);
        RETURN 0;
      }

    /* Enable TLS */
    SocketTLS_enable (socket, g_client_ctx);

    /* Execute operation */
    switch (op)
      {
      case OP_ALERT_DURING_HANDSHAKE:
        test_alert_during_handshake (socket);
        break;

      case OP_ALERT_DURING_IO:
        test_alert_during_io (socket, data, size);
        break;

      case OP_ALERT_CLOSE_NOTIFY:
        test_close_notify (socket);
        break;

      case OP_ALERT_UNEXPECTED:
        /* Send unexpected data to trigger protocol alert */
        test_alert_during_io (socket, data, size);
        test_alert_during_handshake (socket);
        break;

      case OP_ALERT_FATAL_VS_WARNING:
        /* Mix operations to trigger different alert severities */
        test_alert_during_handshake (socket);
        test_alert_during_io (socket, data, size);
        break;

      case OP_ALERT_POST_SHUTDOWN:
        test_close_notify (socket);
        /* Try operations after shutdown */
        test_alert_during_io (socket, data, size);
        break;

      case OP_ALERT_DURING_RENEGOTIATION:
        /* Test renegotiation-related alerts */
        TRY
        {
          (void)SocketTLS_check_renegotiation (socket);
        }
        EXCEPT (SocketTLS_ProtocolError)
        {
          /* Expected */
        }
        END_TRY;
        break;

      case OP_ALERT_CERTIFICATE_ERROR:
        test_cert_alerts (socket);
        break;

      case OP_ALERT_PROTOCOL_VERSION:
        /* Version-related alerts */
        (void)SocketTLS_get_version (socket);
        (void)SocketTLS_get_protocol_version (socket);
        test_alert_during_handshake (socket);
        break;

      case OP_ALERT_DECODE_ERROR:
        /* Send malformed data to trigger decode errors */
        test_alert_during_io (socket, data, size);
        break;

      default:
        break;
      }
  }
  ELSE
  {
    /* Catch all exceptions */
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
