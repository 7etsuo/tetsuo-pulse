/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dtls_enable_config.c - Fuzzer for DTLS Section 4.1 Enable and
 * Configuration
 *
 * Tests DTLS enable and configuration operations per todo_ssl.md section 4.1:
 * - SocketDTLS_enable() on datagram sockets
 * - Context ownership transfer to socket
 * - SocketDTLS_set_peer() with hostname resolution
 * - SocketDTLS_set_hostname() for SNI and verification
 * - SocketDTLS_set_mtu() MTU range validation (576-9000)
 * - SocketDTLS_get_mtu() current effective MTU
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
 * Operations on unconnected sockets will fail, which is expected.
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"

/* Ignore SIGPIPE */
__attribute__ ((constructor)) static void
ignore_sigpipe (void)
{
  signal (SIGPIPE, SIG_IGN);
}

#include "socket/SocketDgram.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types per section 4.1 */
typedef enum
{
  OP_ENABLE_BASIC = 0,           /* Basic enable test */
  OP_ENABLE_OWNERSHIP,           /* Context ownership transfer */
  OP_SET_PEER_IP,                /* set_peer with IP address */
  OP_SET_PEER_HOSTNAME,          /* set_peer with hostname */
  OP_SET_HOSTNAME_VALID,         /* set_hostname with valid name */
  OP_SET_HOSTNAME_FUZZ,          /* set_hostname with fuzz data */
  OP_SET_MTU_VALID_MIN,          /* set_mtu at minimum (576) */
  OP_SET_MTU_VALID_MAX,          /* set_mtu at maximum (9000) */
  OP_SET_MTU_INVALID_LOW,        /* set_mtu below minimum */
  OP_SET_MTU_INVALID_HIGH,       /* set_mtu above maximum */
  OP_GET_MTU,                    /* get_mtu query */
  OP_ENABLE_DOUBLE,              /* Double enable (should fail) */
  OP_COMBINED_CONFIG             /* Combined configuration sequence */
} DTLSEnableConfigOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 13 : 0;
}

/**
 * extract_fuzz_string - Extract a null-terminated string from fuzz data
 * @data: Fuzz input data
 * @size: Size of fuzz data
 * @offset: Offset into data to start extraction
 * @out: Output buffer
 * @max_len: Maximum output length (including null)
 *
 * Returns: Length of extracted string (excluding null)
 */
static size_t
extract_fuzz_string (const uint8_t *data, size_t size, size_t offset,
                     char *out, size_t max_len)
{
  if (offset >= size || max_len == 0)
    {
      if (max_len > 0)
        out[0] = '\0';
      return 0;
    }

  size_t avail = size - offset;
  size_t copy_len = avail > (max_len - 1) ? (max_len - 1) : avail;
  memcpy (out, data + offset, copy_len);
  out[copy_len] = '\0';
  return copy_len;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  SocketDTLSContext_T ctx2 = NULL;

  /* Single TRY block - no nesting per ASan requirements */
  TRY
  {
    switch (op)
      {
      case OP_ENABLE_BASIC:
        /* Section 4.1: Verify DTLS is enabled on datagram sockets */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        /* Verify enabled state */
        if (SocketDTLS_is_enabled (socket) != 1)
          abort (); /* Invariant violation */

        /* Verify handshake not yet done */
        if (SocketDTLS_is_handshake_done (socket) != 0)
          abort (); /* Should be 0 before handshake */
        break;

      case OP_ENABLE_OWNERSHIP:
        /* Section 4.1: Test that context ownership is transferred to socket */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);

        /* Context is now owned by socket - don't free it separately */
        /* Socket cleanup will handle context cleanup */
        ctx = NULL; /* Prevent double-free */
        break;

      case OP_SET_PEER_IP:
        /* Section 4.1: Verify peer address with numeric IP */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        /* Set peer with localhost IP - should succeed without DNS */
        SocketDTLS_set_peer (socket, "127.0.0.1", 4433);
        break;

      case OP_SET_PEER_HOSTNAME:
        /* Section 4.1: Verify peer address resolution (sync, may block) */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        /* set_peer with "localhost" - will do DNS resolution */
        SocketDTLS_set_peer (socket, "localhost", 4433);
        break;

      case OP_SET_HOSTNAME_VALID:
        /* Section 4.1: Verify SNI extension and hostname verification setup */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        SocketDTLS_set_hostname (socket, "example.com");
        break;

      case OP_SET_HOSTNAME_FUZZ:
        /* Section 4.1: Hostname with fuzz data for edge cases */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        if (size > 2)
          {
            char hostname[256];
            extract_fuzz_string (data, size, 1, hostname, sizeof (hostname));
            if (hostname[0] != '\0')
              SocketDTLS_set_hostname (socket, hostname);
          }
        break;

      case OP_SET_MTU_VALID_MIN:
        /* Section 4.1: Verify MTU range validation - minimum (576) */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        SocketDTLS_set_mtu (socket, SOCKET_DTLS_MIN_MTU);

        /* Verify MTU was set */
        if (SocketDTLS_get_mtu (socket) != SOCKET_DTLS_MIN_MTU)
          abort (); /* MTU not set correctly */

        break;

      case OP_SET_MTU_VALID_MAX:
        /* Section 4.1: Verify MTU range validation - maximum (9000) */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        SocketDTLS_set_mtu (socket, SOCKET_DTLS_MAX_MTU);

        /* Verify MTU was set */
        if (SocketDTLS_get_mtu (socket) != SOCKET_DTLS_MAX_MTU)
          abort ();

        break;

      case OP_SET_MTU_INVALID_LOW:
        /* Section 4.1: Verify MTU validation rejects below 576 */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        /* This should raise SocketDTLS_Failed */
        SocketDTLS_set_mtu (socket, SOCKET_DTLS_MIN_MTU - 1);

        /* If we get here, validation failed */
        abort ();

      case OP_SET_MTU_INVALID_HIGH:
        /* Section 4.1: Verify MTU validation rejects above 9000 */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        /* This should raise SocketDTLS_Failed */
        SocketDTLS_set_mtu (socket, SOCKET_DTLS_MAX_MTU + 1);

        /* If we get here, validation failed */
        abort ();

      case OP_GET_MTU:
        /* Section 4.1: Verify current effective MTU is returned */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);

        /* Context has default MTU */
        size_t ctx_mtu = SocketDTLSContext_get_mtu (ctx);

        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket now */

        /* Socket should inherit context MTU */
        size_t socket_mtu = SocketDTLS_get_mtu (socket);
        if (socket_mtu != ctx_mtu)
          abort (); /* MTU inheritance failed */

        /* Set custom MTU */
        size_t custom_mtu = 1400;
        SocketDTLS_set_mtu (socket, custom_mtu);
        if (SocketDTLS_get_mtu (socket) != custom_mtu)
          abort ();

        break;

      case OP_ENABLE_DOUBLE:
        /* Test double enable - should fail with SocketDTLS_Failed */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL;

        /* Second enable should fail */
        ctx2 = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx2); /* Should raise */
        SocketDTLSContext_free (&ctx2);   /* Won't reach here */
        abort (); /* Double enable should fail */

      case OP_COMBINED_CONFIG:
        /* Combined configuration sequence */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        ctx = NULL; /* Owned by socket */

        /* Set various configurations */
        SocketDTLS_set_mtu (socket, 1400);
        SocketDTLS_set_hostname (socket, "test.example.com");

        /* Verify state */
        (void)SocketDTLS_is_enabled (socket);
        (void)SocketDTLS_get_mtu (socket);
        (void)SocketDTLS_get_last_state (socket);

        break;

      default:
        break;
      }
  }
  EXCEPT (SocketDTLS_Failed)
  {
    /* Expected for invalid MTU, double enable, etc. */
  }
  EXCEPT (SocketDTLS_HandshakeFailed) {}
  EXCEPT (SocketDTLS_VerifyFailed) {}
  EXCEPT (SocketDTLS_CookieFailed) {}
  EXCEPT (SocketDTLS_TimeoutExpired) {}
  EXCEPT (SocketDTLS_ShutdownFailed) {}
  EXCEPT (SocketDgram_Failed) {}
  EXCEPT (Socket_Closed) {}
  ELSE
  {
    /* Catch any other exceptions */
  }
  END_TRY;

  /* Cleanup */
  if (socket)
    SocketDgram_free (&socket);
  if (ctx)
    SocketDTLSContext_free (&ctx);
  if (ctx2)
    SocketDTLSContext_free (&ctx2);

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
