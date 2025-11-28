/**
 * fuzz_tls_io.c - Fuzzer for SocketTLS I/O operations
 *
 * Tests TLS socket I/O operations:
 * - TLS enable
 * - SNI hostname setting and validation
 * - Handshake state machine
 * - TLS send/recv operations
 * - TLS shutdown
 * - Error handling paths
 * - Connection info queries
 *
 * Note: This fuzzer tests the TLS I/O layer, not certificate/context
 * operations (those are covered by fuzz_tls_certs, fuzz_tls_verify, etc.)
 */

#ifdef SOCKET_HAS_TLS

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/Socket-private.h" /* For tls_enabled field access */
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

/* Suppress GCC clobbered warnings for volatile variables */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_ENABLE = 0,         /* Enable TLS on socket */
  OP_HOSTNAME,           /* Set SNI hostname variations */
  OP_HANDSHAKE_STATE,    /* Test handshake state machine */
  OP_SEND_RECV,          /* TLS send/recv operations */
  OP_SHUTDOWN,           /* TLS shutdown */
  OP_INFO_QUERIES,       /* Query connection info */
  OP_BUFFER_OPS,         /* Test buffer operations */
  OP_ERROR_PATHS         /* Test error handling paths */
} TLSIOOp;

/* Extract null-terminated string from fuzz data */
static const char *
extract_string (const uint8_t *data, size_t size, size_t offset,
                char *buf, size_t bufsize)
{
  if (offset >= size)
    {
      buf[0] = '\0';
      return buf;
    }

  size_t avail = size - offset;
  size_t copy_len = avail < bufsize - 1 ? avail : bufsize - 1;

  /* Find null terminator or use copy_len */
  size_t actual_len = 0;
  while (actual_len < copy_len && data[offset + actual_len] != '\0')
    actual_len++;

  memcpy (buf, data + offset, actual_len);
  buf[actual_len] = '\0';

  return buf;
}

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 8 : 0;
}

static uint16_t
get_uint16 (const uint8_t *data, size_t offset, size_t size)
{
  if (offset + 2 > size)
    return 0;
  return (uint16_t)data[offset] | ((uint16_t)data[offset + 1] << 8);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;
  volatile uint8_t op = get_op (data, size);
  char hostname_buf[256];
  char send_buf[1024];
  char recv_buf[1024];

  /* Initialize buffers with fuzz data */
  size_t copy_len = size > sizeof (send_buf) ? sizeof (send_buf) : size;
  memcpy (send_buf, data, copy_len);

  TRY
  {
    switch (op)
      {
      case OP_ENABLE:
        {
          /* Test TLS enable lifecycle */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Create a minimal TLS client context (no CA verification) */
          ctx = SocketTLSContext_new_client (NULL);

          /* Try to enable TLS (will fail without connection, but tests paths)
           */
          TRY
          {
            SocketTLS_enable (socket, ctx);
            /* Check if TLS is enabled via private field */
            assert (socket->tls_enabled == 1);
          }
          EXCEPT (SocketTLS_Failed)
          {
            /* Expected - socket not connected */
          }
          END_TRY;

          Socket_free (&socket);
          socket = NULL;
          SocketTLSContext_free (&ctx);
          ctx = NULL;
        }
        break;

      case OP_HOSTNAME:
        {
          /* Test SNI hostname setting with various inputs */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);
          ctx = SocketTLSContext_new_client (NULL);

          /* Try to enable TLS first */
          TRY
          {
            SocketTLS_enable (socket, ctx);

            /* Test various hostname formats */
            const char *hostname
                = extract_string (data, size, 1, hostname_buf,
                                  sizeof (hostname_buf));

            if (strlen (hostname) > 0)
              {
                TRY
                {
                  SocketTLS_set_hostname (socket, hostname);
                }
                EXCEPT (SocketTLS_Failed)
                {
                  /* Invalid hostname - expected */
                }
                END_TRY;
              }

            /* Test specific hostname patterns */
            TRY { SocketTLS_set_hostname (socket, "localhost"); }
            EXCEPT (SocketTLS_Failed) { }
            END_TRY;

            TRY { SocketTLS_set_hostname (socket, "example.com"); }
            EXCEPT (SocketTLS_Failed) { }
            END_TRY;

            TRY { SocketTLS_set_hostname (socket, "*.example.com"); }
            EXCEPT (SocketTLS_Failed) { }
            END_TRY;

            /* Very long hostname */
            char long_hostname[300];
            memset (long_hostname, 'a', sizeof (long_hostname) - 1);
            long_hostname[sizeof (long_hostname) - 1] = '\0';
            TRY { SocketTLS_set_hostname (socket, long_hostname); }
            EXCEPT (SocketTLS_Failed) { }
            END_TRY;
          }
          EXCEPT (SocketTLS_Failed)
          {
            /* TLS enable failed - expected */
          }
          END_TRY;

          Socket_free (&socket);
          socket = NULL;
          SocketTLSContext_free (&ctx);
          ctx = NULL;
        }
        break;

      case OP_HANDSHAKE_STATE:
        {
          /* Test handshake state machine */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);
          ctx = SocketTLSContext_new_client (NULL);

          TRY
          {
            SocketTLS_enable (socket, ctx);

            /* Try handshake (will fail but tests state machine) */
            TRY
            {
              TLSHandshakeState state = SocketTLS_handshake (socket);
              (void)state;

              /* Try handshake again to test multiple calls */
              state = SocketTLS_handshake (socket);
              (void)state;
            }
            EXCEPT (SocketTLS_HandshakeFailed)
            {
              /* Expected - no actual connection */
            }
            EXCEPT (SocketTLS_Failed)
            {
              /* Also expected */
            }
            END_TRY;
          }
          EXCEPT (SocketTLS_Failed)
          {
            /* TLS enable failed */
          }
          END_TRY;

          Socket_free (&socket);
          socket = NULL;
          SocketTLSContext_free (&ctx);
          ctx = NULL;
        }
        break;

      case OP_SEND_RECV:
        {
          /* Test TLS send/recv operations */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);
          ctx = SocketTLSContext_new_client (NULL);

          TRY
          {
            SocketTLS_enable (socket, ctx);

            /* Try send (will fail but tests code paths) */
            size_t len = get_uint16 (data, 1, size) % sizeof (send_buf);
            if (len == 0)
              len = 64;

            TRY
            {
              ssize_t sent = SocketTLS_send (socket, send_buf, len);
              (void)sent;
            }
            EXCEPT (SocketTLS_Failed) { }
            EXCEPT (Socket_Closed) { }
            END_TRY;

            /* Try recv */
            TRY
            {
              ssize_t recvd = SocketTLS_recv (socket, recv_buf, sizeof (recv_buf));
              (void)recvd;
            }
            EXCEPT (SocketTLS_Failed) { }
            EXCEPT (Socket_Closed) { }
            END_TRY;
          }
          EXCEPT (SocketTLS_Failed)
          {
            /* TLS enable failed */
          }
          END_TRY;

          Socket_free (&socket);
          socket = NULL;
          SocketTLSContext_free (&ctx);
          ctx = NULL;
        }
        break;

      case OP_SHUTDOWN:
        {
          /* Test TLS shutdown */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);
          ctx = SocketTLSContext_new_client (NULL);

          TRY
          {
            SocketTLS_enable (socket, ctx);

            /* Try shutdown (tests shutdown paths) */
            TRY { SocketTLS_shutdown (socket); }
            EXCEPT (SocketTLS_ShutdownFailed) { }
            EXCEPT (SocketTLS_Failed) { }
            END_TRY;
          }
          EXCEPT (SocketTLS_Failed)
          {
            /* TLS enable failed */
          }
          END_TRY;

          Socket_free (&socket);
          socket = NULL;
          SocketTLSContext_free (&ctx);
          ctx = NULL;
        }
        break;

      case OP_INFO_QUERIES:
        {
          /* Test connection info query functions */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);
          ctx = SocketTLSContext_new_client (NULL);

          TRY
          {
            SocketTLS_enable (socket, ctx);

            /* Query various info (may return NULL/empty without connection) */
            const char *cipher = SocketTLS_get_cipher (socket);
            const char *version = SocketTLS_get_version (socket);
            const char *alpn = SocketTLS_get_alpn_selected (socket);
            int reused = SocketTLS_is_session_reused (socket);

            (void)cipher;
            (void)version;
            (void)alpn;
            (void)reused;

            /* Check TLS enabled via private field */
            assert (socket->tls_enabled == 1);
          }
          EXCEPT (SocketTLS_Failed)
          {
            /* TLS enable failed */
          }
          END_TRY;

          /* Check TLS enabled on non-TLS socket */
          Socket_T plain_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
          assert (plain_socket->tls_enabled == 0);
          Socket_free (&plain_socket);

          Socket_free (&socket);
          socket = NULL;
          SocketTLSContext_free (&ctx);
          ctx = NULL;
        }
        break;

      case OP_BUFFER_OPS:
        {
          /* Test with various buffer sizes */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);
          ctx = SocketTLSContext_new_client (NULL);

          TRY
          {
            SocketTLS_enable (socket, ctx);

            /* Test with edge case sizes */
            size_t sizes[] = { 1, 16, 256, 1024 };

            for (size_t i = 0; i < sizeof (sizes) / sizeof (sizes[0]); i++)
              {
                TRY
                {
                  if (sizes[i] <= sizeof (send_buf))
                    {
                      SocketTLS_send (socket, send_buf, sizes[i]);
                    }
                }
                EXCEPT (SocketTLS_Failed) { }
                EXCEPT (Socket_Closed) { }
                END_TRY;
              }
          }
          EXCEPT (SocketTLS_Failed)
          {
            /* TLS enable failed */
          }
          END_TRY;

          Socket_free (&socket);
          socket = NULL;
          SocketTLSContext_free (&ctx);
          ctx = NULL;
        }
        break;

      case OP_ERROR_PATHS:
        {
          /* Test error handling paths */

          /* Try operations on non-TLS socket */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          TRY { SocketTLS_handshake (socket); }
          EXCEPT (SocketTLS_Failed) { }
          EXCEPT (SocketTLS_HandshakeFailed) { }
          END_TRY;

          TRY { SocketTLS_send (socket, send_buf, 64); }
          EXCEPT (SocketTLS_Failed) { }
          EXCEPT (Socket_Failed) { }
          END_TRY;

          TRY { SocketTLS_recv (socket, recv_buf, sizeof (recv_buf)); }
          EXCEPT (SocketTLS_Failed) { }
          EXCEPT (Socket_Failed) { }
          END_TRY;

          TRY { SocketTLS_shutdown (socket); }
          EXCEPT (SocketTLS_Failed) { }
          EXCEPT (SocketTLS_ShutdownFailed) { }
          END_TRY;

          TRY { SocketTLS_set_hostname (socket, "test.com"); }
          EXCEPT (SocketTLS_Failed) { }
          END_TRY;

          Socket_free (&socket);
          socket = NULL;
        }
        break;

      default:
        break;
      }
  }
  EXCEPT (SocketTLS_Failed) { }
  EXCEPT (SocketTLS_HandshakeFailed) { }
  EXCEPT (SocketTLS_VerifyFailed) { }
  EXCEPT (SocketTLS_ProtocolError) { }
  EXCEPT (SocketTLS_ShutdownFailed) { }
  EXCEPT (Socket_Failed) { }
  ELSE { }
  END_TRY;

  /* Cleanup */
  if (socket)
    Socket_free (&socket);
  if (ctx)
    SocketTLSContext_free (&ctx);

  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* No-op fuzzer when TLS is not available */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */
