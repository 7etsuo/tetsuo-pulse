/**
 * fuzz_socketdgram.c - Fuzzer for UDP/datagram socket operations
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Socket lifecycle (new/free)
 * - Bind and connect operations
 * - Socket options (TTL, broadcast, timeout)
 * - Multicast join/leave
 * - State accessor functions
 * - Scatter/gather I/O setup
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_socketdgram
 * Run:   ./fuzz_socketdgram corpus/socketdgram/ -fork=16 -max_len=512
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/SocketDgram.h"

/* Operation codes */
enum DgramOp
{
  OP_LIFECYCLE = 0,
  OP_BIND,
  OP_CONNECT,
  OP_OPTIONS,
  OP_TTL,
  OP_MULTICAST,
  OP_ACCESSORS,
  OP_IOV_SETUP,
  OP_COUNT
};

/* Limits for fuzzing */
#define MAX_HOSTNAME_LEN 128
#define MAX_FUZZ_SOCKETS 8
#define MAX_IOV_COUNT 4

/**
 * read_u16 - Read 16-bit value from byte stream (little-endian)
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * extract_string - Extract null-terminated string from fuzz data
 * @data: Input data
 * @size: Size of input
 * @offset: Starting offset
 * @out: Output buffer
 * @out_len: Size of output buffer
 *
 * Returns: Length of extracted string (excluding null)
 */
static size_t
extract_string (const uint8_t *data, size_t size, size_t offset, char *out,
                size_t out_len)
{
  size_t i;
  size_t max_len = out_len - 1;

  if (offset >= size)
    {
      out[0] = '\0';
      return 0;
    }

  for (i = 0; i < max_len && (offset + i) < size; i++)
    {
      uint8_t c = data[offset + i];
      if (c == 0)
        break;
      /* Filter to printable ASCII for hostnames */
      if (c >= 32 && c < 127)
        out[i] = (char)c;
      else
        out[i] = 'x'; /* Replace non-printable */
    }
  out[i] = '\0';
  return i;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Byte 1: Socket domain selector (0=IPv4, 1=IPv6)
 * - Bytes 2-3: Port number
 * - Bytes 4-5: Option values (TTL, timeout, etc.)
 * - Remaining: Hostname/address string data
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketDgram_T sockets[MAX_FUZZ_SOCKETS];
  volatile int socket_count = 0;
  volatile int i;
  /* NOTE: This fuzzer uses IP addresses instead of hostnames to avoid DNS
   * delays. DNS resolution is tested separately by fuzz_dns_validate. */

  if (size < 6)
    return 0;

  uint8_t op = data[0];
  int domain = (data[1] & 0x01) ? AF_INET6 : AF_INET;
  uint16_t port = read_u16 (data + 2);
  uint16_t opt_value = read_u16 (data + 4);

  /* Initialize socket array */
  for (i = 0; i < MAX_FUZZ_SOCKETS; i++)
    sockets[i] = NULL;

  TRY
  {
    switch (op % OP_COUNT)
      {
      case OP_LIFECYCLE:
        {
          /* Test socket creation and destruction cycles */
          int num_sockets = (data[1] % MAX_FUZZ_SOCKETS) + 1;

          for (i = 0; i < num_sockets; i++)
            {
              TRY
              {
                /* Alternate between IPv4 and IPv6 */
                int sock_domain = (i & 1) ? AF_INET6 : AF_INET;
                sockets[socket_count] = SocketDgram_new (sock_domain, 0);
                if (sockets[socket_count])
                  {
                    socket_count++;

                    /* Verify socket is valid */
                    int fd = SocketDgram_fd (sockets[socket_count - 1]);
                    (void)fd;
                  }
              }
              EXCEPT (SocketDgram_Failed) { /* Socket creation can fail */ }
              END_TRY;
            }

          /* Verify live count tracking */
          int live_count = SocketDgram_debug_live_count ();
          (void)live_count;
        }
        break;

      case OP_BIND:
        {
          /* Test bind with various addresses and ports
           *
           * NOTE: We use IP addresses, not hostnames, because:
           * 1. This fuzzer tests socket operations, not DNS resolution
           * 2. DNS can block 5+ seconds on non-existent domains
           * 3. DNS testing is done separately by fuzz_dns_validate
           */
          TRY
          {
            sockets[socket_count] = SocketDgram_new (domain, 0);
            if (sockets[socket_count])
              {
                socket_count++;

                /* Use IP addresses to avoid DNS resolution delays
                 * Select based on fuzz input for coverage */
                static const char *bind_addrs[]
                    = { "127.0.0.1", "0.0.0.0", "::1", "::" };
                const char *bind_addr
                    = bind_addrs[(size > 6 ? data[6] : 0) % 4];

                TRY
                {
                  /* Use port 0 for kernel-assigned port to avoid conflicts */
                  SocketDgram_bind (sockets[0], bind_addr, 0);

                  /* Verify binding succeeded */
                  int is_bound = SocketDgram_isbound (sockets[0]);
                  const char *local_addr
                      = SocketDgram_getlocaladdr (sockets[0]);
                  int local_port = SocketDgram_getlocalport (sockets[0]);
                  (void)is_bound;
                  (void)local_addr;
                  (void)local_port;
                }
                EXCEPT (SocketDgram_Failed)
                {
                  /* Bind can fail for address family mismatch */
                }
                END_TRY;
              }
          }
          EXCEPT (SocketDgram_Failed) {}
          END_TRY;
        }
        break;

      case OP_CONNECT:
        {
          /* Test connect (UDP "connection" to filter packets)
           *
           * NOTE: We use IP addresses, not hostnames - same reasoning as
           * OP_BIND.
           */
          TRY
          {
            sockets[socket_count] = SocketDgram_new (domain, 0);
            if (sockets[socket_count])
              {
                socket_count++;

                /* Use loopback IP addresses */
                const char *connect_addr
                    = (size > 6 && (data[6] & 1)) ? "::1" : "127.0.0.1";

                /* Use safe port range */
                int connect_port = (port % 64000) + 1024;

                TRY
                {
                  SocketDgram_connect (sockets[0], connect_addr, connect_port);

                  /* Verify connection state */
                  int is_connected = SocketDgram_isconnected (sockets[0]);
                  (void)is_connected;
                }
                EXCEPT (SocketDgram_Failed)
                {
                  /* Connect can fail for address family mismatch */
                }
                END_TRY;
              }
          }
          EXCEPT (SocketDgram_Failed) {}
          END_TRY;
        }
        break;

      case OP_OPTIONS:
        {
          /* Test various socket options */
          TRY
          {
            sockets[socket_count] = SocketDgram_new (domain, 0);
            if (sockets[socket_count])
              {
                socket_count++;
                SocketDgram_T sock = sockets[0];

                /* Test each option based on sub-selector */
                uint8_t opt_selector = size > 6 ? data[6] : 0;

                switch (opt_selector % 8)
                  {
                  case 0:
                    SocketDgram_setnonblocking (sock);
                    break;

                  case 1:
                    SocketDgram_setreuseaddr (sock);
                    break;

                  case 2:
                    SocketDgram_setreuseport (sock);
                    break;

                  case 3:
                    SocketDgram_setbroadcast (sock, opt_value & 1);
                    {
                      int bc = SocketDgram_getbroadcast (sock);
                      (void)bc;
                    }
                    break;

                  case 4:
                    {
                      int timeout_sec = (int)(opt_value % 300);
                      SocketDgram_settimeout (sock, timeout_sec);
                      int got_timeout = SocketDgram_gettimeout (sock);
                      (void)got_timeout;
                    }
                    break;

                  case 5:
                    SocketDgram_setcloexec (sock, opt_value & 1);
                    break;

                  case 6:
                    {
                      int rcvbuf = SocketDgram_getrcvbuf (sock);
                      int sndbuf = SocketDgram_getsndbuf (sock);
                      (void)rcvbuf;
                      (void)sndbuf;
                    }
                    break;

                  case 7:
                    /* Multiple options in sequence */
                    SocketDgram_setreuseaddr (sock);
                    SocketDgram_setnonblocking (sock);
                    SocketDgram_setbroadcast (sock, 1);
                    break;
                  }
              }
          }
          EXCEPT (SocketDgram_Failed) {}
          END_TRY;
        }
        break;

      case OP_TTL:
        {
          /* Test TTL setting with boundary values */
          TRY
          {
            sockets[socket_count] = SocketDgram_new (domain, 0);
            if (sockets[socket_count])
              {
                socket_count++;

                /* TTL valid range is 1-255 */
                int ttl = (int)(opt_value % 300); /* May be invalid */

                TRY
                {
                  SocketDgram_setttl (sockets[0], ttl);

                  /* If successful, verify we can read it back */
                  int got_ttl = SocketDgram_getttl (sockets[0]);
                  (void)got_ttl;
                }
                EXCEPT (SocketDgram_Failed)
                {
                  /* TTL out of range (0 or >255) should fail */
                }
                END_TRY;

                /* Test boundary values explicitly */
                TRY { SocketDgram_setttl (sockets[0], 1); /* Min valid */ }
                EXCEPT (SocketDgram_Failed) {}
                END_TRY;

                TRY { SocketDgram_setttl (sockets[0], 255); /* Max valid */ }
                EXCEPT (SocketDgram_Failed) {}
                END_TRY;

                TRY
                {
                  SocketDgram_setttl (sockets[0], 0); /* Invalid - too low */
                }
                EXCEPT (SocketDgram_Failed) { /* Expected to fail */ }
                END_TRY;

                TRY
                {
                  SocketDgram_setttl (sockets[0],
                                      256); /* Invalid - too high */
                }
                EXCEPT (SocketDgram_Failed) { /* Expected to fail */ }
                END_TRY;
              }
          }
          EXCEPT (SocketDgram_Failed) {}
          END_TRY;
        }
        break;

      case OP_MULTICAST:
        {
          /* Test multicast join/leave operations
           *
           * NOTE: Multicast uses AI_NUMERICHOST so it doesn't do DNS lookup,
           * but we still use valid multicast addresses for meaningful testing.
           */
          TRY
          {
            /* Multicast requires IPv4 socket for simplicity */
            sockets[socket_count] = SocketDgram_new (AF_INET, 0);
            if (sockets[socket_count])
              {
                socket_count++;

                /* Use valid multicast addresses (224.0.0.0/4 range) */
                static const char *mcast_groups[]
                    = { "224.0.0.1", "224.0.0.251", "239.255.255.250" };
                const char *group = mcast_groups[(size > 6 ? data[6] : 0) % 3];

                TRY
                {
                  /* Join multicast group */
                  SocketDgram_joinmulticast (sockets[0], group, NULL);

                  /* Leave multicast group */
                  SocketDgram_leavemulticast (sockets[0], group, NULL);
                }
                EXCEPT (SocketDgram_Failed)
                {
                  /* Multicast operations can fail for invalid groups */
                }
                END_TRY;

                /* Test with interface specified */
                if (size > 64)
                  {
                    char iface[32];
                    extract_string (data, size, 64, iface, sizeof (iface));

                    TRY
                    {
                      SocketDgram_joinmulticast (sockets[0], "224.0.0.251",
                                                 iface[0] ? iface : NULL);
                    }
                    EXCEPT (SocketDgram_Failed) {}
                    END_TRY;
                  }
              }
          }
          EXCEPT (SocketDgram_Failed) {}
          END_TRY;
        }
        break;

      case OP_ACCESSORS:
        {
          /* Test state accessor functions */
          TRY
          {
            sockets[socket_count] = SocketDgram_new (domain, 0);
            if (sockets[socket_count])
              {
                socket_count++;
                SocketDgram_T sock = sockets[0];

                /* Test all accessors on unbound socket */
                int fd = SocketDgram_fd (sock);
                const char *local_addr = SocketDgram_getlocaladdr (sock);
                int local_port = SocketDgram_getlocalport (sock);
                int is_connected = SocketDgram_isconnected (sock);
                int is_bound = SocketDgram_isbound (sock);

                (void)fd;
                (void)local_addr;
                (void)local_port;
                (void)is_connected;
                (void)is_bound;

                /* Bind and test again */
                TRY
                {
                  SocketDgram_bind (sock, "127.0.0.1", 0);

                  /* Re-check accessors after bind */
                  local_addr = SocketDgram_getlocaladdr (sock);
                  local_port = SocketDgram_getlocalport (sock);
                  is_bound = SocketDgram_isbound (sock);

                  (void)local_addr;
                  (void)local_port;
                  (void)is_bound;
                }
                EXCEPT (SocketDgram_Failed) {}
                END_TRY;
              }
          }
          EXCEPT (SocketDgram_Failed) {}
          END_TRY;
        }
        break;

      case OP_IOV_SETUP:
        {
          /* Test scatter/gather I/O structure setup (no actual I/O) */
          TRY
          {
            sockets[socket_count] = SocketDgram_new (domain, 0);
            if (sockets[socket_count])
              {
                socket_count++;

                /* Bind to enable send/recv */
                TRY
                {
                  SocketDgram_bind (sockets[0], "127.0.0.1", 0);
                  SocketDgram_setnonblocking (sockets[0]);

                  /* Set up iovec structures from fuzz data */
                  struct iovec iov[MAX_IOV_COUNT];
                  char buffers[MAX_IOV_COUNT][64];
                  int iovcnt = (size > 6 ? data[6] % MAX_IOV_COUNT : 1) + 1;

                  for (int j = 0; j < iovcnt; j++)
                    {
                      size_t buf_len = (size > 7 + (size_t)j)
                                           ? (data[7 + j] % 64) + 1
                                           : 32;
                      iov[j].iov_base = buffers[j];
                      iov[j].iov_len = buf_len;

                      /* Initialize buffer with some data for sendv */
                      memset (buffers[j], 'A' + j, buf_len);
                    }

                  /* Try sendv - will likely fail (no destination) but tests
                   * setup */
                  TRY
                  {
                    /* Connect first to enable send */
                    SocketDgram_connect (sockets[0], "127.0.0.1", 9999);
                    SocketDgram_sendv (sockets[0], iov, iovcnt);
                  }
                  EXCEPT (SocketDgram_Failed) { /* Expected - no receiver */ }
                  END_TRY;

                  /* Try recvv - will return 0 (would block) */
                  TRY { SocketDgram_recvv (sockets[0], iov, iovcnt); }
                  EXCEPT (SocketDgram_Failed) {}
                  END_TRY;
                }
                EXCEPT (SocketDgram_Failed) {}
                END_TRY;
              }
          }
          EXCEPT (SocketDgram_Failed) {}
          END_TRY;
        }
        break;
      }
  }
  EXCEPT (SocketDgram_Failed) { /* Top-level exception handler */ }
  EXCEPT (Arena_Failed) { /* Memory allocation failure */ }
  FINALLY
  {
    /* Clean up all sockets */
    for (i = 0; i < socket_count; i++)
      {
        if (sockets[i])
          SocketDgram_free (&sockets[i]);
      }
  }
  END_TRY;

  return 0;
}
