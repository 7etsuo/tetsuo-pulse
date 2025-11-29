/**
 * fuzz_address_parse.c - Fuzzer for address resolution and port validation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketCommon_resolve_address() with malformed inputs
 * - IPv6 bracket notation [::1]:port parsing
 * - Port range validation (1-65535)
 * - Address family detection
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_address_parse
 * Run:   ./fuzz_address_parse corpus/address_parse/ -fork=16 -max_len=512
 */

#include <assert.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketCommon.h"

/* Maximum address string length */
#define MAX_ADDR_LEN 256

/* Operation codes */
enum AddrOp
{
  ADDR_RESOLVE_TCP = 0,
  ADDR_RESOLVE_UDP,
  ADDR_RESOLVE_PASSIVE,
  ADDR_RESOLVE_IPV4_ONLY,
  ADDR_RESOLVE_IPV6_ONLY,
  ADDR_PARSE_IP,
  ADDR_OP_COUNT
};

/**
 * read_u16 - Read a 16-bit value from byte stream
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * make_address_string - Create null-terminated address from fuzz data
 */
static void
make_address_string (char *buf, size_t bufsize, const uint8_t *data,
                     size_t size)
{
  if (size == 0 || bufsize < 2)
    {
      buf[0] = '\0';
      return;
    }

  size_t len = size < bufsize - 1 ? size : bufsize - 1;
  memcpy (buf, data, len);
  buf[len] = '\0';
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Bytes 1-2: Port number
 * - Remaining: Address string
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char addr_str[MAX_ADDR_LEN];
  struct addrinfo hints;
  struct addrinfo *res = NULL;

  if (size < 3)
    return 0;

  uint8_t op = data[0];
  int port = read_u16 (data + 1);
  const uint8_t *addr_data = data + 3;
  size_t addr_size = size - 3;

  /* Make address string from fuzz data */
  make_address_string (addr_str, sizeof (addr_str), addr_data, addr_size);

  /* Initialize hints */
  memset (&hints, 0, sizeof (hints));

  TRY
  {
    switch (op % ADDR_OP_COUNT)
      {
      case ADDR_RESOLVE_TCP:
        {
          /* TCP address resolution */
          SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);
          int result = SocketCommon_resolve_address (
              addr_str[0] ? addr_str : NULL, port, &hints, &res,
              SocketCommon_Failed, AF_UNSPEC, 0);
          (void)result;
          if (res)
            SocketCommon_free_addrinfo (res);
          res = NULL;
        }
        break;

      case ADDR_RESOLVE_UDP:
        {
          /* UDP address resolution */
          SocketCommon_setup_hints (&hints, SOCK_DGRAM, 0);
          int result = SocketCommon_resolve_address (
              addr_str[0] ? addr_str : NULL, port, &hints, &res,
              SocketCommon_Failed, AF_UNSPEC, 0);
          (void)result;
          if (res)
            SocketCommon_free_addrinfo (res);
          res = NULL;
        }
        break;

      case ADDR_RESOLVE_PASSIVE:
        {
          /* Passive (server) address resolution */
          SocketCommon_setup_hints (&hints, SOCK_STREAM, AI_PASSIVE);
          int result = SocketCommon_resolve_address (NULL, port, &hints, &res,
                                                     SocketCommon_Failed,
                                                     AF_UNSPEC, 0);
          (void)result;
          if (res)
            SocketCommon_free_addrinfo (res);
          res = NULL;
        }
        break;

      case ADDR_RESOLVE_IPV4_ONLY:
        {
          /* IPv4-only resolution */
          SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);
          hints.ai_family = AF_INET;
          int result = SocketCommon_resolve_address (
              addr_str[0] ? addr_str : NULL, port, &hints, &res,
              SocketCommon_Failed, AF_INET, 0);
          (void)result;
          if (res)
            SocketCommon_free_addrinfo (res);
          res = NULL;
        }
        break;

      case ADDR_RESOLVE_IPV6_ONLY:
        {
          /* IPv6-only resolution */
          SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);
          hints.ai_family = AF_INET6;
          int result = SocketCommon_resolve_address (
              addr_str[0] ? addr_str : NULL, port, &hints, &res,
              SocketCommon_Failed, AF_INET6, 0);
          (void)result;
          if (res)
            SocketCommon_free_addrinfo (res);
          res = NULL;
        }
        break;

      case ADDR_PARSE_IP:
        {
          /* Direct IP parsing */
          int family = 0;
          int result = SocketCommon_parse_ip (addr_str, &family);
          (void)result;
          (void)family;

          /* Also test with NULL family output */
          result = SocketCommon_parse_ip (addr_str, NULL);
          (void)result;
        }
        break;
      }
  }
  EXCEPT (SocketCommon_Failed)
  {
    /* Expected for invalid addresses/ports */
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected for resolution failures */
  }
  FINALLY
  {
    if (res)
      SocketCommon_free_addrinfo (res);
  }
  END_TRY;

  return 0;
}

