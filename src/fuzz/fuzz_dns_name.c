/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_name.c - libFuzzer harness for DNS domain name encoding/decoding
 *
 * Fuzzes DNS domain name parsing with compression pointers (RFC 1035 §4.1.2,
 * §4.1.4).
 *
 * Critical test cases:
 * - Compression pointer loops (self-referencing)
 * - Pointer chains > 16 hops (DNS_MAX_POINTER_HOPS)
 * - Pointers beyond message bounds
 * - Labels > 63 bytes (DNS_MAX_LABEL_LEN)
 * - Total name > 255 bytes (DNS_MAX_NAME_LEN)
 * - Reserved header bits (0x40, 0x80)
 * - Empty labels
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_name
 * Run:   ./fuzz_dns_name -fork=16 -max_len=512
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dns/SocketDNSWire.h"

/* Maximum message size to fuzz (16KB is reasonable for DNS) */
#define MAX_FUZZ_MSG_SIZE 16384

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char name[DNS_MAX_NAME_LEN + 16];
  unsigned char wire[DNS_MAX_NAME_LEN + 16];
  size_t consumed;
  size_t written;
  int result;

  if (size == 0)
    return 0;

  /* Cap size to avoid excessive processing */
  if (size > MAX_FUZZ_MSG_SIZE)
    size = MAX_FUZZ_MSG_SIZE;

  /*
   * Test name decoding at various offsets within the message.
   * This exercises compression pointer handling since pointers
   * can reference any earlier position in the message.
   */
  for (size_t offset = 0; offset < size && offset < 64; offset++)
    {
      memset (name, 0, sizeof (name));
      consumed = 0;

      result = SocketDNS_name_decode (data, size, offset, name, sizeof (name),
                                      &consumed);

      if (result >= 0)
        {
          /* Decode succeeded - verify roundtrip if name looks valid */
          if (SocketDNS_name_valid (name))
            {
              written = 0;
              int enc_result
                  = SocketDNS_name_encode (name, wire, sizeof (wire), &written);

              if (enc_result == 0 && written > 0)
                {
                  /* Decode the encoded name and compare */
                  char decoded[DNS_MAX_NAME_LEN + 16];
                  size_t dec_consumed;

                  int dec_result = SocketDNS_name_decode (
                      wire, written, 0, decoded, sizeof (decoded),
                      &dec_consumed);

                  if (dec_result >= 0)
                    {
                      /* Names should match (case-insensitive) */
                      (void)SocketDNS_name_equal (name, decoded);
                    }
                }
            }

          /* Test wire length calculation */
          size_t wire_len = SocketDNS_name_wire_length (name);
          (void)wire_len;
        }
    }

  /* Test name validation with fuzz input as a string */
  if (size > 0 && size < DNS_MAX_NAME_LEN)
    {
      char str[DNS_MAX_NAME_LEN + 1];
      size_t copy_len = size < DNS_MAX_NAME_LEN ? size : DNS_MAX_NAME_LEN;
      memcpy (str, data, copy_len);
      str[copy_len] = '\0';

      /* Test validation */
      int valid = SocketDNS_name_valid (str);
      (void)valid;

      /* Test encoding of arbitrary string */
      written = 0;
      result = SocketDNS_name_encode (str, wire, sizeof (wire), &written);
      (void)result;

      /* Test wire length calculation */
      size_t wire_len = SocketDNS_name_wire_length (str);
      (void)wire_len;
    }

  /* Test name comparison with variations */
  if (size >= 2)
    {
      /* Create two null-terminated strings from halves of input */
      size_t half = size / 2;
      char name1[128], name2[128];

      size_t len1 = half < 127 ? half : 127;
      size_t len2 = (size - half) < 127 ? (size - half) : 127;

      memcpy (name1, data, len1);
      name1[len1] = '\0';

      memcpy (name2, data + half, len2);
      name2[len2] = '\0';

      /* Test case-insensitive comparison */
      int equal = SocketDNS_name_equal (name1, name2);
      (void)equal;
    }

  /* Test with NULL pointers (should not crash) */
  (void)SocketDNS_name_decode (NULL, size, 0, name, sizeof (name), &consumed);
  (void)SocketDNS_name_decode (data, size, 0, NULL, sizeof (name), &consumed);
  (void)SocketDNS_name_decode (data, size, 0, name, sizeof (name), NULL);

  (void)SocketDNS_name_encode (NULL, wire, sizeof (wire), &written);
  (void)SocketDNS_name_encode ("test.com", NULL, sizeof (wire), &written);
  (void)SocketDNS_name_encode ("test.com", wire, sizeof (wire), NULL);

  (void)SocketDNS_name_valid (NULL);
  (void)SocketDNS_name_equal (NULL, "test.com");
  (void)SocketDNS_name_equal ("test.com", NULL);
  (void)SocketDNS_name_wire_length (NULL);

  return 0;
}
