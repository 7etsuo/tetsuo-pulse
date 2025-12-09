/**
 * fuzz_uri_parse.c - URI Parsing Fuzzing Harness
 *
 * Part of the Socket Library Fuzz Testing Suite
 *
 * Tests URI parsing with random/malformed input to find crashes,
 * memory safety issues, and unexpected behavior.
 */

#include "core/Arena.h"
#include "http/SocketHTTP.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * LibFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Limit maximum size to prevent excessive memory usage */
  if (size > SOCKETHTTP_MAX_URI_LEN + 100)
    return 0;

  Arena_T arena = Arena_new ();
  if (!arena)
    return 0;

  SocketHTTP_URI uri;
  char output[SOCKETHTTP_MAX_URI_LEN + 1];

  /* Test URI parsing */
  SocketHTTP_URIResult result
      = SocketHTTP_URI_parse ((const char *)data, size, &uri, arena);

  /* If parse succeeded, test related functions */
  if (result == URI_PARSE_OK)
    {
      /* Test port getter */
      (void)SocketHTTP_URI_get_port (&uri, 80);
      (void)SocketHTTP_URI_get_port (&uri, 443);

      /* Test secure check */
      (void)SocketHTTP_URI_is_secure (&uri);

      /* Test building back to string */
      (void)SocketHTTP_URI_build (&uri, output, sizeof (output));
    }

  /* Test result string */
  (void)SocketHTTP_URI_result_string (result);

  /* Test encoding/decoding */
  if (size < 1024)
    {
      char encoded[4096];
      ssize_t enc_len = SocketHTTP_URI_encode ((const char *)data, size,
                                               encoded, sizeof (encoded));

      if (enc_len > 0)
        {
          char decoded[1024];
          (void)SocketHTTP_URI_decode (encoded, (size_t)enc_len, decoded,
                                       sizeof (decoded));
        }
    }

  Arena_dispose (&arena);
  return 0;
}
