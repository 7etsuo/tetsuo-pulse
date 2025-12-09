/**
 * fuzz_http2_settings.c - HTTP/2 Settings Frame Fuzzer
 *
 * Part of the Socket Library
 * Fuzzes HTTP/2 SETTINGS frame payload parsing.
 */

#include "http/SocketHTTP2.h"
#include <stdint.h>
#include <string.h>

/**
 * Parse and validate settings payload as per RFC 9113 Section 6.5
 * Settings payload format: 6 bytes per setting (2 ID + 4 value)
 */
static int
validate_settings_payload (const uint8_t *data, size_t size)
{
  size_t offset = 0;

  /* Settings must be multiple of 6 bytes */
  if (size % 6 != 0)
    return -1;

  while (offset + 6 <= size)
    {
      uint16_t id = ((uint16_t)data[offset] << 8) | data[offset + 1];
      uint32_t value = ((uint32_t)data[offset + 2] << 24)
                       | ((uint32_t)data[offset + 3] << 16)
                       | ((uint32_t)data[offset + 4] << 8) | data[offset + 5];

      /* Validate settings per RFC 9113 */
      switch (id)
        {
        case HTTP2_SETTINGS_ENABLE_PUSH:
          if (value > 1)
            return -1;
          break;

        case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
          if (value > 0x7FFFFFFF)
            return -1;
          break;

        case HTTP2_SETTINGS_MAX_FRAME_SIZE:
          if (value < SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE
              || value > SOCKETHTTP2_MAX_MAX_FRAME_SIZE)
            return -1;
          break;

        default:
          /* Unknown settings are ignored per RFC */
          break;
        }

      offset += 6;
    }

  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Test settings validation */
  validate_settings_payload (data, size);

  /* Test with various sizes to ensure no crashes */
  for (size_t i = 0; i < size && i <= 120; i += 6)
    {
      validate_settings_payload (data, i);
    }

  return 0;
}
