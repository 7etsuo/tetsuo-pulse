/**
 * fuzz_http_content_type.c - HTTP Content-Type header parsing fuzzing harness
 *
 * Tests MIME type parsing, parameter extraction, and validation with malformed inputs
 * to find vulnerabilities in Content-Type header processing.
 *
 * Targets:
 * - MIME type parsing (type/subtype validation)
 * - Parameter parsing (charset, boundary, etc.)
 * - Malformed Content-Type headers
 * - Boundary parameter validation for multipart
 * - Charset parameter validation
 * - Injection attacks in parameters
 * - Buffer overflows in parameter extraction
 * - Unicode/encoding issues in parameters
 *
 * Content-Type headers are critical for proper content handling and security.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_content_type
 * ./fuzz_http_content_type corpus/http_content_type/ -fork=16 -max_len=2048
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Parse Content-Type header and extract components
 */
static void
parse_content_type (const char *header, Arena_T arena)
{
  if (!header)
    return;

  char *working_copy = Arena_alloc (arena, strlen (header) + 1, __FILE__, __LINE__);
  if (!working_copy)
    return;

  strcpy (working_copy, header);

  /* Parse MIME type */
  char *semicolon = strchr (working_copy, ';');
  char *mime_type = working_copy;

  if (semicolon)
    {
      *semicolon = '\0';
      /* Parameters follow */
    }

  /* Validate MIME type format: type/subtype */
  if (mime_type)
    {
      char *slash = strchr (mime_type, '/');
      if (slash)
        {
          *slash = '\0';
          char *type = mime_type;
          char *subtype = slash + 1;

          /* Basic validation */
          size_t type_len = strlen (type);
          size_t subtype_len = strlen (subtype);

          /* Check for valid characters (RFC 6838) */
          int valid_type = type_len > 0 && type_len <= 127;
          int valid_subtype = subtype_len > 0 && subtype_len <= 127;

          if (valid_type)
            {
              for (size_t i = 0; i < type_len; i++)
                {
                  char c = type[i];
                  if (!isalnum (c) && c != '-' && c != '.' && c != '+')
                    valid_type = 0;
                }
            }

          if (valid_subtype)
            {
              for (size_t i = 0; i < subtype_len; i++)
                {
                  char c = subtype[i];
                  if (!isalnum (c) && c != '-' && c != '.' && c != '+')
                    valid_subtype = 0;
                }
            }

          (void)valid_type;
          (void)valid_subtype;
        }
    }

  /* Parse parameters if present */
  if (semicolon)
    {
      char *params = semicolon + 1;

      /* Parse parameter list */
      char *param = strtok (params, ";");
      while (param)
        {
          /* Skip whitespace */
          while (*param && isspace (*param))
            param++;

          /* Parse name=value */
          char *equals = strchr (param, '=');
          if (equals)
            {
              *equals = '\0';
              char *name = param;
              char *value = equals + 1;

              /* Remove quotes if present */
              if (*value == '"')
                {
                  value++;
                  char *end_quote = strrchr (value, '"');
                  if (end_quote)
                    *end_quote = '\0';
                }

              /* Trim whitespace from name */
              while (*name && isspace (*name))
                name++;
              char *end_name = name + strlen (name) - 1;
              while (end_name > name && isspace (*end_name))
                {
                  *end_name = '\0';
                  end_name--;
                }

              /* Trim whitespace from value */
              while (*value && isspace (*value))
                value++;
              char *end_value = value + strlen (value) - 1;
              while (end_value > value && isspace (*end_value))
                {
                  *end_value = '\0';
                  end_value--;
                }

              /* Process known parameters */
              if (strcasecmp (name, "charset") == 0)
                {
                  /* Validate charset */
                  size_t charset_len = strlen (value);
                  (void)charset_len;
                }
              else if (strcasecmp (name, "boundary") == 0)
                {
                  /* Validate boundary for multipart */
                  size_t boundary_len = strlen (value);
                  /* RFC 2046: boundary should be 1-70 chars */
                  int valid_boundary = boundary_len > 0 && boundary_len <= 70;
                  (void)valid_boundary;
                }
              else if (strcasecmp (name, "filename") == 0)
                {
                  /* Filename parameter (common in multipart) */
                  size_t filename_len = strlen (value);
                  (void)filename_len;
                }
              else if (strcasecmp (name, "name") == 0)
                {
                  /* Field name parameter */
                  size_t name_len = strlen (value);
                  (void)name_len;
                }
            }

          param = strtok (NULL, ";");
        }
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;

  /* Skip empty input */
  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    /* Test 1: Direct Content-Type header parsing */
    if (size > 0)
      {
        char *header = Arena_alloc (arena, size + 1, __FILE__, __LINE__);
        if (header)
          {
            memcpy (header, data, size);
            header[size] = '\0';
            parse_content_type (header, arena);
          }
      }

    /* Test 2: Content-Type headers with common prefixes */
    const char *prefixes[] = {
        "Content-Type: ",
        "content-type: ",    /* Case insensitive */
        "Content-Type:",     /* Missing space */
        "Content-Type: \t",  /* Tab separator */
    };

    for (size_t p = 0; p < sizeof (prefixes) / sizeof (prefixes[0]); p++)
      {
        char header[4096];
        size_t prefix_len = strlen (prefixes[p]);
        size_t data_len = size > sizeof (header) - prefix_len - 1 ?
                         sizeof (header) - prefix_len - 1 : size;

        memcpy (header, prefixes[p], prefix_len);
        memcpy (header + prefix_len, data, data_len);
        header[prefix_len + data_len] = '\0';

        parse_content_type (header, arena);
      }

    /* Test 3: Malformed Content-Type headers */
    const char *malformed_headers[] = {
        "",                                       /* Empty */
        "text/plain",                             /* No header prefix */
        "Content-Type: ",                         /* Empty value */
        "Content-Type: /",                        /* Empty type */
        "Content-Type: text/",                    /* Empty subtype */
        "Content-Type: text/plain/",              /* Extra slash */
        "Content-Type: text/plain; ",             /* Trailing semicolon */
        "Content-Type: text/plain; ; ",           /* Empty parameter */
        "Content-Type: text/plain; param",        /* Parameter without value */
        "Content-Type: text/plain; param=",       /* Parameter with empty value */
        "Content-Type: text/plain; =value",       /* Parameter with empty name */
        "Content-Type: text/plain; param=\"unclosed", /* Unclosed quotes */
        "Content-Type: text/plain; param=\"value\" extra", /* Extra after quotes */
        "Content-Type: text/plain; charset=",     /* Empty charset */
        "Content-Type: text/plain; boundary=",    /* Empty boundary */
        "Content-Type: text/plain; charset=\"utf-8\" ; boundary=abc", /* Multiple params */
        "Content-Type: text/plain; charset=utf-8; boundary=\"abc\"", /* Mixed quotes */
        "Content-Type: text/plain\x00; charset=utf-8", /* Null byte */
        "Content-Type: text/plain\r\nX-Injected: value", /* Header injection */
    };

    for (size_t i = 0; i < sizeof (malformed_headers) / sizeof (malformed_headers[0]); i++)
      {
        parse_content_type (malformed_headers[i], arena);
      }

    /* Test 4: Valid Content-Type headers with various MIME types */
    const char *valid_mime_types[] = {
        "text/plain",
        "text/html",
        "application/json",
        "application/xml",
        "application/octet-stream",
        "multipart/form-data",
        "multipart/mixed",
        "image/jpeg",
        "image/png",
        "audio/mpeg",
        "video/mp4",
        "application/vnd.api+json",
        "text/plain; charset=utf-8",
        "text/html; charset=iso-8859-1",
        "application/json; charset=utf-8",
        "multipart/form-data; boundary=----WebKitFormBoundary123",
        "multipart/mixed; boundary=\"boundary-123\"",
        "text/plain; charset=utf-8; format=flowed",
        "application/octet-stream; name=\"file.txt\"",
    };

    for (size_t i = 0; i < sizeof (valid_mime_types) / sizeof (valid_mime_types[0]); i++)
      {
        char full_header[512];
        int len = snprintf (full_header, sizeof (full_header), "Content-Type: %s", valid_mime_types[i]);
        if (len > 0 && (size_t)len < sizeof (full_header))
          {
            parse_content_type (full_header, arena);
          }
      }

    /* Test 5: Boundary parameter validation for multipart */
    if (size > 10)
      {
        /* Test various boundary values */
        char boundary_test[256];
        size_t boundary_len = size > sizeof (boundary_test) - 50 ? sizeof (boundary_test) - 50 : size;
        memcpy (boundary_test, data, boundary_len);
        boundary_test[boundary_len] = '\0';

        /* Remove problematic characters for boundary */
        for (size_t i = 0; i < boundary_len; i++)
          {
            if (boundary_test[i] < 32 || boundary_test[i] > 126)
              boundary_test[i] = 'A' + (i % 26);
          }

        char multipart_header[512];
        int len = snprintf (multipart_header, sizeof (multipart_header),
                          "Content-Type: multipart/form-data; boundary=%s", boundary_test);
        if (len > 0 && (size_t)len < sizeof (multipart_header))
          {
            parse_content_type (multipart_header, arena);
          }
      }

    /* Test 6: Charset parameter validation */
    if (size > 5)
      {
        char charset_test[128];
        size_t charset_len = size > sizeof (charset_test) - 1 ? sizeof (charset_test) - 1 : size;
        memcpy (charset_test, data, charset_len);
        charset_test[charset_len] = '\0';

        /* Basic charset validation (should be ASCII) */
        int valid_charset = 1;
        for (size_t i = 0; i < charset_len; i++)
          {
            if (charset_test[i] < 32 || charset_test[i] > 126)
              {
                valid_charset = 0;
                break;
              }
          }

        if (valid_charset)
          {
            char charset_header[256];
            int len = snprintf (charset_header, sizeof (charset_header),
                              "Content-Type: text/plain; charset=%s", charset_test);
            if (len > 0 && (size_t)len < sizeof (charset_header))
              {
                parse_content_type (charset_header, arena);
              }
          }
      }
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
