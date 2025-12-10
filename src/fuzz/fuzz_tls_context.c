/**
 * fuzz_tls_context.c - Fuzzer for TLS Context Management (Section 2.1-2.3)
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketTLSContext_new_server() - Server context creation
 * - SocketTLSContext_new_client() - Client context creation
 * - SocketTLSContext_new() - Custom config context creation
 * - SocketTLSContext_load_certificate() - Certificate loading
 * - SocketTLSContext_load_ca() - CA loading
 * - SocketTLSContext_set_verify_mode() - Verify mode mapping
 * - SocketTLSContext_free() - Resource cleanup
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_context Run:   ./fuzz_tls_context corpus/tls_context/ -fork=16
 * -max_len=32768
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

/* Operation codes for fuzzing */
enum ContextOp
{
  CTX_OP_NEW_CLIENT = 0,
  CTX_OP_NEW_CLIENT_CA,
  CTX_OP_NEW_WITH_CONFIG,
  CTX_OP_SET_VERIFY_MODE,
  CTX_OP_SET_PROTOCOL,
  CTX_OP_SET_CIPHERS,
  CTX_OP_ENABLE_SESSION_CACHE,
  CTX_OP_LOAD_CA_PATH,
  CTX_OP_COUNT
};

/* Verify modes to test */
static const TLSVerifyMode verify_modes[] = {
  TLS_VERIFY_NONE,
  TLS_VERIFY_PEER,
  TLS_VERIFY_FAIL_IF_NO_PEER_CERT,
  TLS_VERIFY_CLIENT_ONCE,
};
#define NUM_VERIFY_MODES (sizeof (verify_modes) / sizeof (verify_modes[0]))

/* Protocol versions to test */
static const int protocol_versions[] = {
  TLS1_VERSION,
  TLS1_1_VERSION,
  TLS1_2_VERSION,
  TLS1_3_VERSION,
};
#define NUM_PROTOCOL_VERSIONS                                                 \
  (sizeof (protocol_versions) / sizeof (protocol_versions[0]))

/**
 * extract_string - Safely extract a null-terminated string from fuzz data
 * @data: Fuzz data
 * @size: Data size
 * @max_len: Maximum string length
 * @out_str: Output buffer (must be at least max_len + 1 bytes)
 *
 * Returns: Length of extracted string
 */
static size_t
extract_string (const uint8_t *data, size_t size, size_t max_len, char *out_str)
{
  size_t len = (size > max_len) ? max_len : size;
  memcpy (out_str, data, len);
  out_str[len] = '\0';
  return len;
}

/**
 * fuzz_new_client - Test SocketTLSContext_new_client()
 */
static void
fuzz_new_client (void)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (ctx)
      {
        /* Exercise basic accessors */
        (void)SocketTLSContext_is_server (ctx);
        (void)SocketTLSContext_get_ssl_ctx (ctx);
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for some inputs */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);
}

/**
 * fuzz_new_client_with_ca - Test SocketTLSContext_new_client() with CA path
 * @path: CA file path (may be malformed)
 */
static void
fuzz_new_client_with_ca (const char *path)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (path);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid paths */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);
}

/**
 * fuzz_new_with_config - Test SocketTLSContext_new() with custom config
 * @data: Fuzz data for config values
 * @size: Data size
 */
static void
fuzz_new_with_config (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = NULL;
  SocketTLSConfig_T config;

  SocketTLS_config_defaults (&config);

  /* Override with fuzz values if available */
  if (size >= 2)
    {
      /* Select min/max versions from valid set */
      config.min_version = protocol_versions[data[0] % NUM_PROTOCOL_VERSIONS];
      config.max_version = protocol_versions[data[1] % NUM_PROTOCOL_VERSIONS];

      /* Ensure min <= max */
      if (config.min_version > config.max_version)
        {
          int tmp = config.min_version;
          config.min_version = config.max_version;
          config.max_version = tmp;
        }
    }

  TRY
  {
    ctx = SocketTLSContext_new (&config);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid config combinations */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);

  /* Also test with NULL config */
  TRY
  {
    ctx = SocketTLSContext_new (NULL);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Unexpected but handle gracefully */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);
}

/**
 * fuzz_set_verify_mode - Test SocketTLSContext_set_verify_mode()
 * @mode_idx: Index into verify_modes array
 */
static void
fuzz_set_verify_mode (uint8_t mode_idx)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (ctx)
      {
        TLSVerifyMode mode = verify_modes[mode_idx % NUM_VERIFY_MODES];
        SocketTLSContext_set_verify_mode (ctx, mode);
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Handle gracefully */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);
}

/**
 * fuzz_set_protocol - Test SocketTLSContext_set_min/max_protocol()
 * @min_idx: Index for min protocol version
 * @max_idx: Index for max protocol version
 */
static void
fuzz_set_protocol (uint8_t min_idx, uint8_t max_idx)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (ctx)
      {
        int min_ver = protocol_versions[min_idx % NUM_PROTOCOL_VERSIONS];
        int max_ver = protocol_versions[max_idx % NUM_PROTOCOL_VERSIONS];

        SocketTLSContext_set_min_protocol (ctx, min_ver);
        SocketTLSContext_set_max_protocol (ctx, max_ver);
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid combinations */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);
}

/**
 * fuzz_set_ciphers - Test SocketTLSContext_set_cipher_list()
 * @cipher_str: Cipher string (may be malformed)
 */
static void
fuzz_set_ciphers (const char *cipher_str)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (ctx)
      SocketTLSContext_set_cipher_list (ctx, cipher_str);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid cipher strings */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);
}

/**
 * fuzz_enable_session_cache - Test SocketTLSContext_enable_session_cache()
 * @data: Fuzz data for cache parameters
 * @size: Data size
 */
static void
fuzz_enable_session_cache (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = NULL;
  size_t max_sessions = 100;
  long timeout = 300;

  if (size >= 4)
    {
      max_sessions = (size_t) (data[0] | ((uint16_t)data[1] << 8));
      timeout = (long)(data[2] | ((uint16_t)data[3] << 8));
    }

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (ctx)
      SocketTLSContext_enable_session_cache (ctx, max_sessions, timeout);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid parameters */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);
}

/**
 * fuzz_load_ca_path - Test SocketTLSContext_load_ca() with fuzz path
 * @path: CA path (may be malformed)
 */
static void
fuzz_load_ca_path (const char *path)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (ctx)
      SocketTLSContext_load_ca (ctx, path);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid paths */
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: Operation-specific data
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  uint8_t op = data[0];
  const uint8_t *op_data = data + 1;
  size_t op_size = size - 1;

  /* Clear any stale OpenSSL errors */
  ERR_clear_error ();

  switch (op % CTX_OP_COUNT)
    {
    case CTX_OP_NEW_CLIENT:
      fuzz_new_client ();
      break;

    case CTX_OP_NEW_CLIENT_CA:
      {
        char path_buf[512];
        extract_string (op_data, op_size, sizeof (path_buf) - 1, path_buf);
        fuzz_new_client_with_ca (path_buf);
      }
      break;

    case CTX_OP_NEW_WITH_CONFIG:
      fuzz_new_with_config (op_data, op_size);
      break;

    case CTX_OP_SET_VERIFY_MODE:
      if (op_size >= 1)
        fuzz_set_verify_mode (op_data[0]);
      break;

    case CTX_OP_SET_PROTOCOL:
      if (op_size >= 2)
        fuzz_set_protocol (op_data[0], op_data[1]);
      break;

    case CTX_OP_SET_CIPHERS:
      {
        char cipher_buf[256];
        extract_string (op_data, op_size, sizeof (cipher_buf) - 1, cipher_buf);
        fuzz_set_ciphers (cipher_buf);
      }
      break;

    case CTX_OP_ENABLE_SESSION_CACHE:
      fuzz_enable_session_cache (op_data, op_size);
      break;

    case CTX_OP_LOAD_CA_PATH:
      {
        char path_buf[512];
        extract_string (op_data, op_size, sizeof (path_buf) - 1, path_buf);
        fuzz_load_ca_path (path_buf);
      }
      break;
    }

  /* Clear errors generated during fuzzing */
  ERR_clear_error ();

  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* Stub for non-TLS builds */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */
