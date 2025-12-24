/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_verify_callback.c - Fuzzer for TLS Custom Verification Callbacks
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketTLSContext_set_verify_callback() configuration
 * - internal_verify_callback() wrapper behavior
 * - Exception handling in callback invocation
 * - Callback parameter validation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_verify_callback Run:   ./fuzz_tls_verify_callback
 * corpus/tls_verify_callback/ -fork=16 -max_len=4096
 */

#if SOCKET_HAS_TLS

#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Operation codes for fuzzing verify callback behavior */
enum VerifyCallbackOp
{
  VERIFY_CB_NULL = 0,     /* Set NULL callback */
  VERIFY_CB_ACCEPT,       /* Callback that accepts */
  VERIFY_CB_REJECT,       /* Callback that rejects */
  VERIFY_CB_RAISE_TLS,    /* Callback that raises SocketTLS_Failed */
  VERIFY_CB_RAISE_CUSTOM, /* Callback that raises custom exception */
  VERIFY_CB_MODE_CHANGE,  /* Change verify mode after callback set */
  VERIFY_CB_OP_COUNT
};

/* Custom exception for testing */
static const Except_T Fuzz_CustomException
    = { &Fuzz_CustomException, "Fuzz custom exception" };

/* Callback counters for verification */
static volatile int g_callback_count = 0;
static volatile int g_last_preverify = -1;

/**
 * fuzz_accept_cb - Accept callback for fuzzing
 */
static int
fuzz_accept_cb (int pre_ok, X509_STORE_CTX *x509_ctx,
                SocketTLSContext_T tls_ctx, Socket_T sock, void *user_data)
{
  (void)tls_ctx;
  (void)sock;
  (void)user_data;

  g_callback_count++;
  g_last_preverify = pre_ok;

  /* Accept by clearing any error */
  if (x509_ctx)
    X509_STORE_CTX_set_error (x509_ctx, X509_V_OK);

  return 1;
}

/**
 * fuzz_reject_cb - Reject callback for fuzzing
 */
static int
fuzz_reject_cb (int pre_ok, X509_STORE_CTX *x509_ctx,
                SocketTLSContext_T tls_ctx, Socket_T sock, void *user_data)
{
  (void)tls_ctx;
  (void)sock;
  (void)user_data;

  g_callback_count++;
  g_last_preverify = pre_ok;

  /* Reject by setting error */
  if (x509_ctx)
    X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);

  return 0;
}

/**
 * fuzz_raise_tls_cb - Callback that raises SocketTLS_Failed
 */
static int
fuzz_raise_tls_cb (int pre_ok, X509_STORE_CTX *x509_ctx,
                   SocketTLSContext_T tls_ctx, Socket_T sock, void *user_data)
{
  (void)pre_ok;
  (void)x509_ctx;
  (void)tls_ctx;
  (void)sock;
  (void)user_data;

  g_callback_count++;
  RAISE (SocketTLS_Failed);
  return 1; /* Unreachable */
}

/**
 * fuzz_raise_custom_cb - Callback that raises custom exception
 */
static int
fuzz_raise_custom_cb (int pre_ok, X509_STORE_CTX *x509_ctx,
                      SocketTLSContext_T tls_ctx, Socket_T sock,
                      void *user_data)
{
  (void)pre_ok;
  (void)x509_ctx;
  (void)tls_ctx;
  (void)sock;
  (void)user_data;

  g_callback_count++;
  RAISE (Fuzz_CustomException);
  return 1; /* Unreachable */
}

/**
 * fuzz_verify_callback_config - Test verify callback configuration
 * @op: Operation to perform
 * @mode_byte: Verify mode selector
 * @user_data_valid: Whether to pass valid user_data
 *
 * Tests various callback configurations and verify mode combinations.
 */
static void
fuzz_verify_callback_config (uint8_t op, uint8_t mode_byte,
                             uint8_t user_data_valid)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      RAISE (SocketTLS_Failed);

    /* Select callback based on operation */
    SocketTLSVerifyCallback cb = NULL;
    void *user_data = NULL;

    switch (op % VERIFY_CB_OP_COUNT)
      {
      case VERIFY_CB_NULL:
        cb = NULL;
        break;
      case VERIFY_CB_ACCEPT:
        cb = fuzz_accept_cb;
        break;
      case VERIFY_CB_REJECT:
        cb = fuzz_reject_cb;
        break;
      case VERIFY_CB_RAISE_TLS:
        cb = fuzz_raise_tls_cb;
        break;
      case VERIFY_CB_RAISE_CUSTOM:
        cb = fuzz_raise_custom_cb;
        break;
      case VERIFY_CB_MODE_CHANGE:
        cb = fuzz_accept_cb;
        break;
      }

    if (user_data_valid)
      user_data = (void *)0xDEADBEEF;

    /* Select verify mode */
    TLSVerifyMode mode;
    switch (mode_byte % 4)
      {
      case 0:
        mode = TLS_VERIFY_NONE;
        break;
      case 1:
        mode = TLS_VERIFY_PEER;
        break;
      case 2:
        mode = TLS_VERIFY_FAIL_IF_NO_PEER_CERT;
        break;
      case 3:
        mode = TLS_VERIFY_CLIENT_ONCE;
        break;
      default:
        mode = TLS_VERIFY_PEER;
        break;
      }

    /* Apply configuration */
    SocketTLSContext_set_verify_mode (ctx, mode);
    SocketTLSContext_set_verify_callback (ctx, cb, user_data);

    /* For MODE_CHANGE operation, change mode after setting callback */
    if (op % VERIFY_CB_OP_COUNT == VERIFY_CB_MODE_CHANGE)
      {
        TLSVerifyMode new_mode = (mode_byte & 0x80) ? TLS_VERIFY_NONE
                                                    : TLS_VERIFY_PEER;
        SocketTLSContext_set_verify_mode (ctx, new_mode);
      }

    /* Reset callback to NULL and set again */
    SocketTLSContext_set_verify_callback (ctx, NULL, NULL);
    SocketTLSContext_set_verify_callback (ctx, cb, user_data);
  }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  ELSE { caught = 1; }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;

  (void)caught;
}

/**
 * fuzz_verify_mode_transitions - Test verify mode state transitions
 * @data: Sequence of mode changes
 * @size: Number of mode changes
 *
 * Tests rapid changes between verify modes with callbacks.
 */
static void
fuzz_verify_mode_transitions (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      RAISE (SocketTLS_Failed);

    /* Set initial callback */
    SocketTLSContext_set_verify_callback (ctx, fuzz_accept_cb, NULL);

    /* Perform mode transitions based on fuzz data */
    for (size_t i = 0; i < size && i < 64; i++)
      {
        TLSVerifyMode mode;
        switch (data[i] % 4)
          {
          case 0:
            mode = TLS_VERIFY_NONE;
            break;
          case 1:
            mode = TLS_VERIFY_PEER;
            break;
          case 2:
            mode = TLS_VERIFY_FAIL_IF_NO_PEER_CERT;
            break;
          case 3:
            mode = TLS_VERIFY_CLIENT_ONCE;
            break;
          default:
            mode = TLS_VERIFY_PEER;
            break;
          }

        SocketTLSContext_set_verify_mode (ctx, mode);

        /* Occasionally toggle callback */
        if (data[i] & 0x80)
          {
            if (data[i] & 0x40)
              SocketTLSContext_set_verify_callback (ctx, fuzz_reject_cb, NULL);
            else
              SocketTLSContext_set_verify_callback (ctx, NULL, NULL);
          }
      }
  }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  ELSE { caught = 1; }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;

  (void)caught;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation type selector
 * - Byte 1: Verify mode selector
 * - Byte 2: User data valid flag
 * - Remaining: Additional fuzz data for transitions
 *
 * Tests verify callback configuration and mode transitions.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 3)
    return 0;

  /* Reset global state */
  g_callback_count = 0;
  g_last_preverify = -1;

  uint8_t op = data[0];
  uint8_t mode_byte = data[1];
  uint8_t user_data_flag = data[2];

  /* Clear any stale OpenSSL errors */
  ERR_clear_error ();

  /* Test callback configuration */
  fuzz_verify_callback_config (op, mode_byte, user_data_flag);

  /* Test mode transitions if we have enough data */
  if (size > 3)
    fuzz_verify_mode_transitions (data + 3, size - 3);

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
