/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICError.c - QUIC Error Code String Conversion (RFC 9000 §20)
 *
 * Provides human-readable string representation of QUIC error codes.
 */

#include "quic/SocketQUICError.h"

#include <stdio.h>

/* ============================================================================
 * Transport Error Code Names (RFC 9000 Section 20.1)
 * ============================================================================
 */

static const char *transport_error_names[] = {
  "NO_ERROR",                  /* 0x00 */
  "INTERNAL_ERROR",            /* 0x01 */
  "CONNECTION_REFUSED",        /* 0x02 */
  "FLOW_CONTROL_ERROR",        /* 0x03 */
  "STREAM_LIMIT_ERROR",        /* 0x04 */
  "STREAM_STATE_ERROR",        /* 0x05 */
  "FINAL_SIZE_ERROR",          /* 0x06 */
  "FRAME_ENCODING_ERROR",      /* 0x07 */
  "TRANSPORT_PARAMETER_ERROR", /* 0x08 */
  "CONNECTION_ID_LIMIT_ERROR", /* 0x09 */
  "PROTOCOL_VIOLATION",        /* 0x0a */
  "INVALID_TOKEN",             /* 0x0b */
  "APPLICATION_ERROR",         /* 0x0c */
  "CRYPTO_BUFFER_EXCEEDED",    /* 0x0d */
  "KEY_UPDATE_ERROR",          /* 0x0e */
  "AEAD_LIMIT_REACHED",        /* 0x0f */
  "NO_VIABLE_PATH"             /* 0x10 */
};

#define TRANSPORT_ERROR_COUNT                                                 \
  (sizeof (transport_error_names) / sizeof (transport_error_names[0]))

/* ============================================================================
 * String Conversion
 * ============================================================================
 */

/**
 * Buffer size for crypto error string formatting.
 * Format "CRYPTO_ERROR(0x%02x)" produces at most 19 bytes + null terminator.
 */
#define QUIC_CRYPTO_ERROR_STRING_MAX 32

const char *
SocketQUIC_error_string (uint64_t code)
{
  /* Thread-local buffer for crypto error formatting */
  static __thread char crypto_buf[QUIC_CRYPTO_ERROR_STRING_MAX];

  /* Transport errors: 0x00-0x10 */
  if (code < TRANSPORT_ERROR_COUNT)
    return transport_error_names[code];

  /* Crypto errors: 0x0100-0x01ff */
  if (QUIC_IS_CRYPTO_ERROR (code))
    {
      int ret = snprintf (crypto_buf, sizeof (crypto_buf), "CRYPTO_ERROR(0x%02x)",
                          (unsigned int)QUIC_CRYPTO_ALERT (code));

      /* Defensive check: should never happen with current format */
      if (ret < 0 || (size_t)ret >= sizeof (crypto_buf))
        {
          /* Fallback to safe default on truncation or error */
          return "CRYPTO_ERROR(UNKNOWN)";
        }

      return crypto_buf;
    }

  /* Application errors */
  if (code >= QUIC_APPLICATION_ERROR_BASE)
    return "APPLICATION_PROTOCOL_ERROR";

  /* Unknown/reserved range (0x11-0xff) */
  return "UNKNOWN_ERROR";
}
