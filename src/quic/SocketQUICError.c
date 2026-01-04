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

#include "core/SocketUtil.h"

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

#define TRANSPORT_ERROR_COUNT \
  (sizeof (transport_error_names) / sizeof (transport_error_names[0]))

/* ============================================================================
 * TLS Alert Names (RFC 8446 Section 6)
 * ============================================================================
 */

typedef struct
{
  uint8_t code;
  const char *name;
} TLSAlertEntry;

static const TLSAlertEntry tls_alert_names[]
    = { { 0, "close_notify" },
        { 10, "unexpected_message" },
        { 20, "bad_record_mac" },
        { 22, "record_overflow" },
        { 40, "handshake_failure" },
        { 42, "bad_certificate" },
        { 43, "unsupported_certificate" },
        { 44, "certificate_revoked" },
        { 45, "certificate_expired" },
        { 46, "certificate_unknown" },
        { 47, "illegal_parameter" },
        { 48, "unknown_ca" },
        { 49, "access_denied" },
        { 50, "decode_error" },
        { 51, "decrypt_error" },
        { 70, "protocol_version" },
        { 71, "insufficient_security" },
        { 80, "internal_error" },
        { 86, "inappropriate_fallback" },
        { 90, "user_canceled" },
        { 109, "missing_extension" },
        { 110, "unsupported_extension" },
        { 112, "unrecognized_name" },
        { 113, "bad_certificate_status_response" },
        { 115, "unknown_psk_identity" },
        { 116, "certificate_required" },
        { 120, "no_application_protocol" } };

#define TLS_ALERT_COUNT (sizeof (tls_alert_names) / sizeof (tls_alert_names[0]))

const char *
SocketQUIC_tls_alert_string (uint8_t alert)
{
  for (size_t i = 0; i < TLS_ALERT_COUNT; i++)
    {
      if (tls_alert_names[i].code == alert)
        return tls_alert_names[i].name;
    }
  return NULL;
}

/* ============================================================================
 * String Conversion
 * ============================================================================
 */

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
      uint8_t alert = (uint8_t)QUIC_CRYPTO_ALERT (code);
      const char *name = SocketQUIC_tls_alert_string (alert);

      int ret;
      if (name != NULL)
        {
          ret = snprintf (
              crypto_buf, sizeof (crypto_buf), "CRYPTO_ERROR(%s)", name);
        }
      else
        {
          ret = snprintf (
              crypto_buf, sizeof (crypto_buf), "CRYPTO_ERROR(0x%02x)", alert);
        }

      /* Defensive check: should never happen with current format */
      if (SOCKET_SNPRINTF_CHECK (ret, sizeof (crypto_buf)) < 0)
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
