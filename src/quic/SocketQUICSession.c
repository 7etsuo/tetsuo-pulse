/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICSession.c
 * @brief QUIC Session Resumption and HelloRetryRequest (RFC 9001 §4.5, §4.7).
 */

#include "quic/SocketQUICSession.h"

#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"

#if SOCKET_HAS_TLS
#include <openssl/crypto.h>
#endif

/* ============================================================================
 * Module Exception
 * ============================================================================
 */

const Except_T SocketQUICSession_Failed
    = { &SocketQUICSession_Failed, "SocketQUICSession_Failed" };

/* ============================================================================
 * String Tables
 * ============================================================================
 */

static const char *const state_strings[] = {
  [QUIC_SESSION_STATE_NONE] = "NONE",
  [QUIC_SESSION_STATE_STORED] = "STORED",
  [QUIC_SESSION_STATE_ATTEMPTING] = "ATTEMPTING",
  [QUIC_SESSION_STATE_RESUMED] = "RESUMED",
  [QUIC_SESSION_STATE_NEW] = "NEW",
};

static const char *const result_strings[] = {
  [QUIC_SESSION_OK] = "OK",
  [QUIC_SESSION_ERROR_NULL] = "NULL argument",
  [QUIC_SESSION_ERROR_STATE] = "Invalid state",
  [QUIC_SESSION_ERROR_TICKET] = "Invalid ticket",
  [QUIC_SESSION_ERROR_HRR] = "HelloRetryRequest error",
  [QUIC_SESSION_ERROR_COOKIE] = "Cookie validation failed",
  [QUIC_SESSION_ERROR_MEMORY] = "Memory allocation failed",
  [QUIC_SESSION_ERROR_TRANSPORT] = "Transport parameter mismatch",
  [QUIC_SESSION_ERROR_ALPN] = "ALPN mismatch",
  [QUIC_SESSION_ERROR_EXPIRED] = "Session expired",
  [QUIC_SESSION_ERROR_NOT_RESUMABLE] = "Session not resumable",
};

/* ============================================================================
 * Internal Helpers
 * ============================================================================
 */

/**
 * @brief Get current time in seconds since epoch.
 */
static uint64_t
get_current_time (void)
{
  return (uint64_t)time (NULL);
}

/**
 * @brief Securely clear sensitive memory.
 */
static void
secure_clear (void *ptr, size_t len)
{
  if (ptr == NULL || len == 0)
    return;

#if SOCKET_HAS_TLS
  OPENSSL_cleanse (ptr, len);
#else
  volatile unsigned char *p = ptr;
  while (len--)
    *p++ = 0;
#endif
}

/**
 * @brief Check if ticket has expired.
 */
static int
ticket_is_expired (const SocketQUICTicket_T *ticket)
{
  if (!ticket->valid)
    return 1;

  uint64_t now = get_current_time ();

  /* Handle clock skew - if current time is before issue time, treat as expired */
  if (now < ticket->issue_time)
    return 1;

  uint64_t age = now - ticket->issue_time;

  if (age > ticket->lifetime)
    return 1;

  if (age > QUIC_SESSION_MAX_AGE_SECONDS)
    return 1;

  return 0;
}

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

SocketQUICSession_T
SocketQUICSession_new (Arena_T arena)
{
  if (arena == NULL)
    return NULL;

  SocketQUICSession_T session
      = Arena_alloc (arena, sizeof (*session), __FILE__, __LINE__);
  if (session == NULL)
    return NULL;

  memset (session, 0, sizeof (*session));
  session->arena = arena;
  session->state = QUIC_SESSION_STATE_NONE;

  return session;
}

void
SocketQUICSession_free (SocketQUICSession_T *session)
{
  if (session == NULL || *session == NULL)
    return;

  SocketQUICSession_T s = *session;

  secure_clear (s->ticket.ticket, s->ticket.ticket_len);
  secure_clear (s->hrr.cookie, s->hrr.cookie_len);
  secure_clear (s->hrr.transcript_hash, sizeof (s->hrr.transcript_hash));

  memset (s, 0, sizeof (*s));
  *session = NULL;
}

/* ============================================================================
 * Session Ticket Functions (RFC 9001 §4.5)
 * ============================================================================
 */

SocketQUICSession_Result
SocketQUICSession_store_ticket (SocketQUICSession_T session,
                                const uint8_t *ticket_data,
                                size_t ticket_len,
                                uint32_t lifetime,
                                uint32_t age_add,
                                uint32_t max_early_data)
{
  if (session == NULL)
    return QUIC_SESSION_ERROR_NULL;

  if (ticket_data == NULL || ticket_len == 0)
    return QUIC_SESSION_ERROR_TICKET;

  if (ticket_len > QUIC_SESSION_MAX_TICKET_SIZE)
    return QUIC_SESSION_ERROR_TICKET;

  if (lifetime == 0 || lifetime > QUIC_SESSION_MAX_AGE_SECONDS)
    return QUIC_SESSION_ERROR_TICKET;

  secure_clear (session->ticket.ticket, session->ticket.ticket_len);

  memcpy (session->ticket.ticket, ticket_data, ticket_len);
  session->ticket.ticket_len = ticket_len;
  session->ticket.lifetime = lifetime;
  session->ticket.age_add = age_add;
  session->ticket.issue_time = get_current_time ();
  session->ticket.max_early_data = max_early_data;
  session->ticket.valid = 1;

  if (max_early_data == QUIC_SESSION_0RTT_SENTINEL)
    session->enable_0rtt = 1;
  else
    session->enable_0rtt = 0;

  session->state = QUIC_SESSION_STATE_STORED;

  return QUIC_SESSION_OK;
}

int
SocketQUICSession_can_attempt_0rtt (SocketQUICSession_T session)
{
  if (session == NULL)
    return 0;

  if (!session->ticket.valid)
    return 0;

  if (ticket_is_expired (&session->ticket))
    return 0;

  if (session->ticket.max_early_data != QUIC_SESSION_0RTT_SENTINEL)
    return 0;

  if (!session->enable_0rtt)
    return 0;

  if (!session->params.params_valid)
    return 0;

  return 1;
}

int
SocketQUICSession_can_resume (SocketQUICSession_T session)
{
  if (session == NULL)
    return 0;

  if (!session->ticket.valid)
    return 0;

  if (ticket_is_expired (&session->ticket))
    return 0;

  return 1;
}

uint32_t
SocketQUICSession_get_obfuscated_age (SocketQUICSession_T session)
{
  if (session == NULL || !session->ticket.valid)
    return 0;

  uint64_t now = get_current_time ();
  uint64_t age_ms = (now - session->ticket.issue_time) * 1000;

  return (uint32_t)((age_ms + session->ticket.age_add) & 0xffffffffUL);
}

SocketQUICSession_Result
SocketQUICSession_save_transport_params (
    SocketQUICSession_T session, const SocketQUICTransportParams_T *params)
{
  if (session == NULL)
    return QUIC_SESSION_ERROR_NULL;

  if (params == NULL)
    return QUIC_SESSION_ERROR_NULL;

  session->params.initial_max_data = params->initial_max_data;
  session->params.initial_max_stream_data_bidi_local
      = params->initial_max_stream_data_bidi_local;
  session->params.initial_max_stream_data_bidi_remote
      = params->initial_max_stream_data_bidi_remote;
  session->params.initial_max_stream_data_uni
      = params->initial_max_stream_data_uni;
  session->params.initial_max_streams_bidi = params->initial_max_streams_bidi;
  session->params.initial_max_streams_uni = params->initial_max_streams_uni;
  session->params.active_connection_id_limit
      = params->active_connection_id_limit;
  session->params.params_valid = 1;

  return QUIC_SESSION_OK;
}

SocketQUICSession_Result
SocketQUICSession_validate_transport_params (
    SocketQUICSession_T session, const SocketQUICTransportParams_T *new_params)
{
  if (session == NULL || new_params == NULL)
    return QUIC_SESSION_ERROR_NULL;

  if (!session->params.params_valid)
    return QUIC_SESSION_ERROR_TRANSPORT;

  const SocketQUICSessionParams_T *saved = &session->params;

  if (new_params->initial_max_data < saved->initial_max_data)
    return QUIC_SESSION_ERROR_TRANSPORT;

  if (new_params->initial_max_stream_data_bidi_local
      < saved->initial_max_stream_data_bidi_local)
    return QUIC_SESSION_ERROR_TRANSPORT;

  if (new_params->initial_max_stream_data_bidi_remote
      < saved->initial_max_stream_data_bidi_remote)
    return QUIC_SESSION_ERROR_TRANSPORT;

  if (new_params->initial_max_stream_data_uni
      < saved->initial_max_stream_data_uni)
    return QUIC_SESSION_ERROR_TRANSPORT;

  if (new_params->initial_max_streams_bidi < saved->initial_max_streams_bidi)
    return QUIC_SESSION_ERROR_TRANSPORT;

  if (new_params->initial_max_streams_uni < saved->initial_max_streams_uni)
    return QUIC_SESSION_ERROR_TRANSPORT;

  if (new_params->active_connection_id_limit < saved->active_connection_id_limit)
    return QUIC_SESSION_ERROR_TRANSPORT;

  return QUIC_SESSION_OK;
}

void
SocketQUICSession_clear_ticket (SocketQUICSession_T session)
{
  if (session == NULL)
    return;

  secure_clear (session->ticket.ticket, session->ticket.ticket_len);
  memset (&session->ticket, 0, sizeof (session->ticket));
  session->enable_0rtt = 0;

  if (session->state == QUIC_SESSION_STATE_STORED)
    session->state = QUIC_SESSION_STATE_NONE;
}

/* ============================================================================
 * HelloRetryRequest Functions (RFC 9001 §4.7)
 * ============================================================================
 */

SocketQUICSession_Result
SocketQUICSession_on_hrr_received (SocketQUICSession_T session,
                                   const uint8_t *cookie,
                                   size_t cookie_len)
{
  if (session == NULL)
    return QUIC_SESSION_ERROR_NULL;

  if (cookie_len > QUIC_SESSION_MAX_COOKIE_SIZE)
    return QUIC_SESSION_ERROR_COOKIE;

  session->hrr.hrr_received = 1;

  if (cookie != NULL && cookie_len > 0)
    {
      memcpy (session->hrr.cookie, cookie, cookie_len);
      session->hrr.cookie_len = cookie_len;
    }
  else
    {
      session->hrr.cookie_len = 0;
    }

  return QUIC_SESSION_OK;
}

SocketQUICSession_Result
SocketQUICSession_on_hrr_sent (SocketQUICSession_T session)
{
  if (session == NULL)
    return QUIC_SESSION_ERROR_NULL;

  session->hrr.hrr_sent = 1;

  return QUIC_SESSION_OK;
}

int
SocketQUICSession_is_hrr (SocketQUICSession_T session)
{
  if (session == NULL)
    return 0;

  return session->hrr.hrr_received || session->hrr.hrr_sent;
}

SocketQUICSession_Result
SocketQUICSession_get_hrr_cookie (SocketQUICSession_T session,
                                  const uint8_t **cookie,
                                  size_t *cookie_len)
{
  if (session == NULL || cookie == NULL || cookie_len == NULL)
    return QUIC_SESSION_ERROR_NULL;

  if (!session->hrr.hrr_received)
    return QUIC_SESSION_ERROR_HRR;

  if (session->hrr.cookie_len == 0)
    return QUIC_SESSION_ERROR_COOKIE;

  *cookie = session->hrr.cookie;
  *cookie_len = session->hrr.cookie_len;

  return QUIC_SESSION_OK;
}

SocketQUICSession_Result
SocketQUICSession_set_hrr_transcript (SocketQUICSession_T session,
                                      const uint8_t hash[32])
{
  if (session == NULL || hash == NULL)
    return QUIC_SESSION_ERROR_NULL;

  memcpy (session->hrr.transcript_hash, hash, 32);
  session->hrr.transcript_hash_valid = 1;

  return QUIC_SESSION_OK;
}

int
SocketQUICSession_hrr_rejects_0rtt (SocketQUICSession_T session)
{
  if (session == NULL)
    return 0;

  return session->hrr.hrr_sent != 0;
}

/* ============================================================================
 * State Query Functions
 * ============================================================================
 */

SocketQUICSessionState
SocketQUICSession_get_state (SocketQUICSession_T session)
{
  if (session == NULL)
    return QUIC_SESSION_STATE_NONE;

  return session->state;
}

int
SocketQUICSession_is_resumed (SocketQUICSession_T session)
{
  if (session == NULL)
    return 0;

  return session->state == QUIC_SESSION_STATE_RESUMED;
}

void
SocketQUICSession_mark_resumed (SocketQUICSession_T session)
{
  if (session == NULL)
    return;

  session->state = QUIC_SESSION_STATE_RESUMED;
}

void
SocketQUICSession_mark_new (SocketQUICSession_T session)
{
  if (session == NULL)
    return;

  session->state = QUIC_SESSION_STATE_NEW;
}

/* ============================================================================
 * ALPN Functions (RFC 9001 §4.6.3)
 * ============================================================================
 */

SocketQUICSession_Result
SocketQUICSession_save_alpn (SocketQUICSession_T session,
                             const char *alpn,
                             size_t alpn_len)
{
  if (session == NULL)
    return QUIC_SESSION_ERROR_NULL;

  if (alpn == NULL || alpn_len == 0)
    return QUIC_SESSION_ERROR_ALPN;

  if (alpn_len >= sizeof (session->alpn))
    return QUIC_SESSION_ERROR_ALPN;

  memcpy (session->alpn, alpn, alpn_len);
  session->alpn[alpn_len] = '\0';
  session->alpn_len = alpn_len;

  return QUIC_SESSION_OK;
}

SocketQUICSession_Result
SocketQUICSession_validate_alpn (SocketQUICSession_T session,
                                 const char *alpn,
                                 size_t alpn_len)
{
  if (session == NULL || alpn == NULL)
    return QUIC_SESSION_ERROR_NULL;

  if (session->alpn_len == 0)
    return QUIC_SESSION_OK;

  if (alpn_len != session->alpn_len)
    return QUIC_SESSION_ERROR_ALPN;

  if (memcmp (session->alpn, alpn, alpn_len) != 0)
    return QUIC_SESSION_ERROR_ALPN;

  return QUIC_SESSION_OK;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

const char *
SocketQUICSession_state_string (SocketQUICSessionState state)
{
  if (state < 0 || (size_t)state >= sizeof (state_strings) / sizeof (char *))
    return "UNKNOWN";

  return state_strings[state];
}

const char *
SocketQUICSession_result_string (SocketQUICSession_Result result)
{
  if (result < 0 || (size_t)result >= sizeof (result_strings) / sizeof (char *))
    return "UNKNOWN";

  return result_strings[result];
}
