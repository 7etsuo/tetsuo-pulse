/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSoverHTTPS.c
 * @brief DNS-over-HTTPS transport implementation (RFC 8484).
 * @ingroup dns_doh
 *
 * Implements encrypted DNS transport using HTTPS.
 *
 * ## Key Implementation Details
 *
 * - POST method with application/dns-message content type (default)
 * - GET method with base64url-encoded DNS query in ?dns= parameter
 * - HTTP/2 multiplexing support via SocketHTTPClient
 * - Cache-Control header integration for response caching
 */

#include "dns/SocketDNSoverHTTPS.h"

#if SOCKET_HAS_TLS

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "dns/SocketDNSWire.h"
#include "http/SocketHTTPClient.h"

#undef T
#define T SocketDNSoverHTTPS_T

/** Maximum DNS message size (64KB). */
#define DOH_MAX_MESSAGE_SIZE 65535

/** Maximum URL length for GET requests. */
#define DOH_MAX_URL_LENGTH 2048

/** Maximum query size for GET method (to prevent base64 explosion). */
#define DOH_MAX_GET_QUERY_SIZE 512

/* Well-known DoH servers */
static const struct
{
  const char *name;
  const char *url;
} well_known_servers[] = {
  { "google", "https://dns.google/dns-query" },
  { "cloudflare", "https://cloudflare-dns.com/dns-query" },
  { "quad9", "https://dns.quad9.net/dns-query" },
  { "nextdns", "https://dns.nextdns.io" },
  { NULL, NULL }
};

/* Server configuration entry */
struct ServerConfig
{
  char url[DOH_MAX_SERVER_URL_LENGTH];
  SocketDNSoverHTTPS_Method method;
  int prefer_http2;
  int timeout_ms;
};

/* Pending query */
struct SocketDNSoverHTTPS_Query
{
  uint16_t id;
  unsigned char *query_copy;
  size_t query_len;
  int64_t sent_time_ms;
  int cancelled;
  int completed;
  int error;
  SocketDNSoverHTTPS_Callback callback;
  void *userdata;

  /* HTTP response data (copy for callback) */
  unsigned char *response;
  size_t response_len;

  struct SocketDNSoverHTTPS_Query *next;
  struct SocketDNSoverHTTPS_Query *prev;
};

/* Main transport structure */
struct T
{
  Arena_T arena;

  /* HTTP client */
  SocketHTTPClient_T http_client;

  /* Server configuration */
  struct ServerConfig servers[DOH_MAX_SERVERS];
  int server_count;
  int current_server;

  /* Pending queries (for tracking only - queries are synchronous) */
  struct SocketDNSoverHTTPS_Query *pending_head;
  struct SocketDNSoverHTTPS_Query *pending_tail;
  int pending_count;

  /* Statistics */
  SocketDNSoverHTTPS_Stats stats;
};

const Except_T SocketDNSoverHTTPS_Failed
    = { &SocketDNSoverHTTPS_Failed, "DNS-over-HTTPS operation failed" };

/* Use centralized monotonic time utility from SocketUtil.h */
#define get_monotonic_ms() Socket_get_monotonic_ms()

/**
 * Convert standard Base64 to Base64URL (RFC 4648 Section 5).
 * Replaces + with -, / with _, and removes padding.
 */
static size_t
base64url_encode (const unsigned char *input, size_t input_len, char *output,
                  size_t output_size)
{
  ssize_t len
      = SocketCrypto_base64_encode (input, input_len, output, output_size);
  if (len < 0)
    return 0;

  /* Convert to URL-safe alphabet */
  for (size_t i = 0; i < (size_t)len; i++)
    {
      if (output[i] == '+')
        output[i] = '-';
      else if (output[i] == '/')
        output[i] = '_';
    }

  /* Remove padding */
  while (len > 0 && output[len - 1] == '=')
    len--;

  output[len] = '\0';
  return (size_t)len;
}

/* Extract DNS message ID from query buffer */
static uint16_t
extract_query_id (const unsigned char *query, size_t len)
{
  if (len < 2)
    return 0;
  return (uint16_t)((query[0] << 8) | query[1]);
}

/* Map DNS RCODE to DoH error code */
static int
rcode_to_error (int rcode)
{
  switch (rcode)
    {
    case DNS_RCODE_NOERROR:
      return DOH_ERROR_SUCCESS;
    case DNS_RCODE_FORMERR:
      return DOH_ERROR_FORMERR;
    case DNS_RCODE_SERVFAIL:
      return DOH_ERROR_SERVFAIL;
    case DNS_RCODE_NXDOMAIN:
      return DOH_ERROR_NXDOMAIN;
    case DNS_RCODE_REFUSED:
      return DOH_ERROR_REFUSED;
    default:
      return DOH_ERROR_INVALID;
    }
}

/* Add query to pending list */
static void
add_pending_query (T transport, struct SocketDNSoverHTTPS_Query *q)
{
  q->next = NULL;
  q->prev = transport->pending_tail;

  if (transport->pending_tail)
    transport->pending_tail->next = q;
  else
    transport->pending_head = q;

  transport->pending_tail = q;
  transport->pending_count++;
}

/* Remove query from pending list */
static void
remove_pending_query (T transport, struct SocketDNSoverHTTPS_Query *q)
{
  if (q->prev)
    q->prev->next = q->next;
  else
    transport->pending_head = q->next;

  if (q->next)
    q->next->prev = q->prev;
  else
    transport->pending_tail = q->prev;

  transport->pending_count--;
}

T
SocketDNSoverHTTPS_new (Arena_T arena)
{
  T transport;

  assert (arena);

  transport = ALLOC (arena, sizeof (*transport));
  memset (transport, 0, sizeof (*transport));

  transport->arena = arena;
  transport->server_count = 0;
  transport->current_server = 0;
  transport->pending_head = NULL;
  transport->pending_tail = NULL;
  transport->pending_count = 0;

  /* Create HTTP client with HTTP/2 support */
  SocketHTTPClient_Config config;
  SocketHTTPClient_config_defaults (&config);
  config.max_version = HTTP_VERSION_2;
  config.enable_connection_pool = 1;
  config.max_connections_per_host = 2;
  config.request_timeout_ms = DOH_QUERY_TIMEOUT_MS;
  config.connect_timeout_ms = DOH_CONNECT_TIMEOUT_MS;

  transport->http_client = SocketHTTPClient_new (&config);
  if (!transport->http_client)
    RAISE (SocketDNSoverHTTPS_Failed);

  return transport;
}

void
SocketDNSoverHTTPS_free (T *transport)
{
  if (!transport || !*transport)
    return;

  T t = *transport;

  /* Cancel all pending queries */
  struct SocketDNSoverHTTPS_Query *q = t->pending_head;
  while (q)
    {
      struct SocketDNSoverHTTPS_Query *next = q->next;
      if (!q->completed && q->callback)
        {
          q->callback ((SocketDNSoverHTTPS_Query_T)q, NULL, 0,
                       DOH_ERROR_CANCELLED, q->userdata);
        }
      q = next;
    }

  /* Free HTTP client */
  if (t->http_client)
    SocketHTTPClient_free (&t->http_client);

  *transport = NULL;
}

int
SocketDNSoverHTTPS_configure (T transport,
                               const SocketDNSoverHTTPS_Config *config)
{
  assert (transport);
  assert (config);
  assert (config->url);

  if (transport->server_count >= DOH_MAX_SERVERS)
    return -1;

  struct ServerConfig *s = &transport->servers[transport->server_count];

  size_t url_len = strlen (config->url);
  if (url_len >= sizeof (s->url))
    return -1;

  /* SECURITY: Validate URL scheme is https:// to prevent SSRF */
  if (strncmp (config->url, "https://", 8) != 0)
    return -1;

  /* SECURITY: Reject control characters in URL to prevent injection */
  for (size_t i = 0; i < url_len; i++)
    {
      unsigned char c = (unsigned char)config->url[i];
      if (c < 0x20 || c == 0x7F)
        return -1;
    }

  memcpy (s->url, config->url, url_len + 1); /* Include null terminator */
  s->method = config->method;
  s->prefer_http2 = config->prefer_http2 ? 1 : 0; /* Respect HTTP/2 preference */
  s->timeout_ms
      = config->timeout_ms > 0 ? config->timeout_ms : DOH_QUERY_TIMEOUT_MS;

  transport->server_count++;
  return 0;
}

int
SocketDNSoverHTTPS_add_server (T transport, const char *server_name)
{
  assert (transport);
  assert (server_name);

  for (int i = 0; well_known_servers[i].name; i++)
    {
      if (strcasecmp (server_name, well_known_servers[i].name) == 0)
        {
          SocketDNSoverHTTPS_Config cfg = { .url = well_known_servers[i].url,
                                             .method = DOH_METHOD_POST,
                                             .prefer_http2 = 1,
                                             .timeout_ms
                                             = DOH_QUERY_TIMEOUT_MS };
          return SocketDNSoverHTTPS_configure (transport, &cfg);
        }
    }

  return -1; /* Unknown server */
}

void
SocketDNSoverHTTPS_clear_servers (T transport)
{
  assert (transport);
  transport->server_count = 0;
  transport->current_server = 0;
}

int
SocketDNSoverHTTPS_server_count (T transport)
{
  assert (transport);
  return transport->server_count;
}

/**
 * Build GET request URL with base64url-encoded DNS query.
 *
 * @param transport Transport context (for arena allocation).
 * @param query DNS query buffer.
 * @param len Query length.
 * @param server Server configuration.
 * @param url_out Output URL string (arena-allocated).
 * @param error_out Output error code on failure.
 * @return 0 on success, -1 on failure.
 */
static int
doh_build_get_request (T transport, const unsigned char *query, size_t len,
                       struct ServerConfig *server, char **url_out,
                       int *error_out)
{
  assert (transport);
  assert (query);
  assert (server);
  assert (url_out);
  assert (error_out);

  /* SECURITY: Enforce maximum query size for GET method to prevent
   * memory exhaustion via base64 encoding. Use POST for large queries. */
  if (len > DOH_MAX_GET_QUERY_SIZE)
    {
      *error_out = DOH_ERROR_INVALID;
      return -1;
    }

  /* Base64URL encode the DNS query */
  size_t b64_size = SocketCrypto_base64_encoded_size (len);
  char *b64 = ALLOC (transport->arena, b64_size);
  size_t b64_len = base64url_encode (query, len, b64, b64_size);

  if (b64_len == 0)
    {
      *error_out = DOH_ERROR_INVALID;
      return -1;
    }

  /* Build URL with query parameter */
  char *url = ALLOC (transport->arena, DOH_MAX_URL_LENGTH);
  int url_len
      = snprintf (url, DOH_MAX_URL_LENGTH, "%s?dns=%s", server->url, b64);

  if (url_len < 0 || url_len >= DOH_MAX_URL_LENGTH)
    {
      *error_out = DOH_ERROR_INVALID;
      return -1;
    }

  *url_out = url;
  return 0;
}

/**
 * Execute HTTP request (GET or POST based on server configuration).
 *
 * @param transport Transport context.
 * @param server Server configuration.
 * @param query DNS query buffer.
 * @param len Query length.
 * @param response Output HTTP response structure.
 * @param error_out Output error code on failure.
 * @return 0 on success, -1 on failure.
 */
static int
doh_execute_request (T transport, struct ServerConfig *server,
                     const unsigned char *query, size_t len,
                     SocketHTTPClient_Response *response, int *error_out)
{
  assert (transport);
  assert (server);
  assert (query);
  assert (response);
  assert (error_out);

  volatile int request_ok = 0;
  volatile int http_error = DOH_ERROR_NETWORK;

  TRY
  {
    int ret;

    if (server->method == DOH_METHOD_GET)
      {
        char *url = NULL;
        int build_err = DOH_ERROR_SUCCESS;

        if (doh_build_get_request (transport, query, len, server, &url,
                                   &build_err)
            != 0)
          {
            http_error = build_err;
            request_ok = 0;
          }
        else
          {
            /* Execute GET request */
            ret = SocketHTTPClient_get (transport->http_client, url, response);
            request_ok = (ret == 0) ? 1 : 0;
          }
      }
    else
      {
        /* Execute POST request */
        ret = SocketHTTPClient_post (transport->http_client, server->url,
                                     "application/dns-message", query, len,
                                     response);
        request_ok = (ret == 0) ? 1 : 0;
      }
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    request_ok = 0;
    http_error = DOH_ERROR_HTTP;
  }
  EXCEPT (SocketHTTPClient_DNSFailed)
  {
    request_ok = 0;
    http_error = DOH_ERROR_NETWORK;
  }
  EXCEPT (SocketHTTPClient_ConnectFailed)
  {
    request_ok = 0;
    http_error = DOH_ERROR_NETWORK;
  }
  EXCEPT (SocketHTTPClient_TLSFailed)
  {
    request_ok = 0;
    http_error = DOH_ERROR_TLS;
  }
  EXCEPT (SocketHTTPClient_Timeout)
  {
    request_ok = 0;
    http_error = DOH_ERROR_TIMEOUT;
  }
  END_TRY;

  if (!request_ok)
    {
      *error_out = http_error;
      return -1;
    }

  return 0;
}

/**
 * Validate HTTP response and DNS message.
 *
 * @param response HTTP response structure.
 * @param expected_id Expected DNS query ID (for logging/debugging).
 * @param error_out Output error code on validation failure.
 * @return 0 on success, -1 on validation failure.
 */
static int
doh_validate_response (const SocketHTTPClient_Response *response,
                       uint16_t expected_id, int *error_out)
{
  assert (response);
  assert (error_out);
  (void)expected_id; /* Reserved for future logging */

  /* Check HTTP status */
  if (response->status_code != 200)
    {
      *error_out = DOH_ERROR_HTTP;
      return -1;
    }

  /* Verify Content-Type */
  const char *ct = SocketHTTP_Headers_get (response->headers, "Content-Type");
  if (!ct || strstr (ct, "application/dns-message") == NULL)
    {
      *error_out = DOH_ERROR_CONTENT_TYPE;
      return -1;
    }

  /* Check minimum response size */
  if (response->body_len < DNS_HEADER_SIZE)
    {
      *error_out = DOH_ERROR_INVALID;
      return -1;
    }

  /* SECURITY: Validate response size before allocation to prevent memory
   * exhaustion. DNS messages are limited to 65535 bytes. */
  if (response->body_len > DOH_MAX_MESSAGE_SIZE)
    {
      *error_out = DOH_ERROR_INVALID;
      return -1;
    }

  /* Parse DNS header to check RCODE */
  SocketDNS_Header hdr;
  if (SocketDNS_header_decode (response->body, response->body_len, &hdr) != 0)
    {
      *error_out = DOH_ERROR_INVALID;
      return -1;
    }

  /* Map RCODE to error (success or DNS-level error) */
  *error_out = rcode_to_error (hdr.rcode);
  return 0;
}

SocketDNSoverHTTPS_Query_T
SocketDNSoverHTTPS_query (T transport, const unsigned char *query, size_t len,
                           SocketDNSoverHTTPS_Callback callback, void *userdata)
{
  assert (transport);
  assert (query);
  assert (len >= DNS_HEADER_SIZE);
  assert (callback);

  if (transport->server_count == 0)
    {
      callback (NULL, NULL, 0, DOH_ERROR_NO_SERVER, userdata);
      return NULL;
    }

  if (transport->pending_count >= DOH_MAX_PENDING_QUERIES)
    {
      callback (NULL, NULL, 0, DOH_ERROR_NETWORK, userdata);
      return NULL;
    }

  /* Allocate query structure */
  struct SocketDNSoverHTTPS_Query *q = ALLOC (transport->arena, sizeof (*q));
  memset (q, 0, sizeof (*q));

  q->id = extract_query_id (query, len);
  q->callback = callback;
  q->userdata = userdata;
  q->sent_time_ms = get_monotonic_ms ();
  q->cancelled = 0;
  q->completed = 0;
  q->error = DOH_ERROR_SUCCESS;

  /* Copy query for potential retransmission */
  q->query_copy = ALLOC (transport->arena, len);
  memcpy (q->query_copy, query, len);
  q->query_len = len;

  /* Get current server configuration */
  struct ServerConfig *server = &transport->servers[transport->current_server];

  /* Execute HTTP request */
  SocketHTTPClient_Response response = { 0 };
  int exec_error = DOH_ERROR_SUCCESS;

  if (doh_execute_request (transport, server, query, len, &response,
                           &exec_error)
      != 0)
    {
      callback ((SocketDNSoverHTTPS_Query_T)q, NULL, 0, exec_error, userdata);
      SocketHTTPClient_Response_free (&response);
      return NULL;
    }

  /* Validate response */
  int validate_error = DOH_ERROR_SUCCESS;

  if (doh_validate_response (&response, q->id, &validate_error) != 0)
    {
      callback ((SocketDNSoverHTTPS_Query_T)q, NULL, 0, validate_error,
                userdata);
      SocketHTTPClient_Response_free (&response);
      transport->stats.queries_sent++;
      transport->stats.queries_failed++;
      return NULL;
    }

  /* Copy validated response to query structure */
  q->response = ALLOC (transport->arena, response.body_len);
  memcpy (q->response, response.body, response.body_len);
  q->response_len = response.body_len;
  q->completed = 1;
  q->error = validate_error;

  /* Update stats */
  transport->stats.queries_sent++;
  transport->stats.bytes_sent += len;
  transport->stats.bytes_received += response.body_len;

  if (q->error == DOH_ERROR_SUCCESS)
    transport->stats.queries_completed++;
  else
    transport->stats.queries_failed++;

  /* Invoke callback immediately (synchronous operation) */
  callback ((SocketDNSoverHTTPS_Query_T)q, q->response, q->response_len,
            q->error, userdata);

  SocketHTTPClient_Response_free (&response);

  return (SocketDNSoverHTTPS_Query_T)q;
}

int
SocketDNSoverHTTPS_cancel (T transport, SocketDNSoverHTTPS_Query_T query)
{
  assert (transport);
  (void)transport;

  if (!query)
    return -1;

  struct SocketDNSoverHTTPS_Query *q = (struct SocketDNSoverHTTPS_Query *)query;

  /* For synchronous implementation, query is already completed by the time
   * we get the handle, so cancellation is not meaningful. Mark as cancelled
   * anyway for consistency. */
  q->cancelled = 1;
  return 0;
}

uint16_t
SocketDNSoverHTTPS_query_id (SocketDNSoverHTTPS_Query_T query)
{
  if (!query)
    return 0;

  struct SocketDNSoverHTTPS_Query *q = (struct SocketDNSoverHTTPS_Query *)query;
  return q->id;
}

int
SocketDNSoverHTTPS_process (T transport, int timeout_ms)
{
  assert (transport);
  (void)transport;
  (void)timeout_ms;

  /* For synchronous implementation, all queries are completed immediately
   * in SocketDNSoverHTTPS_query(). This function is a no-op but provided
   * for API compatibility with async patterns. */
  return 0;
}

int
SocketDNSoverHTTPS_pending_count (T transport)
{
  assert (transport);
  (void)transport;
  /* For synchronous implementation, there are never pending queries */
  return 0;
}

void
SocketDNSoverHTTPS_stats (T transport, SocketDNSoverHTTPS_Stats *stats)
{
  assert (transport);
  assert (stats);
  *stats = transport->stats;
}

const char *
SocketDNSoverHTTPS_strerror (int error)
{
  switch (error)
    {
    case DOH_ERROR_SUCCESS:
      return "Success";
    case DOH_ERROR_TIMEOUT:
      return "Query timeout";
    case DOH_ERROR_CANCELLED:
      return "Query cancelled";
    case DOH_ERROR_NETWORK:
      return "Network error";
    case DOH_ERROR_TLS:
      return "TLS error";
    case DOH_ERROR_HTTP:
      return "HTTP error";
    case DOH_ERROR_INVALID:
      return "Invalid response";
    case DOH_ERROR_NO_SERVER:
      return "No server configured";
    case DOH_ERROR_CONTENT_TYPE:
      return "Invalid Content-Type";
    case DOH_ERROR_FORMERR:
      return "Format error (FORMERR)";
    case DOH_ERROR_SERVFAIL:
      return "Server failure (SERVFAIL)";
    case DOH_ERROR_NXDOMAIN:
      return "Domain not found (NXDOMAIN)";
    case DOH_ERROR_REFUSED:
      return "Query refused (REFUSED)";
    default:
      return "Unknown error";
    }
}

#endif /* SOCKET_HAS_TLS */
