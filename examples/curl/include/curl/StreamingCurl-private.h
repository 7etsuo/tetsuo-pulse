/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl-private.h
 * @brief Internal structures for streaming curl module.
 *
 * This file is not part of the public API. Do not include directly.
 */

#ifndef STREAMINGCURL_PRIVATE_INCLUDED
#define STREAMINGCURL_PRIVATE_INCLUDED

#include "curl/StreamingCurl.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

/* Forward declarations */
struct SocketProxy_Config;
struct SocketHTTP2_Conn;
struct SocketHTTP2_Stream;
struct SocketHTTP1_Parser;

/* Optional TLS support */
#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#endif

/* Buffer size constants */
#define CURL_MAX_FILENAME_LEN 256
#define CURL_MAX_COOKIE_NAME_LEN 256
#define CURL_MAX_DOMAIN_LEN 256
#define CURL_MAX_REALM_LEN 256
#define CURL_MAX_NONCE_LEN 256
#define CURL_MAX_OPAQUE_LEN 256
#define CURL_MAX_PATH_LEN 1024
#define CURL_MAX_COOKIE_VALUE_LEN 4096
#define CURL_MAX_COOKIE_LINE_LEN 4096
#define CURL_MAX_CREDENTIAL_LEN 512
#define CURL_MAX_AUTH_BUFFER_LEN 1024
#define CURL_MAX_QOP_LEN 64
#define CURL_MAX_URL_BUFFER_LEN 8192
#define CURL_REQUEST_BUFFER_SIZE 8192
#define CURL_CHUNK_BUFFER_SIZE 16384

/* HTTP/1.1 buffer sizes */
#define CURL_H1_RECV_BUFFER_SIZE 16384
#define CURL_H1_BODY_BUFFER_SIZE 16384

/* HTTP/2 buffer sizes */
#define CURL_H2_DATA_BUFFER_SIZE 16384
#define CURL_H2_DECOMP_BUFFER_SIZE 32768
#define CURL_H2_MAX_HEADERS 128

/* Decompression buffer size */
#define CURL_DECOMP_BUFFER_SIZE 32768

/* Header count limits */
#define CURL_MAX_HEADER_COUNT_SMALL 64

/* HTTP default ports */
#define CURL_HTTP_DEFAULT_PORT 80
#define CURL_HTTPS_DEFAULT_PORT 443

/* HTTP status codes - no body responses */
#define CURL_HTTP_STATUS_NO_CONTENT 204
#define CURL_HTTP_STATUS_NOT_MODIFIED 304

/* HTTP status codes - informational range */
#define CURL_HTTP_STATUS_INFORMATIONAL_MIN 100
#define CURL_HTTP_STATUS_INFORMATIONAL_MAX 200

/* HTTP status codes - redirects */
#define CURL_HTTP_STATUS_MOVED_PERMANENTLY 301
#define CURL_HTTP_STATUS_FOUND 302
#define CURL_HTTP_STATUS_SEE_OTHER 303
#define CURL_HTTP_STATUS_TEMPORARY_REDIRECT 307
#define CURL_HTTP_STATUS_PERMANENT_REDIRECT 308

/* HTTP status codes - client error boundary */
#define CURL_HTTP_STATUS_CLIENT_ERROR_MIN 400

/* Default configuration values */
#define CURL_DEFAULT_CONNECT_TIMEOUT_MS 30000
#define CURL_DEFAULT_DNS_TIMEOUT_MS 5000
#define CURL_DEFAULT_REQUEST_TIMEOUT_MS 0 /* No limit */
#define CURL_DEFAULT_MAX_REDIRECTS 50
#define CURL_DEFAULT_MAX_RETRIES 3

/* Numeric parsing */
#define CURL_DECIMAL_BASE 10

/**
 * @brief Internal connection state.
 */
typedef struct CurlConnection
{
  Socket_T socket;                 /**< Underlying socket */
  SocketBuf_T buffer;              /**< Buffered I/O wrapper */
  int is_tls;                      /**< TLS connection flag */
  SocketHTTP_Version http_version; /**< Negotiated HTTP version */

#if SOCKET_HAS_TLS
  SocketTLSContext_T tls_context; /**< TLS context (owned if auto-created) */
  int owns_tls_context;           /**< 1 if we created the context */
#endif

  /* HTTP/2 state (if applicable) */
  struct SocketHTTP2_Conn *h2_conn;     /**< HTTP/2 connection */
  struct SocketHTTP2_Stream *h2_stream; /**< Current HTTP/2 stream */

  /* HTTP/1.1 state */
  struct SocketHTTP1_Parser *h1_parser; /**< HTTP/1.1 response parser */

  /* Connection tracking */
  char *host;    /**< Connected host (for reuse) */
  int port;      /**< Connected port */
  int reusable;  /**< Can be reused for next request */
  int connected; /**< Connection is established */
} CurlConnection;

/**
 * @brief Cookie entry.
 */
typedef struct CurlCookie
{
  char *domain;            /**< Cookie domain */
  char *path;              /**< Cookie path */
  char *name;              /**< Cookie name */
  char *value;             /**< Cookie value */
  time_t expires;          /**< Expiration time (0 = session) */
  int secure;              /**< Secure flag */
  int http_only;           /**< HttpOnly flag */
  struct CurlCookie *next; /**< Next cookie in list */
} CurlCookie;

/**
 * @brief Cookie jar.
 */
typedef struct CurlCookieJar
{
  CurlCookie *cookies; /**< Linked list of cookies */
  char *filename;      /**< Persistence file */
  int dirty;           /**< Needs saving */
  Arena_T arena;       /**< Memory arena */
} CurlCookieJar;

/**
 * @brief Custom headers list.
 */
typedef struct CurlCustomHeader
{
  char *name;                    /**< Header name */
  char *value;                   /**< Header value */
  struct CurlCustomHeader *next; /**< Next header */
} CurlCustomHeader;

/**
 * @brief Internal session structure.
 */
struct CurlSession
{
  /* Configuration (copied from options) */
  CurlOptions options;

  /* Memory management */
  Arena_T arena;         /**< Session arena */
  Arena_T request_arena; /**< Per-request arena (reset each request) */

  /* State machine */
  CurlState state;
  CurlError last_error;

  /* Current request */
  CurlParsedURL current_url;            /**< Parsed URL of current request */
  SocketHTTP_Method request_method;     /**< Current request method */
  SocketHTTP_Headers_T request_headers; /**< Current request headers */

  /* Response */
  CurlResponse response;

  /* Connection (may be reused) */
  CurlConnection *conn;

  /* Custom headers (persist across requests) */
  CurlCustomHeader *custom_headers;

  /* Cookie handling */
  CurlCookieJar *cookie_jar;

  /* Authentication state */
  CurlAuth auth;
  char *auth_header; /**< Pre-computed auth header */

  /* Transfer state */
  int64_t upload_total;      /**< Total bytes to upload */
  int64_t upload_sent;       /**< Bytes uploaded so far */
  int64_t download_total;    /**< Total bytes to download */
  int64_t download_received; /**< Bytes downloaded so far */

  /* Retry state */
  int retry_count; /**< Current retry attempt */
};

/**
 * @brief Duplicate a string into an arena.
 *
 * Common utility used throughout the curl module.
 *
 * @param arena Memory arena
 * @param str String to duplicate
 * @param len String length
 * @return Duplicated string, or NULL if str is NULL or len is 0
 */
extern char *curl_arena_strdup (Arena_T arena, const char *str, size_t len);

/**
 * @brief Wait for socket to become readable with timeout.
 *
 * Uses poll() to wait for data to be available on the socket.
 *
 * @param conn Connection
 * @param timeout_ms Timeout in milliseconds (0 = no timeout, -1 = block)
 * @return 1 if readable, 0 on timeout, -1 on error
 */
extern int curl_wait_readable (CurlConnection *conn, int timeout_ms);

/**
 * @brief Internal URL parsing helper.
 *
 * Wraps SocketHTTP_URI_parse() with curl-specific validation.
 *
 * @param url URL string
 * @param len Length (0 for strlen)
 * @param result Output structure
 * @param arena Memory arena
 * @return CURL_OK or CURL_ERROR_INVALID_URL
 */
extern CurlError curl_internal_parse_url (const char *url,
                                          size_t len,
                                          CurlParsedURL *result,
                                          Arena_T arena);

/**
 * @brief Check if two URLs have the same origin.
 *
 * Same origin means same scheme, host, and port.
 *
 * @param a First parsed URL
 * @param b Second parsed URL
 * @return 1 if same origin, 0 otherwise
 */
extern int
curl_urls_same_origin (const CurlParsedURL *a, const CurlParsedURL *b);

/**
 * @brief Copy a parsed URL.
 *
 * @param dst Destination
 * @param src Source
 * @param arena Arena for string allocations
 */
extern void
curl_url_copy (CurlParsedURL *dst, const CurlParsedURL *src, Arena_T arena);


/**
 * @brief Establish a connection to a URL target.
 *
 * Uses Happy Eyeballs for direct connections, or proxy tunneling if
 * configured. For HTTPS URLs, performs TLS handshake with ALPN.
 *
 * @param url Parsed target URL
 * @param options Connection options
 * @param arena Memory arena for allocations
 * @return New connection, or NULL on failure (sets Curl exception)
 * @throws Curl_DNSFailed on DNS resolution failure
 * @throws Curl_ConnectFailed on connection failure
 * @throws Curl_TLSFailed on TLS handshake failure
 * @throws Curl_Timeout on connection timeout
 */
extern CurlConnection *curl_connect (const CurlParsedURL *url,
                                     const CurlOptions *options,
                                     Arena_T arena);

/**
 * @brief Close a connection and release resources.
 *
 * @param conn Connection to close (may be NULL)
 */
extern void curl_connection_close (CurlConnection *conn);

/**
 * @brief Check if a connection can be reused for a URL.
 *
 * Checks if the connection is still open and matches the URL's
 * host, port, and TLS requirements.
 *
 * @param conn Existing connection (may be NULL)
 * @param url Target URL
 * @return 1 if reusable, 0 otherwise
 */
extern int
curl_connection_reusable (const CurlConnection *conn, const CurlParsedURL *url);

/**
 * @brief Get the negotiated ALPN protocol.
 *
 * @param conn Connection
 * @return Protocol string ("h2", "http/1.1") or NULL if not TLS
 */
extern const char *curl_connection_alpn (const CurlConnection *conn);

/**
 * @brief Check if connection uses HTTP/2.
 *
 * @param conn Connection
 * @return 1 if HTTP/2, 0 otherwise
 */
extern int curl_connection_is_http2 (const CurlConnection *conn);


/**
 * @brief Build HTTP/1.1 request headers.
 *
 * @param session Session with request info
 * @param method HTTP method
 * @param body Request body (may be NULL)
 * @param body_len Body length
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t curl_build_http1_request (CurlSession_T session,
                                         SocketHTTP_Method method,
                                         const void *body,
                                         size_t body_len,
                                         char *output,
                                         size_t output_size);

/**
 * @brief Send HTTP/1.1 request with optional body.
 *
 * @param session Session
 * @param method HTTP method
 * @param body Static body (NULL for streaming)
 * @param body_len Body length
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_send_http1_request (CurlSession_T session,
                                          SocketHTTP_Method method,
                                          const void *body,
                                          size_t body_len);

/**
 * @brief Send chunked body using read callback.
 *
 * @param session Session with read callback
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_send_chunked_body (CurlSession_T session);

/**
 * @brief Send HTTP/2 request with optional body.
 *
 * @param session Session
 * @param method HTTP method
 * @param body Static body (NULL for streaming)
 * @param body_len Body length
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_send_http2_request (CurlSession_T session,
                                          SocketHTTP_Method method,
                                          const void *body,
                                          size_t body_len);

/**
 * @brief Send DATA frame(s) for HTTP/2.
 *
 * @param session Session
 * @param data Data to send
 * @param len Data length
 * @param end_stream End stream flag
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_send_h2_data (CurlSession_T session,
                                    const void *data,
                                    size_t len,
                                    int end_stream);

/**
 * @brief Send streaming body for HTTP/2 using read callback.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_send_h2_streaming_body (CurlSession_T session);

/**
 * @brief Send request using appropriate protocol.
 *
 * Automatically selects HTTP/1.1 or HTTP/2 based on connection.
 *
 * @param session Session
 * @param method HTTP method
 * @param body Request body (NULL for none)
 * @param body_len Body length
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_send_request (CurlSession_T session,
                                    SocketHTTP_Method method,
                                    const void *body,
                                    size_t body_len);

/**
 * @brief Build request headers for a session.
 *
 * @param session Session
 * @param method HTTP method
 * @param content_type Content-Type for body (may be NULL)
 * @param body_len Body length (0 for none or streaming)
 * @return 0 on success, -1 on error
 */
extern int curl_build_request_headers (CurlSession_T session,
                                       SocketHTTP_Method method,
                                       const char *content_type,
                                       size_t body_len);


/**
 * @brief Build Basic authentication header value.
 *
 * @param username Username
 * @param password Password
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Header value length, or -1 on error
 */
extern ssize_t curl_auth_basic (const char *username,
                                const char *password,
                                char *output,
                                size_t output_size);

/**
 * @brief Build Bearer token authentication header value.
 *
 * @param token Bearer token
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Header value length, or -1 on error
 */
extern ssize_t
curl_auth_bearer (const char *token, char *output, size_t output_size);

/**
 * @brief Parse WWW-Authenticate header for Digest parameters.
 *
 * @param header WWW-Authenticate header value
 * @param realm Output realm
 * @param realm_size Realm buffer size
 * @param nonce Output nonce
 * @param nonce_size Nonce buffer size
 * @param opaque Output opaque (may be NULL)
 * @param opaque_size Opaque buffer size
 * @param qop Output qop (may be NULL)
 * @param qop_size Qop buffer size
 * @return 0 on success, -1 on error
 */
extern int curl_auth_parse_digest_challenge (const char *header,
                                             char *realm,
                                             size_t realm_size,
                                             char *nonce,
                                             size_t nonce_size,
                                             char *opaque,
                                             size_t opaque_size,
                                             char *qop,
                                             size_t qop_size);

/**
 * @brief Digest authentication parameters.
 *
 * Groups all parameters needed for RFC 7616 Digest authentication.
 */
typedef struct CurlDigestParams
{
  /* Credentials */
  const char *username; /**< Username */
  const char *password; /**< Password */

  /* Challenge parameters */
  const char *realm;  /**< Realm from server challenge */
  const char *nonce;  /**< Nonce from server challenge */
  const char *opaque; /**< Opaque from challenge (may be NULL) */
  const char *qop;    /**< Quality of Protection (may be NULL) */

  /* Request parameters */
  const char *uri;    /**< Request URI */
  const char *method; /**< HTTP method */

  /* Client parameters */
  const char *nc;     /**< Nonce count (hex string) */
  const char *cnonce; /**< Client nonce */

  /* Output buffer */
  char *output;       /**< Output buffer */
  size_t output_size; /**< Output buffer size */
} CurlDigestParams;

/**
 * @brief Build Digest authentication header value.
 *
 * @param params Digest authentication parameters
 * @return Header value length, or -1 on error
 */
extern ssize_t curl_auth_digest (const CurlDigestParams *params);

/**
 * @brief Set up authentication header for session.
 *
 * @param session Session
 * @return 0 on success, -1 on error
 */
extern int curl_auth_setup (CurlSession_T session);

/**
 * @brief Handle 401 Unauthorized response for Digest auth.
 *
 * @param session Session
 * @param www_auth WWW-Authenticate header value
 * @param method HTTP method
 * @param uri Request URI
 * @return 0 on success, -1 on error
 */
extern int curl_auth_handle_challenge (CurlSession_T session,
                                       const char *www_auth,
                                       const char *method,
                                       const char *uri);


/**
 * @brief Receive and parse HTTP/1.1 response headers.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_receive_h1_headers (CurlSession_T session);

/**
 * @brief Stream HTTP/1.1 response body through callback.
 *
 * Handles Content-Length and chunked transfer encoding transparently.
 * Invokes write callback with body data without buffering.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_receive_h1_body (CurlSession_T session);

/**
 * @brief Receive complete HTTP/1.1 response (headers + body).
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_receive_h1_response (CurlSession_T session);

/**
 * @brief Check if HTTP/1.1 connection should be kept alive.
 *
 * @param session Session after response
 * @return 1 if keep-alive, 0 otherwise
 */
extern int curl_h1_should_keepalive (CurlSession_T session);

/**
 * @brief Get trailer headers (for chunked responses).
 *
 * @param session Session after body complete
 * @return Trailer headers or NULL
 */
extern SocketHTTP_Headers_T curl_h1_get_trailers (CurlSession_T session);


/**
 * @brief Receive and parse HTTP/2 response headers.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_receive_h2_headers (CurlSession_T session);

/**
 * @brief Stream HTTP/2 response body through callback.
 *
 * Handles DATA frames with flow control (WINDOW_UPDATE).
 * Invokes write callback with body data without buffering.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_receive_h2_body (CurlSession_T session);

/**
 * @brief Receive complete HTTP/2 response (headers + body).
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_receive_h2_response (CurlSession_T session);

/**
 * @brief Get HTTP/2 stream state.
 *
 * @param session Session
 * @return Stream state, or -1 on error
 */
extern int curl_h2_stream_state (CurlSession_T session);

/**
 * @brief Close HTTP/2 stream.
 *
 * @param session Session
 * @param error_code HTTP/2 error code (0 for no error)
 */
extern void curl_h2_stream_close (CurlSession_T session, int error_code);

/**
 * @brief Get current send window for HTTP/2 stream.
 *
 * @param session Session
 * @return Send window size, or 0 on error
 */
extern int32_t curl_h2_send_window (CurlSession_T session);

/**
 * @brief Get current receive window for HTTP/2 stream.
 *
 * @param session Session
 * @return Receive window size, or 0 on error
 */
extern int32_t curl_h2_recv_window (CurlSession_T session);


/**
 * @brief Decompression context for streaming decompression.
 */
typedef struct CurlDecompressor CurlDecompressor;

/**
 * @brief Create a new decompressor.
 *
 * @param encoding Content-Encoding header value
 * @param arena Memory arena
 * @return New decompressor, or NULL on error
 */
extern CurlDecompressor *
curl_decompressor_new (const char *encoding, Arena_T arena);

/**
 * @brief Decompress data.
 *
 * @param decomp Decompressor
 * @param input Compressed input
 * @param input_len Input length
 * @param output Output buffer
 * @param output_len Output buffer size
 * @param bytes_written Output bytes written
 * @return 0 on success, -1 on error
 */
extern int curl_decompressor_decompress (CurlDecompressor *decomp,
                                         const unsigned char *input,
                                         size_t input_len,
                                         unsigned char *output,
                                         size_t output_len,
                                         size_t *bytes_written);

/**
 * @brief Finish decompression and get remaining data.
 *
 * @param decomp Decompressor
 * @param output Output buffer
 * @param output_len Output buffer size
 * @param bytes_written Output bytes written
 * @return 0 on success, -1 on error
 */
extern int curl_decompressor_finish (CurlDecompressor *decomp,
                                     unsigned char *output,
                                     size_t output_len,
                                     size_t *bytes_written);

/**
 * @brief Free decompressor resources.
 *
 * @param decomp Pointer to decompressor (set to NULL)
 */
extern void curl_decompressor_free (CurlDecompressor **decomp);

/**
 * @brief Check if decompressor is for identity encoding.
 *
 * @param decomp Decompressor
 * @return 1 if identity, 0 otherwise
 */
extern int curl_decompressor_is_identity (CurlDecompressor *decomp);

/**
 * @brief Get coding type name.
 *
 * @param decomp Decompressor
 * @return Static string name
 */
extern const char *curl_decompressor_coding_name (CurlDecompressor *decomp);

/**
 * @brief Create decompressor for session based on Content-Encoding.
 *
 * @param session Session
 * @return New decompressor, or NULL if not needed/error
 */
extern CurlDecompressor *
curl_session_create_decompressor (CurlSession_T session);

/**
 * @brief Decompress body data with session's decompressor.
 *
 * @param session Session
 * @param decomp Decompressor (may be NULL)
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer
 * @param output_len Output buffer size
 * @param bytes_written Bytes written to output
 * @return 0 on success, -1 on error
 */
extern int curl_session_decompress (CurlSession_T session,
                                    CurlDecompressor *decomp,
                                    const unsigned char *input,
                                    size_t input_len,
                                    unsigned char *output,
                                    size_t output_len,
                                    size_t *bytes_written);

/**
 * @brief Check if Content-Encoding indicates compression.
 *
 * @param headers Response headers
 * @return 1 if compressed, 0 otherwise
 */
extern int curl_is_content_compressed (SocketHTTP_Headers_T headers);

/**
 * @brief Parse Content-Encoding to coding type.
 *
 * @param encoding Content-Encoding header value
 * @return Coding type
 */
extern SocketHTTP_Coding curl_parse_content_encoding (const char *encoding);


/**
 * @brief Check if current response is a redirect.
 *
 * @param session Session
 * @return 1 if redirect (301/302/303/307/308), 0 otherwise
 */
extern int curl_is_redirect (CurlSession_T session);

/**
 * @brief Get redirect status code.
 *
 * @param session Session
 * @return Status code or 0 if not a redirect
 */
extern int curl_redirect_status (CurlSession_T session);

/**
 * @brief Get Location header from redirect response.
 *
 * @param session Session
 * @return Location URL or NULL
 */
extern const char *curl_redirect_location (CurlSession_T session);

/**
 * @brief Check if redirect changes the HTTP method.
 *
 * 303 always changes to GET. 301/302 with POST changes to GET.
 * 307/308 preserve the original method.
 *
 * @param session Session
 * @return 1 if method changes to GET, 0 otherwise
 */
extern int curl_redirect_changes_method (CurlSession_T session);

/**
 * @brief Get the HTTP method for redirect request.
 *
 * @param session Session
 * @return Method to use for redirect
 */
extern SocketHTTP_Method curl_redirect_method (CurlSession_T session);

/**
 * @brief Check if redirect preserves request body.
 *
 * Only 307 and 308 preserve the body.
 *
 * @param session Session
 * @return 1 if body should be preserved, 0 otherwise
 */
extern int curl_redirect_preserves_body (CurlSession_T session);

/**
 * @brief Check if redirect is to a different origin.
 *
 * @param session Session
 * @param location Location URL
 * @return 1 if cross-origin, 0 if same origin
 */
extern int
curl_redirect_is_cross_origin (CurlSession_T session, const char *location);

/**
 * @brief Resolve redirect URL relative to current URL.
 *
 * @param session Session
 * @param location Location header value
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t curl_resolve_redirect_url (CurlSession_T session,
                                          const char *location,
                                          char *output,
                                          size_t output_size);

/**
 * @brief Parse redirect URL into CurlParsedURL.
 *
 * @param session Session
 * @param location Location header value
 * @param result Output parsed URL
 * @return 0 on success, -1 on error
 */
extern int curl_parse_redirect_url (CurlSession_T session,
                                    const char *location,
                                    CurlParsedURL *result);

/**
 * @brief Check if redirect should be followed.
 *
 * Considers: follow_redirects option, max_redirects limit, Location header.
 *
 * @param session Session
 * @return 1 if should follow, 0 otherwise
 */
extern int curl_should_follow_redirect (CurlSession_T session);

/**
 * @brief Prepare session for redirect.
 *
 * Updates current_url, request_method, redirect_count.
 * Closes connection if cross-origin.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_prepare_redirect (CurlSession_T session);

/**
 * @brief Handle redirect response.
 *
 * If redirect should be followed, prepares session for next request.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
extern CurlError curl_handle_redirect (CurlSession_T session);

/**
 * @brief Get current redirect count.
 *
 * @param session Session
 * @return Number of redirects followed
 */
extern int curl_get_redirect_count (CurlSession_T session);

/**
 * @brief Check if redirect is a security downgrade (HTTPS to HTTP).
 *
 * @param session Session
 * @param location Location URL
 * @return 1 if downgrade, 0 otherwise
 */
extern int
curl_redirect_is_secure_downgrade (CurlSession_T session, const char *location);

/**
 * @brief Check if redirect is to the same host.
 *
 * @param session Session
 * @param location Location URL
 * @return 1 if same host, 0 otherwise
 */
extern int
curl_redirect_is_same_host (CurlSession_T session, const char *location);

/**
 * @brief Reset redirect count.
 *
 * @param session Session
 */
extern void curl_reset_redirect_count (CurlSession_T session);


/**
 * @brief Create a new cookie jar.
 *
 * @param arena Memory arena
 * @return New cookie jar, or NULL on error
 */
extern CurlCookieJar *curl_cookiejar_new (Arena_T arena);

/**
 * @brief Free cookie jar.
 *
 * @param jar Pointer to cookie jar (set to NULL)
 */
extern void curl_cookiejar_free (CurlCookieJar **jar);

/**
 * @brief Parse a Set-Cookie header value.
 *
 * @param set_cookie Set-Cookie header value
 * @param request_host Request host (for default domain)
 * @param request_path Request path (for default path)
 * @param request_secure 1 if HTTPS, 0 if HTTP
 * @param arena Memory arena
 * @return Parsed cookie, or NULL on error
 */
extern CurlCookie *curl_cookie_parse (const char *set_cookie,
                                      const char *request_host,
                                      const char *request_path,
                                      int request_secure,
                                      Arena_T arena);

/**
 * @brief Check if cookie domain matches request host.
 *
 * @param cookie_domain Cookie domain
 * @param request_host Request host
 * @return 1 if matches, 0 otherwise
 */
extern int
curl_cookie_domain_match (const char *cookie_domain, const char *request_host);

/**
 * @brief Check if cookie path matches request path.
 *
 * @param cookie_path Cookie path
 * @param request_path Request path
 * @return 1 if matches, 0 otherwise
 */
extern int
curl_cookie_path_match (const char *cookie_path, const char *request_path);

/**
 * @brief Check if cookie matches request.
 *
 * Checks domain, path, secure flag, and expiration.
 *
 * @param cookie Cookie to check
 * @param host Request host
 * @param path Request path
 * @param is_secure 1 if HTTPS, 0 if HTTP
 * @return 1 if matches, 0 otherwise
 */
extern int curl_cookie_matches (const CurlCookie *cookie,
                                const char *host,
                                const char *path,
                                int is_secure);

/**
 * @brief Check if cookie has expired.
 *
 * @param cookie Cookie to check
 * @return 1 if expired, 0 otherwise
 */
extern int curl_cookie_is_expired (const CurlCookie *cookie);

/**
 * @brief Add cookie to jar.
 *
 * Replaces existing cookie with same name/domain/path.
 *
 * @param jar Cookie jar
 * @param cookie Cookie to add
 * @return 0 on success, -1 on error
 */
extern int curl_cookiejar_add (CurlCookieJar *jar, CurlCookie *cookie);

/**
 * @brief Remove cookie from jar.
 *
 * @param jar Cookie jar
 * @param name Cookie name
 * @param domain Cookie domain (NULL for any)
 * @param path Cookie path (NULL for any)
 * @return 1 if removed, 0 if not found, -1 on error
 */
extern int curl_cookiejar_remove (CurlCookieJar *jar,
                                  const char *name,
                                  const char *domain,
                                  const char *path);

/**
 * @brief Clear all cookies from jar.
 *
 * @param jar Cookie jar
 */
extern void curl_cookiejar_clear (CurlCookieJar *jar);

/**
 * @brief Clear expired cookies from jar.
 *
 * @param jar Cookie jar
 */
extern void curl_cookiejar_clear_expired (CurlCookieJar *jar);

/**
 * @brief Get number of cookies in jar.
 *
 * @param jar Cookie jar
 * @return Cookie count
 */
extern int curl_cookiejar_count (const CurlCookieJar *jar);

/**
 * @brief Build Cookie header value for request.
 *
 * @param jar Cookie jar
 * @param host Request host
 * @param path Request path
 * @param is_secure 1 if HTTPS, 0 if HTTP
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t curl_cookiejar_get_header (const CurlCookieJar *jar,
                                          const char *host,
                                          const char *path,
                                          int is_secure,
                                          char *output,
                                          size_t output_size);

/**
 * @brief Process Set-Cookie headers from response.
 *
 * @param jar Cookie jar
 * @param headers Response headers
 * @param host Request host
 * @param path Request path
 * @param is_secure 1 if HTTPS, 0 if HTTP
 * @param arena Memory arena for new cookies
 * @return Number of cookies processed
 */
extern int curl_cookiejar_process_response (CurlCookieJar *jar,
                                            SocketHTTP_Headers_T headers,
                                            const char *host,
                                            const char *path,
                                            int is_secure,
                                            Arena_T arena);

/**
 * @brief Load cookies from Netscape format file.
 *
 * @param jar Cookie jar
 * @param filename Cookie file path
 * @return Number of cookies loaded, or -1 on error
 */
extern int curl_cookiejar_load (CurlCookieJar *jar, const char *filename);

/**
 * @brief Save cookies to Netscape format file.
 *
 * @param jar Cookie jar
 * @param filename Cookie file path (NULL to use jar's filename)
 * @return 0 on success, -1 on error
 */
extern int curl_cookiejar_save (const CurlCookieJar *jar, const char *filename);

/**
 * @brief Add cookies to request headers.
 *
 * @param session Session
 * @return 1 if cookies added, 0 if no cookies
 */
extern int curl_session_add_cookies (CurlSession_T session);

/**
 * @brief Process cookies from response.
 *
 * @param session Session
 * @return Number of cookies processed
 */
extern int curl_session_process_cookies (CurlSession_T session);

/**
 * @brief Initialize cookie handling for session.
 *
 * @param session Session
 * @param cookie_file Cookie file path (NULL for no persistence)
 * @return 0 on success, -1 on error
 */
extern int
curl_session_init_cookies (CurlSession_T session, const char *cookie_file);

/**
 * @brief Save session cookies if dirty.
 *
 * @param session Session
 * @return 0 on success, -1 on error
 */
extern int curl_session_save_cookies (CurlSession_T session);

#endif /* STREAMINGCURL_PRIVATE_INCLUDED */
