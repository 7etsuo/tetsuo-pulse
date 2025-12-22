/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_HTTP_INCLUDED
#define SOCKETSIMPLE_HTTP_INCLUDED

/**
 * @file SocketSimple-http.h
 * @brief Simple HTTP client operations.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Types
 *============================================================================*/

/**
 * @brief HTTP response structure.
 */
typedef struct {
    int status_code;      /**< HTTP status code (200, 404, etc.) */
    char *body;           /**< Response body (caller must free) */
    size_t body_len;      /**< Body length in bytes */
    char *content_type;   /**< Content-Type header (caller must free, may be NULL) */
    char *location;       /**< Location header for redirects (caller must free, may be NULL) */
} SocketSimple_HTTPResponse;

/**
 * @brief Opaque HTTP client handle for connection reuse.
 */
typedef struct SocketSimple_HTTP *SocketSimple_HTTP_T;

/**
 * @brief HTTP client options.
 */
typedef struct {
    int connect_timeout_ms;  /**< Connection timeout (0 = default 30s) */
    int request_timeout_ms;  /**< Request timeout (0 = default 60s) */
    int max_redirects;       /**< Max redirects to follow (0 = disabled, default 5) */
    int verify_ssl;          /**< Verify TLS certificates (default: 1) */
    const char *user_agent;  /**< Custom User-Agent (NULL = default) */
    const char *proxy_url;   /**< Proxy URL (NULL = no proxy) */
    const char *auth_user;   /**< Basic auth username (NULL = none) */
    const char *auth_pass;   /**< Basic auth password */
    const char *bearer_token;/**< Bearer token (NULL = none) */
} SocketSimple_HTTPOptions;

/**
 * @brief Initialize HTTP options to defaults.
 *
 * @param opts Options structure to initialize.
 */
extern void Socket_simple_http_options_init(SocketSimple_HTTPOptions *opts);

/*============================================================================
 * One-liner HTTP Functions
 *============================================================================*/

/**
 * @brief Perform HTTP GET request.
 *
 * Automatically handles http:// and https:// URLs.
 *
 * @param url Full URL (e.g., "https://api.example.com/data").
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 *
 * Example:
 * @code
 * SocketSimple_HTTPResponse resp;
 * if (Socket_simple_http_get("https://api.example.com/users", &resp) == 0) {
 *     printf("Status: %d\nBody: %.*s\n",
 *            resp.status_code, (int)resp.body_len, resp.body);
 *     Socket_simple_http_response_free(&resp);
 * } else {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 * }
 * @endcode
 */
extern int Socket_simple_http_get(const char *url,
                                   SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP GET with custom headers.
 *
 * @param url Full URL.
 * @param headers NULL-terminated array of headers (e.g., {"Accept: application/json", NULL}).
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_get_ex(const char *url,
                                      const char **headers,
                                      SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP POST request.
 *
 * @param url Full URL.
 * @param content_type Content-Type header value.
 * @param body Request body.
 * @param body_len Body length.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_post(const char *url,
                                    const char *content_type,
                                    const void *body,
                                    size_t body_len,
                                    SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP PUT request.
 *
 * @param url Full URL.
 * @param content_type Content-Type header value.
 * @param body Request body.
 * @param body_len Body length.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_put(const char *url,
                                   const char *content_type,
                                   const void *body,
                                   size_t body_len,
                                   SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP DELETE request.
 *
 * @param url Full URL.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_delete(const char *url,
                                      SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP HEAD request.
 *
 * @param url Full URL.
 * @param response Output response structure (body will be empty).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_head(const char *url,
                                    SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP PATCH request.
 *
 * @param url Full URL.
 * @param content_type Content-Type header value.
 * @param body Request body.
 * @param body_len Body length.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_patch(const char *url,
                                     const char *content_type,
                                     const void *body,
                                     size_t body_len,
                                     SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP OPTIONS request.
 *
 * @param url Full URL.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_options(const char *url,
                                       SocketSimple_HTTPResponse *response);

/*============================================================================
 * Extended Functions with Custom Headers
 *============================================================================*/

/**
 * @brief Perform HTTP POST with custom headers.
 *
 * @param url Full URL.
 * @param headers NULL-terminated array of headers (e.g., {"X-Custom: value", NULL}).
 * @param content_type Content-Type header value (NULL for default).
 * @param body Request body.
 * @param body_len Body length.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_post_ex(const char *url,
                                       const char **headers,
                                       const char *content_type,
                                       const void *body,
                                       size_t body_len,
                                       SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP PUT with custom headers.
 *
 * @param url Full URL.
 * @param headers NULL-terminated array of headers.
 * @param content_type Content-Type header value (NULL for default).
 * @param body Request body.
 * @param body_len Body length.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_put_ex(const char *url,
                                      const char **headers,
                                      const char *content_type,
                                      const void *body,
                                      size_t body_len,
                                      SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP DELETE with custom headers.
 *
 * @param url Full URL.
 * @param headers NULL-terminated array of headers.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_delete_ex(const char *url,
                                         const char **headers,
                                         SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP HEAD with custom headers.
 *
 * @param url Full URL.
 * @param headers NULL-terminated array of headers.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_head_ex(const char *url,
                                       const char **headers,
                                       SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP PATCH with custom headers.
 *
 * @param url Full URL.
 * @param headers NULL-terminated array of headers.
 * @param content_type Content-Type header value (NULL for default).
 * @param body Request body.
 * @param body_len Body length.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_patch_ex(const char *url,
                                        const char **headers,
                                        const char *content_type,
                                        const void *body,
                                        size_t body_len,
                                        SocketSimple_HTTPResponse *response);

/**
 * @brief Perform HTTP OPTIONS with custom headers.
 *
 * @param url Full URL.
 * @param headers NULL-terminated array of headers.
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_http_options_ex(const char *url,
                                          const char **headers,
                                          SocketSimple_HTTPResponse *response);

/*============================================================================
 * Generic Request Function
 *============================================================================*/

/**
 * @brief HTTP method types for generic request.
 */
typedef enum {
    SIMPLE_HTTP_GET,
    SIMPLE_HTTP_POST,
    SIMPLE_HTTP_PUT,
    SIMPLE_HTTP_DELETE,
    SIMPLE_HTTP_HEAD,
    SIMPLE_HTTP_PATCH,
    SIMPLE_HTTP_OPTIONS
} SocketSimple_HTTPMethod;

/**
 * @brief Perform generic HTTP request with all options.
 *
 * This is the most flexible function, allowing any combination of
 * method, headers, body, and client options.
 *
 * @param method HTTP method.
 * @param url Full URL.
 * @param headers NULL-terminated array of headers (NULL for none).
 * @param body Request body (NULL for none).
 * @param body_len Body length.
 * @param opts Client options (NULL for defaults).
 * @param response Output response structure.
 * @return 0 on success, -1 on error.
 *
 * Example:
 * @code
 * SocketSimple_HTTPOptions opts;
 * Socket_simple_http_options_init(&opts);
 * opts.connect_timeout_ms = 5000;
 * opts.auth_user = "user";
 * opts.auth_pass = "pass";
 *
 * const char *headers[] = {"X-Custom: value", "Accept: application/json", NULL};
 * SocketSimple_HTTPResponse resp;
 *
 * if (Socket_simple_http_request(SIMPLE_HTTP_POST, "https://api.example.com/data",
 *                                 headers, "{\"key\":\"value\"}", 15, &opts, &resp) == 0) {
 *     printf("Status: %d\n", resp.status_code);
 *     Socket_simple_http_response_free(&resp);
 * }
 * @endcode
 */
extern int Socket_simple_http_request(SocketSimple_HTTPMethod method,
                                       const char *url,
                                       const char **headers,
                                       const void *body,
                                       size_t body_len,
                                       const SocketSimple_HTTPOptions *opts,
                                       SocketSimple_HTTPResponse *response);

/*============================================================================
 * JSON Convenience Functions
 *============================================================================*/

/**
 * @brief HTTP GET with JSON response.
 *
 * Automatically sets Accept: application/json header.
 *
 * @param url Full URL.
 * @param json_out Output: JSON string (caller must free).
 * @param json_len Output: JSON length.
 * @return HTTP status code (>0), or -1 on error.
 *
 * Example:
 * @code
 * char *json;
 * size_t len;
 * int status = Socket_simple_http_get_json("https://api.example.com/users", &json, &len);
 * if (status == 200) {
 *     printf("JSON: %s\n", json);
 *     free(json);
 * }
 * @endcode
 */
extern int Socket_simple_http_get_json(const char *url,
                                        char **json_out,
                                        size_t *json_len);

/**
 * @brief HTTP POST with JSON body and JSON response.
 *
 * Automatically sets Content-Type: application/json.
 *
 * @param url Full URL.
 * @param json_body JSON string to send.
 * @param json_out Output: JSON response (caller must free).
 * @param json_len Output: response length.
 * @return HTTP status code (>0), or -1 on error.
 */
extern int Socket_simple_http_post_json(const char *url,
                                         const char *json_body,
                                         char **json_out,
                                         size_t *json_len);

/**
 * @brief HTTP PUT with JSON body and JSON response.
 */
extern int Socket_simple_http_put_json(const char *url,
                                        const char *json_body,
                                        char **json_out,
                                        size_t *json_len);

/*============================================================================
 * File Operations
 *============================================================================*/

/**
 * @brief Download file from URL.
 *
 * @param url Source URL.
 * @param filepath Destination file path.
 * @return 0 on success, -1 on HTTP error, -2 on file error.
 */
extern int Socket_simple_http_download(const char *url, const char *filepath);

/**
 * @brief Upload file to URL (PUT).
 *
 * @param url Destination URL.
 * @param filepath Source file path.
 * @param content_type MIME type (NULL for application/octet-stream).
 * @return HTTP status code (>0), -1 on HTTP error, -2 on file error.
 */
extern int Socket_simple_http_upload(const char *url,
                                      const char *filepath,
                                      const char *content_type);

/*============================================================================
 * HTTP Client Handle (Connection Reuse)
 *============================================================================*/

/**
 * @brief Create reusable HTTP client.
 *
 * Maintains connection pool for better performance with multiple requests.
 *
 * @return Client handle, or NULL on error.
 */
extern SocketSimple_HTTP_T Socket_simple_http_new(void);

/**
 * @brief Create HTTP client with options.
 *
 * @param opts Client options (NULL for defaults).
 * @return Client handle, or NULL on error.
 */
extern SocketSimple_HTTP_T Socket_simple_http_new_ex(
    const SocketSimple_HTTPOptions *opts);

/**
 * @brief Perform GET using client handle.
 */
extern int Socket_simple_http_client_get(SocketSimple_HTTP_T client,
                                          const char *url,
                                          SocketSimple_HTTPResponse *response);

/**
 * @brief Perform POST using client handle.
 */
extern int Socket_simple_http_client_post(SocketSimple_HTTP_T client,
                                           const char *url,
                                           const char *content_type,
                                           const void *body,
                                           size_t body_len,
                                           SocketSimple_HTTPResponse *response);

/**
 * @brief Free HTTP client.
 *
 * @param client Pointer to client handle.
 */
extern void Socket_simple_http_free(SocketSimple_HTTP_T *client);

/*============================================================================
 * Cleanup
 *============================================================================*/

/**
 * @brief Free HTTP response resources.
 *
 * @param response Response structure to free.
 */
extern void Socket_simple_http_response_free(SocketSimple_HTTPResponse *response);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_HTTP_INCLUDED */
