/**
 * SocketTLSContext.c - TLS Context Management Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Manages creation, configuration, and lifecycle of OpenSSL SSL_CTX objects.
 * Encapsulates secure defaults (TLS1.3-only, PFS ciphers), cert loading,
 * verification modes, ALPN, and session caching. Uses Arena for internal allocations.
 * Provides opaque T interface with exception-based errors.
 *
 * Key integration:
 * - Automatic protocol/cipher hardening
 * - CA cert loading for verification
 * - ALPN wire-format construction from strings
 * - Session cache config for perf
 * - Detailed OpenSSL error formatting in exceptions
 *
 * Thread safety: Context modification not thread-safe. After setup, sharing
 * for SSL_new() is safe (OpenSSL CTX is ref-counted). Use mutex if modifying shared.
 * Per-connection SSL objects are independent.
 *
 * Error handling: Uses SocketTLS_Failed exception with context-specific details.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLSContext.h"
#include "tls/SocketTLSConfig.h"
#include <assert.h>
#include <string.h>
#include <errno.h>

/* Thread-local error buffer for detailed error messages
 * Prevents race conditions when multiple threads raise TLS context errors simultaneously */
#ifdef _WIN32
static __declspec(thread) char tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#else
static __thread char tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#endif

/* Thread-local exception for detailed TLS context error messages
 * Prevents race conditions when multiple threads raise same exception type. */
#ifdef _WIN32
static __declspec(thread) Except_T SocketTLSContext_DetailedException;
#else
static __thread Except_T SocketTLSContext_DetailedException;
#endif

/* Macro to raise TLS context exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason */
#define RAISE_TLS_CONTEXT_ERROR(exception)                                     \
    do                                                                        \
    {                                                                         \
        SocketTLSContext_DetailedException = (exception);                    \
        SocketTLSContext_DetailedException.reason = tls_context_error_buf;   \
        RAISE(SocketTLSContext_DetailedException);                            \
    }                                                                         \
    while (0)

#define T SocketTLSContext_T

struct T
{
    SSL_CTX *ssl_ctx;           /* OpenSSL context */
    Arena_T arena;              /* Arena for allocations */
    int is_server;              /* 1 for server, 0 for client */
    int session_cache_enabled;  /* Session cache flag */
    size_t session_cache_size;  /* Session cache size */
};

/* Helper function to format OpenSSL errors and raise TLS context exceptions */
static void
raise_tls_context_error(const char *context)
{
    unsigned long openssl_error = ERR_get_error();
    char openssl_error_buf[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];

    if (openssl_error != 0)
    {
        ERR_error_string_n(openssl_error, openssl_error_buf, sizeof(openssl_error_buf));
        snprintf(tls_context_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "%s: OpenSSL error: %s", context, openssl_error_buf);
    }
    else
    {
        snprintf(tls_context_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "%s: Unknown TLS error", context);
    }

    /* Use SocketTLS_Failed for general TLS context errors */
    RAISE_TLS_CONTEXT_ERROR(SocketTLS_Failed);
}

/**
 * alloc_and_init_ctx - Allocate and initialize common TLS context structure
 * @method: OpenSSL method (TLS_server_method() or TLS_client_method())
 * @is_server: Non-zero for server mode, zero for client
 *
 * Shared initialization logic for client and server contexts. Creates SSL_CTX,
 * configures secure TLS1.3-only settings and ciphersuites, allocates context
 * struct with calloc, creates arena, initializes fields.
 *
 * Returns: New T instance ready for further configuration
 * Raises: SocketTLS_Failed on any failure (OpenSSL config, memory)
 * Thread-safe: Yes - independent instances
 * 
 * Note: Caller must load certificates and set other options. Uses calloc for
 * ctx struct (freed separately); arena for internal buffers.
 */
static T
alloc_and_init_ctx(const SSL_METHOD *method, int is_server)
{
    T ctx;
    SSL_CTX *ssl_ctx;

    /* Create SSL_CTX with specified method */
    ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx)
    {
        raise_tls_context_error("Failed to create SSL_CTX");
    }

    /* Set protocol and cipher configs */
    if (SSL_CTX_set_min_proto_version(ssl_ctx, SOCKET_TLS_MIN_VERSION) != 1)
    {
        SSL_CTX_free(ssl_ctx);
        raise_tls_context_error("Failed to set TLS1.3 min version");
    }

    if (SSL_CTX_set_max_proto_version(ssl_ctx, SOCKET_TLS_MAX_VERSION) != 1)
    {
        SSL_CTX_free(ssl_ctx);
        raise_tls_context_error("Failed to enforce TLS1.3 max version");
    }

    if (SSL_CTX_set_ciphersuites(ssl_ctx, SOCKET_TLS13_CIPHERSUITES) != 1)
    {
        SSL_CTX_free(ssl_ctx);
        raise_tls_context_error("Failed to set secure ciphersuites");
    }

    /* Allocate and initialize context structure */
    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        SSL_CTX_free(ssl_ctx);
        raise_tls_context_error("ENOMEM: calloc for context struct");
    }

    /* Create arena */
    ctx->arena = Arena_new();
    if (!ctx->arena)
    {
        free(ctx);
        SSL_CTX_free(ssl_ctx);
        raise_tls_context_error("Failed to create context arena");
    }

    /* Initialize fields - transfer ownership of ssl_ctx */
    ctx->ssl_ctx = ssl_ctx;
    ctx->is_server = !!is_server;
    ctx->session_cache_enabled = 0;
    ctx->session_cache_size = SOCKET_TLS_SESSION_CACHE_SIZE;

    return ctx;
}

/**
 * SocketTLSContext_new_server - Create a new server TLS context
 * @cert_file: Server certificate file path (PEM format)
 * @key_file: Private key file path (PEM format)
 * @ca_file: CA certificate file path (optional, may be NULL)
 *
 * Creates a new SSL_CTX for server-side TLS operations. Loads the server
 * certificate and private key. Optionally loads CA certificates for client
 * certificate verification.
 *
 * Returns: New TLS context instance
 * Raises: SocketTLS_Failed on error (file not found, invalid cert/key, etc.)
 * Thread-safe: Yes (creates independent context)
 */
T
SocketTLSContext_new_server(const char *cert_file, const char *key_file, const char *ca_file)
{
    T ctx;

    assert(cert_file);
    assert(key_file);

    /* Allocate and initialize common context structure */
    ctx = alloc_and_init_ctx(TLS_server_method(), 1);

    /* Load server certificate and key */
    TRY
        SocketTLSContext_load_certificate(ctx, cert_file, key_file);
        if (ca_file)
        {
            SocketTLSContext_load_ca(ctx, ca_file);
        }
    EXCEPT(SocketTLS_Failed)
        SocketTLSContext_free(&ctx);
        RERAISE;
    END_TRY;

    return ctx;
}

/**
 * SocketTLSContext_new_client - Create a new client TLS context
 * @ca_file: CA certificate file path for server verification (optional, may be NULL)
 *
 * Creates a new SSL_CTX for client-side TLS operations. Optionally loads CA
 * certificates for server certificate verification.
 *
 * Returns: New TLS context instance
 * Raises: SocketTLS_Failed on error
 * Thread-safe: Yes (creates independent context)
 */
T
SocketTLSContext_new_client(const char *ca_file)
{
    T ctx;

    /* Allocate and initialize common context structure */
    ctx = alloc_and_init_ctx(TLS_client_method(), 0);

    /* Load CA certificates if provided */
    if (ca_file)
    {
        TRY
            SocketTLSContext_load_ca(ctx, ca_file);
            /* Enable verification by default when CA is provided */
            SocketTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);
        EXCEPT(SocketTLS_Failed)
            SocketTLSContext_free(&ctx);
            RERAISE;
        END_TRY;
    }

    return ctx;
}

/**
 * SocketTLSContext_load_certificate - Load server certificate and private key
 * @ctx: TLS context instance
 * @cert_file: Certificate file path (PEM format)
 * @key_file: Private key file path (PEM format)
 *
 * Loads a server certificate and its corresponding private key into the TLS context.
 * Both files must be in PEM format.
 *
 * Raises: SocketTLS_Failed on error (file not found, invalid format, key/cert mismatch)
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_load_certificate(T ctx, const char *cert_file, const char *key_file)
{
    assert(ctx);
    assert(ctx->ssl_ctx);
    assert(cert_file);
    assert(key_file);

    /* Load certificate */
    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1)
    {
        raise_tls_context_error("Failed to load certificate file");
    }

    /* Load private key */
    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1)
    {
        raise_tls_context_error("Failed to load private key file");
    }

    /* Verify that the private key matches the certificate */
    if (SSL_CTX_check_private_key(ctx->ssl_ctx) != 1)
    {
        raise_tls_context_error("Private key does not match certificate");
    }
}

/**
 * SocketTLSContext_load_ca - Load CA certificates for peer verification
 * @ctx: TLS context instance
 * @ca_file: CA certificate file or directory path
 *
 * Loads CA certificates used for verifying peer certificates. The path can be
 * either a single file containing CA certificates or a directory containing
 * multiple CA certificate files.
 *
 * Raises: SocketTLS_Failed on error (file not found, invalid format)
 * Thread-safe: No (modifies shared context)
 */
void SocketTLSContext_load_ca(T ctx, const char *ca_file)
{
    assert(ctx);
    assert(ctx->ssl_ctx);
    assert(ca_file);

    /* Load CA certificates */
    if (SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_file, NULL) != 1)
    {
        /* Try as directory if file loading failed */
        if (SSL_CTX_load_verify_locations(ctx->ssl_ctx, NULL, ca_file) != 1)
        {
            raise_tls_context_error("Failed to load CA certificates");
        }
    }
}

/**
 * SocketTLSContext_set_verify_mode - Configure certificate verification mode
 * @ctx: TLS context instance
 * @mode: Verification mode (TLS_VERIFY_NONE, TLS_VERIFY_PEER, etc.)
 *
 * Sets the certificate verification mode for TLS connections. This controls
 * whether peer certificates are verified and what happens when verification fails.
 *
 * Thread-safe: No (modifies shared context)
 */
void SocketTLSContext_set_verify_mode(T ctx, TLSVerifyMode mode)
{
    assert(ctx);
    assert(ctx->ssl_ctx);

    int openssl_mode = 0;

    /* Convert our enum to OpenSSL flags */
    switch (mode)
    {
    case TLS_VERIFY_NONE:
        openssl_mode = SSL_VERIFY_NONE;
        break;
    case TLS_VERIFY_PEER:
        openssl_mode = SSL_VERIFY_PEER;
        break;
    case TLS_VERIFY_FAIL_IF_NO_PEER_CERT:
        openssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        break;
    case TLS_VERIFY_CLIENT_ONCE:
        openssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
        break;
    default:
        raise_tls_context_error("Invalid TLS verification mode");
        return;
    }

    SSL_CTX_set_verify(ctx->ssl_ctx, openssl_mode, NULL);
}

/**
 * SocketTLSContext_set_min_protocol - Set minimum TLS protocol version
 * @ctx: TLS context instance
 * @version: Minimum TLS version (e.g., TLS1_2_VERSION)
 *
 * Sets the minimum allowed TLS protocol version for connections.
 * Attempts to use SSL_CTX_set_min_proto_version() for OpenSSL 1.1.0+,
 * falls back to SSL_CTX_set_options() for older versions.
 *
 * Thread-safe: No (modifies shared context)
 */
void SocketTLSContext_set_min_protocol(T ctx, int version)
{
    assert(ctx);
    assert(ctx->ssl_ctx);

    /* Try the modern API first (OpenSSL 1.1.0+) */
    if (SSL_CTX_set_min_proto_version(ctx->ssl_ctx, version) != 1)
    {
#if defined(SSL_OP_NO_SSLv2) && defined(SSL_OP_NO_SSLv3)
        /* Fall back to disabling older protocols via options */
        long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

        if (version > TLS1_VERSION)
            options |= SSL_OP_NO_TLSv1;
        if (version > TLS1_1_VERSION)
            options |= SSL_OP_NO_TLSv1_1;
        if (version > TLS1_2_VERSION)
            options |= SSL_OP_NO_TLSv1_2;

        long current_options = SSL_CTX_set_options(ctx->ssl_ctx, options);
        if (!(current_options & options))
        {
            raise_tls_context_error("Failed to set minimum TLS protocol version");
        }
#else
        /* On modern OpenSSL without deprecated macros, assume set_min_proto_version works 
         * or we are stuck. If it failed above, we can't fallback easily. */
        raise_tls_context_error("Failed to set minimum TLS protocol version (fallback unavailable)");
#endif
    }
}

/**
 * SocketTLSContext_set_max_protocol - Set maximum TLS protocol version
 * @ctx: TLS context instance
 * @version: Maximum TLS version (e.g., TLS1_3_VERSION)
 *
 * Sets the maximum allowed TLS protocol version for connections.
 * Uses SSL_CTX_set_max_proto_version() (OpenSSL 1.1.0+).
 *
 * Thread-safe: No (modifies shared context)
 */
void SocketTLSContext_set_max_protocol(T ctx, int version)
{
    assert(ctx);
    assert(ctx->ssl_ctx);

    if (SSL_CTX_set_max_proto_version(ctx->ssl_ctx, version) != 1)
    {
        raise_tls_context_error("Failed to set maximum TLS protocol version");
    }
}

/**
 * SocketTLSContext_set_cipher_list - Configure allowed cipher suites
 * @ctx: TLS context instance
 * @ciphers: OpenSSL cipher list string (e.g., "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA")
 *
 * Sets the list of allowed cipher suites for TLS connections. Uses OpenSSL's
 * cipher list format. Pass NULL to use OpenSSL defaults.
 *
 * Thread-safe: No (modifies shared context)
 */
void SocketTLSContext_set_cipher_list(T ctx, const char *ciphers)
{
    assert(ctx);
    assert(ctx->ssl_ctx);

    if (ciphers)
    {
        if (SSL_CTX_set_cipher_list(ctx->ssl_ctx, ciphers) != 1)
        {
            raise_tls_context_error("Failed to set cipher list");
        }
    }
    else
    {
        /* Use default cipher list */
        if (SSL_CTX_set_cipher_list(ctx->ssl_ctx, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA") != 1)
        {
            raise_tls_context_error("Failed to set default cipher list");
        }
    }
}

/**
 * SocketTLSContext_set_alpn_protos - Configure ALPN protocol negotiation
 * @ctx: TLS context instance
 * @protos: Array of protocol name strings (e.g., ["h2", "http/1.1"])
 * @count: Number of protocols in the array
 *
 * Sets the list of protocols to advertise during ALPN negotiation.
 * Each protocol string must be <= SOCKET_TLS_MAX_ALPN_LEN bytes.
 * For servers, this sets the list of supported protocols.
 * For clients, this sets the list of desired protocols in preference order.
 *
 * Thread-safe: No (modifies shared context)
 */
void SocketTLSContext_set_alpn_protos(T ctx, const char **protos, size_t count)
{
    assert(ctx);
    assert(ctx->ssl_ctx);
    assert(protos || count == 0);

    if (count == 0)
        return;

    /* Calculate total buffer size needed for wire format */
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++)
    {
        assert(protos[i]);
        size_t len = strlen(protos[i]);
        if (len == 0 || len > SOCKET_TLS_MAX_ALPN_LEN)
        {
            raise_tls_context_error("Invalid ALPN protocol length");
        }
        total_len += 1 + len;  /* 1 byte length + protocol string */
    }

    /* Allocate buffer from context arena */
    unsigned char *wire_buf = Arena_alloc(ctx->arena, total_len, __FILE__, __LINE__);
    if (!wire_buf)
    {
        raise_tls_context_error("Failed to allocate ALPN buffer");
    }

    /* Convert to wire format (length-prefixed strings) */
    size_t offset = 0;
    for (size_t i = 0; i < count; i++)
    {
        size_t len = strlen(protos[i]);
        wire_buf[offset++] = (unsigned char)len;
        memcpy(wire_buf + offset, protos[i], len);
        offset += len;
    }

    /* Set ALPN protocols */
    if (SSL_CTX_set_alpn_protos(ctx->ssl_ctx, wire_buf, (unsigned int)total_len) != 0)
    {
        raise_tls_context_error("Failed to set ALPN protocols");
    }
}

/**
 * SocketTLSContext_enable_session_cache - Enable TLS session caching
 * @ctx: TLS context instance
 *
 * Enables TLS session caching to improve performance by reusing established
 * sessions. Session caching is enabled by default for both client and server
 * contexts, but this function allows explicit control.
 *
 * Thread-safe: No (modifies shared context)
 */
void SocketTLSContext_enable_session_cache(T ctx)
{
    assert(ctx);
    assert(ctx->ssl_ctx);

    long mode;

    if (ctx->is_server)
    {
        mode = SSL_SESS_CACHE_SERVER;
    }
    else
    {
        mode = SSL_SESS_CACHE_CLIENT;
    }

    if (SSL_CTX_set_session_cache_mode(ctx->ssl_ctx, mode) == 0)
    {
        raise_tls_context_error("Failed to enable session cache");
    }

    ctx->session_cache_enabled = 1;
}

/**
 * SocketTLSContext_set_session_cache_size - Set session cache size limit
 * @ctx: TLS context instance
 * @size: Maximum number of cached sessions
 *
 * Sets the maximum number of sessions that can be cached. This helps control
 * memory usage for session caching. The default is SOCKET_TLS_SESSION_CACHE_SIZE.
 *
 * Thread-safe: No (modifies shared context)
 */
void SocketTLSContext_set_session_cache_size(T ctx, size_t size)
{
    assert(ctx);
    assert(ctx->ssl_ctx);

    if (size == 0)
    {
        raise_tls_context_error("Session cache size cannot be zero");
    }

    if (SSL_CTX_sess_set_cache_size(ctx->ssl_ctx, (long)size) == 0)
    {
        raise_tls_context_error("Failed to set session cache size");
    }

    ctx->session_cache_size = size;
}

/**
 * SocketTLSContext_free - Destroy TLS context and free resources
 * @ctx: Pointer to TLS context instance
 *
 * Frees all resources associated with the TLS context, including the
 * OpenSSL SSL_CTX and arena allocations. Sets the pointer to NULL.
 *
 * Thread-safe: No (not safe to free while in use by other threads)
 */
void SocketTLSContext_free(T *ctx)
{
    assert(ctx);

    if (*ctx)
    {
        T c = *ctx;

        /* Free OpenSSL context */
        if (c->ssl_ctx)
        {
            SSL_CTX_free(c->ssl_ctx);
            c->ssl_ctx = NULL;
        }

        /* Free arena (this cleans up all arena allocations) */
        if (c->arena)
        {
            Arena_dispose(&c->arena);
        }

        /* Free context structure */
        free(c);
        *ctx = NULL;
    }
}

/**
 * SocketTLSContext_get_ssl_ctx - Get internal SSL_CTX pointer
 * @ctx: TLS context instance
 *
 * Returns the internal OpenSSL SSL_CTX pointer for use by other modules.
 * This breaks the abstraction but is necessary for integration with
 * existing socket TLS functionality.
 *
 * Returns: SSL_CTX pointer (cast to void* for opacity)
 * Thread-safe: Yes (reading pointer is safe)
 */
void *SocketTLSContext_get_ssl_ctx(T ctx)
{
    assert(ctx);
    return (void *)ctx->ssl_ctx;
}

/**
 * SocketTLSContext_is_server - Check if context is for server
 * @ctx: TLS context instance
 *
 * Returns: 1 if server context, 0 if client context
 * Thread-safe: Yes
 */
int SocketTLSContext_is_server(T ctx)
{
    assert(ctx);
    return ctx->is_server;
}

#undef T

#endif /* SOCKET_HAS_TLS */
