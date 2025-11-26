#ifndef SOCKETTLSCONFIG_INCLUDED
#define SOCKETTLSCONFIG_INCLUDED

/**
 * SocketTLSConfig.h - TLS Configuration Constants and Stubs
 *
 * Defines secure defaults for TLS operations: TLS1.3-only, modern ciphers,
 * buffer sizes, timeouts, and limits. Provides stub typedefs when TLS disabled
 * for compilation without OpenSSL.
 *
 * All constants can be overridden before including this header.
 * Enforces high-security posture by default (no legacy protocols/ciphers).
 *
 * Thread-safe: Yes - compile-time constants
 */

#ifdef SOCKET_HAS_TLS

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* TLS Protocol Versions - STRICT TLS1.3-ONLY (recommended for high-perf
 * servers) */
/* Compatibility mode removed to enforce strict security standards */
#define SOCKET_TLS_MIN_VERSION TLS1_3_VERSION
#define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION

/* TLS1.3 Modern Ciphersuites (ECDHE-PFS only, AES-GCM/ChaCha20-Poly1305) */
#define SOCKET_TLS13_CIPHERSUITES                                             \
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_"      \
  "SHA256"

/* TLS handshake timeout defaults */
#ifndef SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000 /* 30 seconds */
#endif

/* TLS read/write buffer sizes */
#ifndef SOCKET_TLS_BUFFER_SIZE
#define SOCKET_TLS_BUFFER_SIZE 16384 /* 16KB - TLS record max */
#endif

/* Maximum certificate chain depth */
#ifndef SOCKET_TLS_MAX_CERT_CHAIN_DEPTH
#define SOCKET_TLS_MAX_CERT_CHAIN_DEPTH 10
#endif

/* ALPN protocol string limits */
#ifndef SOCKET_TLS_MAX_ALPN_LEN
#define SOCKET_TLS_MAX_ALPN_LEN 255
#endif

/* SNI hostname length limit */
#ifndef SOCKET_TLS_MAX_SNI_LEN
#define SOCKET_TLS_MAX_SNI_LEN 255
#endif

/* TLS session cache size (number of sessions) */
#ifndef SOCKET_TLS_SESSION_CACHE_SIZE
#define SOCKET_TLS_SESSION_CACHE_SIZE 1000
#endif

/* TLS error buffer size for detailed error messages */
#ifndef SOCKET_TLS_ERROR_BUFSIZE
#define SOCKET_TLS_ERROR_BUFSIZE 512
#endif

/* OpenSSL error string buffer size for temporary error formatting */
#ifndef SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE
#define SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE 256
#endif

/* Maximum number of SNI certificates */
#ifndef SOCKET_TLS_MAX_SNI_CERTS
#define SOCKET_TLS_MAX_SNI_CERTS 100
#endif

/* Initial SNI certificate array capacity (doubles on expansion) */
#ifndef SOCKET_TLS_SNI_INITIAL_CAPACITY
#define SOCKET_TLS_SNI_INITIAL_CAPACITY 4
#endif

/* Maximum number of ALPN protocols */
#ifndef SOCKET_TLS_MAX_ALPN_PROTOCOLS
#define SOCKET_TLS_MAX_ALPN_PROTOCOLS 16
#endif

/* Session ticket key length (OpenSSL uses 80 bytes: 16 name + 32 AES + 32 HMAC)
 */
#ifndef SOCKET_TLS_TICKET_KEY_LEN
#define SOCKET_TLS_TICKET_KEY_LEN 80
#endif

/* Default session cache timeout in seconds */
#ifndef SOCKET_TLS_SESSION_TIMEOUT_DEFAULT
#define SOCKET_TLS_SESSION_TIMEOUT_DEFAULT 300L
#endif

/* Maximum file path length for certificates/keys */
#ifndef SOCKET_TLS_MAX_PATH_LEN
#define SOCKET_TLS_MAX_PATH_LEN 4096
#endif

/* Maximum DNS label length per RFC 1035 */
#ifndef SOCKET_TLS_MAX_LABEL_LEN
#define SOCKET_TLS_MAX_LABEL_LEN 63
#endif

#else /* SOCKET_HAS_TLS not defined */

/* Stub definitions when TLS is disabled */
#ifndef SSL_CTX
typedef void SSL_CTX;
#endif
#ifndef SSL
typedef void SSL;
#endif
#ifndef X509
typedef void X509;
#endif
#ifndef X509_STORE
typedef void X509_STORE;
#endif

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONFIG_INCLUDED */
