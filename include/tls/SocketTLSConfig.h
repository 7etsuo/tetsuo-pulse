#ifndef SOCKETTLSCONFIG_INCLUDED
#define SOCKETTLSCONFIG_INCLUDED

#ifdef SOCKET_HAS_TLS

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* TLS Protocol Versions - STRICT TLS1.3-ONLY (recommended for high-perf servers) */
/* Compatibility mode removed to enforce strict security standards */
#define SOCKET_TLS_MIN_VERSION TLS1_3_VERSION
#define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION

/* TLS1.3 Modern Ciphersuites (ECDHE-PFS only, AES-GCM/ChaCha20-Poly1305) */
#define SOCKET_TLS13_CIPHERSUITES "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

/* TLS handshake timeout defaults */
#ifndef SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000  /* 30 seconds */
#endif

/* TLS read/write buffer sizes */
#ifndef SOCKET_TLS_BUFFER_SIZE
#define SOCKET_TLS_BUFFER_SIZE 16384  /* 16KB - TLS record max */
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

/* Forward declarations for TLS types */
/* OpenSSL types are already defined by the includes above when SOCKET_HAS_TLS is set */
#ifndef SOCKET_HAS_TLS
typedef void SSL_CTX;
typedef void SSL;
typedef void X509;
typedef void X509_STORE;
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
