#ifndef SOCKETTLSCONFIG_INCLUDED
#define SOCKETTLSCONFIG_INCLUDED

#ifdef SOCKET_HAS_TLS

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* TLS protocol version configuration */
#define SOCKET_TLS_MIN_VERSION TLS1_2_VERSION
#define SOCKET_TLS_MAX_VERSION 0  /* 0 = use highest available */

/* TLS handshake timeout defaults */
#ifndef SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000  /* 30 seconds */
#endif

/* TLS read/write buffer sizes */
#ifndef SOCKET_TLS_BUFFER_SIZE
#define SOCKET_TLS_BUFFER_SIZE 16384  /* 16KB - typical TLS record size */
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
typedef struct SSL_CTX SSL_CTX;
typedef struct SSL SSL;
typedef struct X509 X509;
typedef struct X509_STORE X509_STORE;

#else /* SOCKET_HAS_TLS not defined */

/* Stub definitions when TLS is disabled */
typedef void SSL_CTX;
typedef void SSL;
typedef void X509;
typedef void X509_STORE;

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONFIG_INCLUDED */
