#ifndef SOCKETTLSCONTEXT_INCLUDED
#define SOCKETTLSCONTEXT_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h"

#ifdef SOCKET_HAS_TLS

#define T SocketTLSContext_T
typedef struct T *T;

/* TLS context creation */
T SocketTLSContext_new_server(const char *cert_file, const char *key_file, const char *ca_file);
T SocketTLSContext_new_client(const char *ca_file);

/* Certificate management */
void SocketTLSContext_load_certificate(T ctx, const char *cert_file, const char *key_file);
void SocketTLSContext_load_ca(T ctx, const char *ca_file);
void SocketTLSContext_set_verify_mode(T ctx, TLSVerifyMode mode);

/* Protocol configuration */
void SocketTLSContext_set_min_protocol(T ctx, int version);
void SocketTLSContext_set_max_protocol(T ctx, int version);
void SocketTLSContext_set_cipher_list(T ctx, const char *ciphers);

/* ALPN support */
void SocketTLSContext_set_alpn_protos(T ctx, const char **protos, size_t count);

/* Session management */
void SocketTLSContext_enable_session_cache(T ctx);
void SocketTLSContext_set_session_cache_size(T ctx, size_t size);

/* Context lifecycle */
void SocketTLSContext_free(T *ctx);

/* Internal: Get SSL_CTX* (for implementation use) */
void *SocketTLSContext_get_ssl_ctx(T ctx);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONTEXT_INCLUDED */
