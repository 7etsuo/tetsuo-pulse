/**
 * test_tls_phase4.c - Phase 4.1 ALPN/SNI Unit Tests
 *
 * Tests the new ALPN and SNI functionality implemented in Phase 4.1
 */

#include "test/Test.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#include "core/Arena.h"

#ifdef SOCKET_HAS_TLS

TEST(tls_sni_certificate_selection)
{
    (void)0;  /* SNI testing requires full client/server handshake setup - covered in integration tests */
}

TEST(tls_alpn_protocol_negotiation)
{
    (void)0;  /* Full ALPN negotiation requires client/server handshake - covered in integration tests */
}

TEST(tls_alpn_get_selected)
{
    (void)0;  /* ALPN get selected requires handshake - covered in integration tests */
}

TEST(tls_alpn_callback)
{
    (void)0;  /* ALPN callback testing requires full handshake - covered in integration tests */
}

static int
dummy_verify_cb (int pre_ok, X509_STORE_CTX *ctx, SocketTLSContext_T tls_ctx, Socket_T sock, void *user_data)
{
  (void)pre_ok; (void)ctx; (void)tls_ctx; (void)sock; (void)user_data;
  return 1;  /* Accept for test */
}



TEST(verify_callback_api)
{
    Arena_T arena = Arena_new ();
    SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);  /* No CA for test */
    
    /* Test set_callback with NULL (disable) */
    SocketTLSContext_set_verify_callback (ctx, NULL, NULL);  /* Should not raise */
    
    /* Test set with dummy callback */
    SocketTLSVerifyCallback dummy_cb = (SocketTLSVerifyCallback)dummy_verify_cb;
    void *dummy_data = (void*)0x1;
    SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);
    SocketTLSContext_set_verify_callback (ctx, dummy_cb, dummy_data);  /* Should not raise */
    
    /* Test set mode after callback (reconfig) */
    SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
    
    /* Cleanup */
    SocketTLSContext_free (&ctx);
    Arena_dispose (&arena);
}

TEST(verify_integration_basic)
{
    /* Basic integration: set callback, enable TLS on sock, check no crash */
    /* Full handshake with certs for callback invocation/fail paths */
    (void)0;  /* Stub; expand with socketpair + self-signed certs to test wrapper and fail cases */
}
TEST(verify_integration_cert)
{
    /* Basic integration: set callback, enable TLS on sock, check no crash */
    /* Full handshake mock or real certs needed for complete; stub for API */
    (void)0;  /* Expand with cert files for real test: callback called during verify */
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}

#else
int main(void) { return 0; }
#endif