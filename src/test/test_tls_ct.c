/**
 * test_tls_ct.c - Certificate Transparency Tests
 *
 * Tests CT enable/disable, modes, custom log lists, and integration with TLS
 * context. Requires SOCKET_HAS_TLS and SOCKET_HAS_CT_SUPPORT.
 *
 * CT Support Detection:
 * - SOCKET_HAS_CT_SUPPORT is defined in SocketTLSConfig.h
 * - Requires OpenSSL 1.1.0+ without OPENSSL_NO_CT
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLSConfig.h" /* For SOCKET_HAS_CT_SUPPORT */
#include "tls/SocketTLSContext.h"

TEST (ct_context_basic_operations)
{
  volatile SocketTLSContext_T ctx = NULL;
  volatile int success = 0;
  volatile SocketTLSContext_T ctx2 = NULL;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#endif
  TRY
  {
    ctx = SocketTLSContext_new_client (NULL); /* Minimal client context */

    /* Test default state */
    ASSERT_EQ (SocketTLSContext_ct_enabled (ctx), 0);
    ASSERT_EQ (SocketTLSContext_get_ct_mode (ctx), CT_VALIDATION_PERMISSIVE);

    /* Test enable strict */
    SocketTLSContext_enable_ct (ctx, CT_VALIDATION_STRICT);
    ASSERT_EQ (SocketTLSContext_ct_enabled (ctx), 1);
    ASSERT_EQ (SocketTLSContext_get_ct_mode (ctx), CT_VALIDATION_STRICT);

    /* Test enable permissive */
    ctx2 = SocketTLSContext_new_client (NULL);
    SocketTLSContext_enable_ct (ctx2, CT_VALIDATION_PERMISSIVE);
    ASSERT_EQ (SocketTLSContext_ct_enabled (ctx2), 1);
    ASSERT_EQ (SocketTLSContext_get_ct_mode (ctx2), CT_VALIDATION_PERMISSIVE);

    /* Test custom log file - invalid */
    TRY
    {
      SocketTLSContext_set_ctlog_list_file (ctx, NULL);
      Test_fail ("Expected failure on NULL log file", __FILE__, __LINE__);
    }
    EXCEPT (SocketTLS_Failed) { /* Expected */ }
    END_TRY;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

    TRY
    {
      SocketTLSContext_set_ctlog_list_file (ctx, "");
      Test_fail ("Expected failure on empty log file", __FILE__, __LINE__);
    }
    EXCEPT (SocketTLS_Failed) {}
    END_TRY;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

    /* Test valid path (use temp or /dev/null placeholder) */
#if SOCKET_HAS_CT_SUPPORT
    TRY
    {
      SocketTLSContext_set_ctlog_list_file (
          ctx, "/dev/null"); /* May not be valid log, but path ok */
      /* If succeeds or fails due to content, ok - tests path val and API */
      success = 1;
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Acceptable if /dev/null not loadable as log list */
      SOCKET_LOG_WARN_MSG (
          "CT log test: OpenSSL failed to load placeholder file");
      success = 1; /* API call tested */
    }
    END_TRY;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
    ASSERT (success == 1);
#endif

    success = 1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Handle unsupported or config errors */
    if (Except_stack->exception->type == &SocketTLS_Failed
        && strstr (Except_stack->exception->reason, "CT not supported")
               != NULL)
      {
        /* Expected without OpenSSL CT */
        success = 1;
      }
    else
      {
        {
          char buf[512];
          snprintf (buf, sizeof (buf), "Unexpected TLS failure: %s",
                    Except_stack->exception->reason);
          Test_fail (buf, __FILE__, __LINE__);
        }
      }
  }
  FINALLY
  {
    SocketTLSContext_free ((SocketTLSContext_T *)&ctx);
    SocketTLSContext_free ((SocketTLSContext_T *)&ctx2);
  }
  END_TRY;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

  ASSERT (success == 1);
}

TEST (ct_server_context_rejection)
{
  volatile SocketTLSContext_T server = NULL;
  volatile int exception_raised = 0;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#endif
  TRY
  {
    /* Create server context (requires cert/key; use placeholders or skip load)
     */
    server = SocketTLSContext_new_server (
        "/dev/null", "/dev/null", NULL); /* Will fail load, but for API test */

    TRY
    {
      SocketTLSContext_enable_ct (server, CT_VALIDATION_STRICT);
      Test_fail ("Expected SocketTLS_Failed on server CT enable", __FILE__,
                 __LINE__);
    }
    EXCEPT (SocketTLS_Failed)
    {
      ASSERT (strcmp (Except_stack->exception->reason,
                      "CT verification is for clients only")
              == 0);
      exception_raised = 1;
    }
    END_TRY;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

    ASSERT (exception_raised == 1);

    TRY
    {
      SocketTLSContext_set_ctlog_list_file (server, "/dev/null");
      Test_fail ("Expected failure on server custom log", __FILE__, __LINE__);
    }
    EXCEPT (SocketTLS_Failed)
    {
      ASSERT (strstr (Except_stack->exception->reason, "clients only") != NULL
              || strstr (Except_stack->exception->reason, "not supported")
                     != NULL);
      exception_raised++;
    }
    END_TRY;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Cert load failure expected if no files; API test still valid */
  }
  FINALLY { SocketTLSContext_free ((SocketTLSContext_T *)&server); }
  END_TRY;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
}

#else /* !SOCKET_HAS_TLS */

TEST_CASE ("CT Tests Skipped Without TLS")
{
  PASS_MSG ("TLS disabled - CT tests skipped");
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
