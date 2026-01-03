/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketerror.c - SocketError module unit tests
 * Tests for error categorization and errno classification.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "core/SocketError.h"
#include "test/Test.h"

/* ============================================================================
 * NETWORK CATEGORY TESTS
 * ============================================================================
 */

TEST (error_categorize_econnrefused_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ECONNREFUSED);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_econnreset_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ECONNRESET);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_ehostunreach_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EHOSTUNREACH);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_enetunreach_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENETUNREACH);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_enotconn_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENOTCONN);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_epipe_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EPIPE);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_econnaborted_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ECONNABORTED);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_eagain_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EAGAIN);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_ealready_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EALREADY);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_einprogress_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EINPROGRESS);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

TEST (error_categorize_eintr_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EINTR);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}

#ifdef ENETDOWN
TEST (error_categorize_enetdown_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENETDOWN);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}
#endif

#ifdef ENETRESET
TEST (error_categorize_enetreset_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENETRESET);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}
#endif

#ifdef EWOULDBLOCK
TEST (error_categorize_ewouldblock_is_network)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EWOULDBLOCK);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
}
#endif

/* ============================================================================
 * PROTOCOL CATEGORY TESTS
 * ============================================================================
 */

TEST (error_categorize_einval_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EINVAL);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}

TEST (error_categorize_eafnosupport_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EAFNOSUPPORT);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}

TEST (error_categorize_ebadf_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EBADF);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}

TEST (error_categorize_efault_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EFAULT);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}

TEST (error_categorize_eisconn_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EISCONN);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}

TEST (error_categorize_enotsock_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENOTSOCK);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}

TEST (error_categorize_eopnotsupp_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EOPNOTSUPP);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}

TEST (error_categorize_eprotonosupport_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EPROTONOSUPPORT);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}

#ifdef EPROTO
TEST (error_categorize_eproto_is_protocol)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EPROTO);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
}
#endif

/* ============================================================================
 * APPLICATION CATEGORY TESTS
 * ============================================================================
 */

TEST (error_categorize_eacces_is_application)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EACCES);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION, cat);
}

TEST (error_categorize_eaddrinuse_is_application)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EADDRINUSE);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION, cat);
}

TEST (error_categorize_eaddrnotavail_is_application)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EADDRNOTAVAIL);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION, cat);
}

TEST (error_categorize_eperm_is_application)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EPERM);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION, cat);
}

/* ============================================================================
 * TIMEOUT CATEGORY TESTS
 * ============================================================================
 */

TEST (error_categorize_etimedout_is_timeout)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ETIMEDOUT);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_TIMEOUT, cat);
}

/* ============================================================================
 * RESOURCE CATEGORY TESTS
 * ============================================================================
 */

TEST (error_categorize_emfile_is_resource)
{
  SocketErrorCategory cat = SocketError_categorize_errno (EMFILE);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE, cat);
}

TEST (error_categorize_enobufs_is_resource)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENOBUFS);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE, cat);
}

TEST (error_categorize_enomem_is_resource)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENOMEM);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE, cat);
}

TEST (error_categorize_enfile_is_resource)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENFILE);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE, cat);
}

#ifdef ENOSPC
TEST (error_categorize_enospc_is_resource)
{
  SocketErrorCategory cat = SocketError_categorize_errno (ENOSPC);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE, cat);
}
#endif

/* ============================================================================
 * UNKNOWN CATEGORY TESTS
 * ============================================================================
 */

TEST (error_categorize_zero_is_unknown)
{
  SocketErrorCategory cat = SocketError_categorize_errno (0);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_UNKNOWN, cat);
}

TEST (error_categorize_invalid_errno_is_unknown)
{
  /* Use an errno value that should not be in the mappings table */
  SocketErrorCategory cat = SocketError_categorize_errno (99999);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_UNKNOWN, cat);
}

/* ============================================================================
 * CATEGORY NAME TESTS
 * ============================================================================
 */

TEST (error_category_name_network)
{
  const char *name = SocketError_category_name (SOCKET_ERROR_CATEGORY_NETWORK);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp (name, "NETWORK"));
}

TEST (error_category_name_protocol)
{
  const char *name
      = SocketError_category_name (SOCKET_ERROR_CATEGORY_PROTOCOL);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp (name, "PROTOCOL"));
}

TEST (error_category_name_application)
{
  const char *name
      = SocketError_category_name (SOCKET_ERROR_CATEGORY_APPLICATION);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp (name, "APPLICATION"));
}

TEST (error_category_name_timeout)
{
  const char *name = SocketError_category_name (SOCKET_ERROR_CATEGORY_TIMEOUT);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp (name, "TIMEOUT"));
}

TEST (error_category_name_resource)
{
  const char *name
      = SocketError_category_name (SOCKET_ERROR_CATEGORY_RESOURCE);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp (name, "RESOURCE"));
}

TEST (error_category_name_unknown)
{
  const char *name = SocketError_category_name (SOCKET_ERROR_CATEGORY_UNKNOWN);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp (name, "UNKNOWN"));
}

TEST (error_category_name_invalid_returns_unknown)
{
  const char *name = SocketError_category_name ((SocketErrorCategory)999);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp (name, "UNKNOWN"));
}

/* ============================================================================
 * RETRYABLE ERRNO TESTS
 * ============================================================================
 */

TEST (error_retryable_econnrefused_is_retryable)
{
  int retryable = SocketError_is_retryable_errno (ECONNREFUSED);
  ASSERT_EQ (1, retryable);
}

TEST (error_retryable_etimedout_is_retryable)
{
  int retryable = SocketError_is_retryable_errno (ETIMEDOUT);
  ASSERT_EQ (1, retryable);
}

TEST (error_retryable_einval_is_not_retryable)
{
  int retryable = SocketError_is_retryable_errno (EINVAL);
  ASSERT_EQ (0, retryable);
}

TEST (error_retryable_eacces_is_not_retryable)
{
  int retryable = SocketError_is_retryable_errno (EACCES);
  ASSERT_EQ (0, retryable);
}

TEST (error_retryable_enomem_is_not_retryable)
{
  int retryable = SocketError_is_retryable_errno (ENOMEM);
  ASSERT_EQ (0, retryable);
}

TEST (error_retryable_unknown_errno_is_not_retryable)
{
  int retryable = SocketError_is_retryable_errno (99999);
  ASSERT_EQ (0, retryable);
}

/* ============================================================================
 * SocketError_is_retryable_errno tests
 * ============================================================================
 */

TEST (socketerror_retryable_network_errors)
{
  /* Basic network errors - should be retryable */
  ASSERT_EQ (1, SocketError_is_retryable_errno (EAGAIN));
#ifdef EWOULDBLOCK
  ASSERT_EQ (1, SocketError_is_retryable_errno (EWOULDBLOCK));
#endif
  ASSERT_EQ (1, SocketError_is_retryable_errno (EALREADY));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ECONNREFUSED));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ECONNRESET));
  ASSERT_EQ (1, SocketError_is_retryable_errno (EHOSTUNREACH));
  ASSERT_EQ (1, SocketError_is_retryable_errno (EINPROGRESS));
  ASSERT_EQ (1, SocketError_is_retryable_errno (EINTR));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ENOTCONN));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ENETUNREACH));
  ASSERT_EQ (1, SocketError_is_retryable_errno (EPIPE));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ECONNABORTED));
}

TEST (socketerror_retryable_platform_specific)
{
  /* Platform-specific network errors */
#ifdef ENETDOWN
  ASSERT_EQ (1, SocketError_is_retryable_errno (ENETDOWN));
#endif
#ifdef ENETRESET
  ASSERT_EQ (1, SocketError_is_retryable_errno (ENETRESET));
#endif
}

TEST (socketerror_retryable_timeout)
{
  /* Timeout errors should be retryable */
  ASSERT_EQ (1, SocketError_is_retryable_errno (ETIMEDOUT));
}

TEST (socketerror_non_retryable_config)
{
  /* Configuration errors - not retryable */
  ASSERT_EQ (0, SocketError_is_retryable_errno (EINVAL));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EACCES));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EADDRINUSE));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EADDRNOTAVAIL));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EAFNOSUPPORT));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EBADF));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EFAULT));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EISCONN));
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENOTSOCK));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EOPNOTSUPP));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EPROTONOSUPPORT));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EPERM));
}

TEST (socketerror_non_retryable_platform_specific)
{
  /* Platform-specific non-retryable errors */
#ifdef EPROTO
  ASSERT_EQ (0, SocketError_is_retryable_errno (EPROTO));
#endif
}

TEST (socketerror_non_retryable_resource)
{
  /* Resource exhaustion - not retryable */
  ASSERT_EQ (0, SocketError_is_retryable_errno (EMFILE));
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENOMEM));
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENOBUFS));
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENFILE));
#ifdef ENOSPC
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENOSPC));
#endif
}

TEST (socketerror_retryable_edge_cases)
{
  /* Edge cases */
  ASSERT_EQ (0, SocketError_is_retryable_errno (0));
  ASSERT_EQ (0, SocketError_is_retryable_errno (99999));
  ASSERT_EQ (0, SocketError_is_retryable_errno (-1));
}

TEST (socketerror_categorize_network)
{
  /* Network category errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (ECONNREFUSED));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (ECONNRESET));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (ENETUNREACH));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (EHOSTUNREACH));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (EAGAIN));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (EINPROGRESS));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (ENOTCONN));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (EPIPE));
}

TEST (socketerror_categorize_protocol)
{
  /* Protocol category errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EINVAL));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EAFNOSUPPORT));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EBADF));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EISCONN));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (ENOTSOCK));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EOPNOTSUPP));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EPROTONOSUPPORT));
}

TEST (socketerror_categorize_application)
{
  /* Application category errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION,
             SocketError_categorize_errno (EACCES));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION,
             SocketError_categorize_errno (EADDRINUSE));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION,
             SocketError_categorize_errno (EADDRNOTAVAIL));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION,
             SocketError_categorize_errno (EPERM));
}

TEST (socketerror_categorize_timeout)
{
  /* Timeout category */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_TIMEOUT,
             SocketError_categorize_errno (ETIMEDOUT));
}

TEST (socketerror_categorize_resource)
{
  /* Resource category errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE,
             SocketError_categorize_errno (EMFILE));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE,
             SocketError_categorize_errno (ENOMEM));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE,
             SocketError_categorize_errno (ENOBUFS));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE,
             SocketError_categorize_errno (ENFILE));
}

TEST (socketerror_categorize_unknown)
{
  /* Unknown category for unmapped errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_UNKNOWN,
             SocketError_categorize_errno (99999));
}

TEST (socketerror_category_name)
{
  /* Verify category names */
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_NETWORK),
                  "NETWORK")
          == 0);
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_PROTOCOL),
                  "PROTOCOL")
          == 0);
  ASSERT (
      strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_APPLICATION),
              "APPLICATION")
      == 0);
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_TIMEOUT),
                  "TIMEOUT")
          == 0);
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_RESOURCE),
                  "RESOURCE")
          == 0);
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_UNKNOWN),
                  "UNKNOWN")
          == 0);

  /* Out of range */
  ASSERT (strcmp (SocketError_category_name ((SocketErrorCategory)999),
                  "UNKNOWN")
          == 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
