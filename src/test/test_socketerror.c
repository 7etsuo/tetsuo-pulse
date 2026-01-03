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

/* ============================================================================
 * SocketError_category_name Tests
 * ============================================================================
 */

/* Test all valid category enum values return correct names */
TEST (socketerror_category_name_all_valid)
{
  ASSERT_NOT_NULL (SocketError_category_name (SOCKET_ERROR_CATEGORY_NETWORK));
  ASSERT_EQ (0,
             strcmp ("NETWORK",
                     SocketError_category_name (SOCKET_ERROR_CATEGORY_NETWORK)));

  ASSERT_NOT_NULL (SocketError_category_name (SOCKET_ERROR_CATEGORY_PROTOCOL));
  ASSERT_EQ (
      0,
      strcmp ("PROTOCOL",
              SocketError_category_name (SOCKET_ERROR_CATEGORY_PROTOCOL)));

  ASSERT_NOT_NULL (
      SocketError_category_name (SOCKET_ERROR_CATEGORY_APPLICATION));
  ASSERT_EQ (0,
             strcmp ("APPLICATION",
                     SocketError_category_name (
                         SOCKET_ERROR_CATEGORY_APPLICATION)));

  ASSERT_NOT_NULL (SocketError_category_name (SOCKET_ERROR_CATEGORY_TIMEOUT));
  ASSERT_EQ (0,
             strcmp ("TIMEOUT",
                     SocketError_category_name (SOCKET_ERROR_CATEGORY_TIMEOUT)));

  ASSERT_NOT_NULL (SocketError_category_name (SOCKET_ERROR_CATEGORY_RESOURCE));
  ASSERT_EQ (
      0,
      strcmp ("RESOURCE",
              SocketError_category_name (SOCKET_ERROR_CATEGORY_RESOURCE)));

  ASSERT_NOT_NULL (SocketError_category_name (SOCKET_ERROR_CATEGORY_UNKNOWN));
  ASSERT_EQ (0,
             strcmp ("UNKNOWN",
                     SocketError_category_name (SOCKET_ERROR_CATEGORY_UNKNOWN)));
}

/* Test negative category value returns "UNKNOWN" */
TEST (socketerror_category_name_negative)
{
  const char *name = SocketError_category_name ((SocketErrorCategory)-1);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp ("UNKNOWN", name));
}

/* Test out-of-bounds positive value returns "UNKNOWN" */
TEST (socketerror_category_name_out_of_bounds)
{
  const char *name
      = SocketError_category_name (SOCKET_ERROR_CATEGORY_COUNT);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp ("UNKNOWN", name));

  name = SocketError_category_name ((SocketErrorCategory)999);
  ASSERT_NOT_NULL (name);
  ASSERT_EQ (0, strcmp ("UNKNOWN", name));
}

/* Test all returned strings are non-NULL and non-empty */
TEST (socketerror_category_name_non_null_non_empty)
{
  for (int cat = 0; cat < SOCKET_ERROR_CATEGORY_COUNT; cat++)
    {
      const char *name = SocketError_category_name ((SocketErrorCategory)cat);
      ASSERT_NOT_NULL (name);
      ASSERT (strlen (name) > 0);
    }

  /* Also test out-of-bounds */
  const char *unknown = SocketError_category_name ((SocketErrorCategory)-1);
  ASSERT_NOT_NULL (unknown);
  ASSERT (strlen (unknown) > 0);
}

/* Test returned strings are static (same pointer on repeated calls) */
TEST (socketerror_category_name_static_strings)
{
  const char *name1
      = SocketError_category_name (SOCKET_ERROR_CATEGORY_NETWORK);
  const char *name2
      = SocketError_category_name (SOCKET_ERROR_CATEGORY_NETWORK);
  ASSERT_EQ (name1, name2); /* Should be same pointer */

  const char *unknown1 = SocketError_category_name ((SocketErrorCategory)-1);
  const char *unknown2 = SocketError_category_name ((SocketErrorCategory)999);
  ASSERT_EQ (unknown1, unknown2); /* Both should point to "UNKNOWN" */
}

/* Test categorize_errno integration with category_name */
TEST (socketerror_category_name_integration_categorize)
{
  int saved_errno = errno;

  /* Network errors should categorize to NETWORK */
  SocketErrorCategory cat = SocketError_categorize_errno (ECONNREFUSED);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
  ASSERT_EQ (0, strcmp ("NETWORK", SocketError_category_name (cat)));

  cat = SocketError_categorize_errno (ECONNRESET);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK, cat);
  ASSERT_EQ (0, strcmp ("NETWORK", SocketError_category_name (cat)));

  /* Timeout errors should categorize to TIMEOUT */
  cat = SocketError_categorize_errno (ETIMEDOUT);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_TIMEOUT, cat);
  ASSERT_EQ (0, strcmp ("TIMEOUT", SocketError_category_name (cat)));

  /* Resource errors should categorize to RESOURCE */
  cat = SocketError_categorize_errno (ENOMEM);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE, cat);
  ASSERT_EQ (0, strcmp ("RESOURCE", SocketError_category_name (cat)));

  cat = SocketError_categorize_errno (EMFILE);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE, cat);
  ASSERT_EQ (0, strcmp ("RESOURCE", SocketError_category_name (cat)));

  /* Protocol errors should categorize to PROTOCOL */
  cat = SocketError_categorize_errno (EINVAL);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL, cat);
  ASSERT_EQ (0, strcmp ("PROTOCOL", SocketError_category_name (cat)));

  /* Application errors should categorize to APPLICATION */
  cat = SocketError_categorize_errno (EACCES);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION, cat);
  ASSERT_EQ (0, strcmp ("APPLICATION", SocketError_category_name (cat)));

  /* Unknown errno should categorize to UNKNOWN */
  cat = SocketError_categorize_errno (99999);
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_UNKNOWN, cat);
  ASSERT_EQ (0, strcmp ("UNKNOWN", SocketError_category_name (cat)));

  errno = saved_errno;
}

/* ==================== Socket_safe_strerror Unit Tests ==================== */

/* Test zero errno returns "No error" */
TEST (socketerror_safe_strerror_zero_errno)
{
  const char *result = Socket_safe_strerror (0);

  ASSERT_NOT_NULL (result);
  ASSERT (strcmp (result, "No error") == 0);
}

/* Test valid errno values return descriptive strings */
TEST (socketerror_safe_strerror_valid_errno)
{
  struct
  {
    int errnum;
    const char *expected_substring;
  } test_cases[] = {
    { ECONNREFUSED, "" }, /* Any non-NULL, non-empty string is valid */
    { ETIMEDOUT, "" },    { ENOMEM, "" },
    { EAGAIN, "" },       { EINVAL, "" },
    { EPIPE, "" },        { ECONNRESET, "" },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      const char *result = Socket_safe_strerror (test_cases[i].errnum);

      ASSERT_NOT_NULL (result);
      ASSERT (strlen (result) > 0); /* Must return non-empty string */
    }
}

/* Test invalid errno returns "Unknown error" message */
TEST (socketerror_safe_strerror_invalid_errno)
{
  const char *result = Socket_safe_strerror (99999);

  ASSERT_NOT_NULL (result);
  /* Should contain either "Unknown" or the error number */
  ASSERT (strstr (result, "Unknown") != NULL || strstr (result, "99999") != NULL);
}

/* Test thread-local buffer reuse (consistent pointer per thread) */
TEST (socketerror_safe_strerror_buffer_reuse)
{
  /* Call with errno=0 twice - this always uses the thread-local buffer */
  const char *result1 = Socket_safe_strerror (0);
  const char *result2 = Socket_safe_strerror (0);

  /* Same thread should reuse the same buffer (same pointer) for errno=0 */
  ASSERT_EQ (result1, result2);
  ASSERT (strcmp (result1, "No error") == 0);

  /* GNU strerror_r may return static strings for other errno values,
   * so we test that multiple calls to errno=0 use the thread-local buffer */
}

/* Test buffer doesn't overflow with maximum errno */
TEST (socketerror_safe_strerror_buffer_bounds)
{
  /* Test with various errno values including edge cases */
  const int test_errnos[] = { 0, 1, EINVAL, ECONNREFUSED, ETIMEDOUT, 99999 };

  for (size_t i = 0; i < sizeof (test_errnos) / sizeof (test_errnos[0]); i++)
    {
      const char *result = Socket_safe_strerror (test_errnos[i]);

      ASSERT_NOT_NULL (result);
      /* Verify buffer size constraint (SOCKET_STRERROR_BUFSIZE = 128) */
      size_t len = strlen (result);
      ASSERT (len < 128);
    }
}

/* Test both strerror_r variants are handled correctly */
TEST (socketerror_safe_strerror_platform_variants)
{
  /* Test common error that exists on all platforms */
  const char *result_einval = Socket_safe_strerror (EINVAL);
  const char *result_econnrefused = Socket_safe_strerror (ECONNREFUSED);

  ASSERT_NOT_NULL (result_einval);
  ASSERT_NOT_NULL (result_econnrefused);

  /* Both should return non-empty strings */
  ASSERT (strlen (result_einval) > 0);
  ASSERT (strlen (result_econnrefused) > 0);

#if defined(__GLIBC__) && defined(_GNU_SOURCE)
  /* GNU extension path - strerror_r returns char* */
  /* Verify we're getting descriptive text, not just error codes */
  ASSERT (strstr (result_einval, "Invalid") != NULL
          || strstr (result_einval, "invalid") != NULL
          || strstr (result_einval, "argument") != NULL);
#else
  /* XSI-compliant path - strerror_r returns int, fills buffer */
  /* Just verify we got non-NULL, non-empty string */
  ASSERT (result_einval[0] != '\0');
#endif
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
