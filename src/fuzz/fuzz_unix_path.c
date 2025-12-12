/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_unix_path.c - Fuzzer for Unix domain socket path validation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Path length validation (max ~107 chars for sun_path)
 * - Directory traversal detection (../ patterns)
 * - Abstract namespace paths (@ prefix)
 * - sockaddr_un setup and initialization
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_unix_path
 * Run:   ./fuzz_unix_path corpus/unix_path/ -fork=16 -max_len=256
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Maximum path length for Unix sockets (typically 108 on Linux, 104 on BSD) */
#define UNIX_PATH_MAX (sizeof (((struct sockaddr_un *)0)->sun_path) - 1)

/* Operation codes */
enum UnixPathOp
{
  OP_VALIDATE_PATH = 0,
  OP_IS_ABSTRACT,
  OP_SETUP_ABSTRACT,
  OP_SETUP_REGULAR,
  OP_SETUP_SOCKADDR,
  OP_CHECK_TRAVERSAL,
  OP_COUNT
};

/**
 * fuzz_is_abstract_path - Check if path is abstract namespace
 * @path: Unix socket path
 *
 * Replicates unix_is_abstract_path() from Socket.c
 */
static inline int
fuzz_is_abstract_path (const char *path)
{
  return path && path[0] == '@';
}

/**
 * fuzz_check_traversal - Check for directory traversal patterns
 * @path: Path string
 * @path_len: Length of path
 *
 * Returns: 1 if traversal detected, 0 otherwise
 */
static int
fuzz_check_traversal (const char *path, size_t path_len)
{
  if (!path || path_len == 0)
    return 0;

  /* Check for /../ anywhere in path */
  if (strstr (path, "/../"))
    return 1;

  /* Check for .. alone */
  if (strcmp (path, "..") == 0)
    return 1;

  /* Check for ../ at start */
  if (path_len >= 3 && strncmp (path, "../", 3) == 0)
    return 1;

  /* Check for /.. at end */
  if (path_len >= 3 && strcmp (path + path_len - 3, "/..") == 0)
    return 1;

  return 0;
}

/**
 * fuzz_validate_path - Validate Unix socket path
 * @path: Path string
 * @path_len: Length of path
 *
 * Returns: 0 on valid, -1 on invalid
 * Replicates unix_validate_path() from Socket.c
 */
static int
fuzz_validate_path (const char *path, size_t path_len)
{
  if (path_len > UNIX_PATH_MAX)
    return -1;

  if (fuzz_check_traversal (path, path_len))
    return -1;

  return 0;
}

/**
 * fuzz_setup_abstract_socket - Setup abstract namespace socket address
 * @addr: Output sockaddr_un structure
 * @path: Unix socket path (starting with '@')
 * @path_len: Length of path
 *
 * Replicates unix_setup_abstract_socket() from Socket.c
 */
static void
fuzz_setup_abstract_socket (struct sockaddr_un *addr, const char *path,
                            size_t path_len)
{
  size_t name_len = path_len > 0 ? path_len - 1 : 0;
  size_t max_name_len = sizeof (addr->sun_path) - 1;
  if (name_len > max_name_len)
    name_len = max_name_len;

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;
  addr->sun_path[0] = '\0'; /* Abstract namespace marker */
  if (name_len > 0)
    memcpy (addr->sun_path + 1, path + 1, name_len);
}

/**
 * fuzz_setup_regular_socket - Setup regular filesystem socket address
 * @addr: Output sockaddr_un structure
 * @path: Unix socket path
 * @path_len: Length of path
 *
 * Replicates unix_setup_regular_socket() from Socket.c
 */
static void
fuzz_setup_regular_socket (struct sockaddr_un *addr, const char *path,
                           size_t path_len)
{
  size_t max_path_len = sizeof (addr->sun_path) - 1;
  if (path_len > max_path_len)
    path_len = max_path_len;

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;
  memcpy (addr->sun_path, path, path_len);
  addr->sun_path[path_len] = '\0';
}

/**
 * fuzz_setup_sockaddr - Initialize sockaddr_un from path
 * @addr: Output sockaddr_un structure
 * @path: Unix socket path
 * @path_len: Length of path
 *
 * Replicates unix_setup_sockaddr() from Socket.c
 */
static void
fuzz_setup_sockaddr (struct sockaddr_un *addr, const char *path,
                     size_t path_len)
{
  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;

  if (path[0] == '@')
    fuzz_setup_abstract_socket (addr, path, path_len);
  else
    fuzz_setup_regular_socket (addr, path, path_len);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: Path string (null-terminated or used as-is)
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct sockaddr_un addr;
  char path[256];
  size_t path_len;

  if (size < 2)
    return 0;

  uint8_t op = data[0];
  const uint8_t *path_data = data + 1;
  size_t path_data_len = size - 1;

  /* Cap path length to buffer size - 1 for null terminator */
  if (path_data_len > sizeof (path) - 1)
    path_data_len = sizeof (path) - 1;

  /* Copy and null-terminate the path */
  memcpy (path, path_data, path_data_len);
  path[path_data_len] = '\0';
  path_len = strlen (path); /* May be shorter if data contains null bytes */

  switch (op % OP_COUNT)
    {
    case OP_VALIDATE_PATH:
      {
        /* Test path validation */
        int result = fuzz_validate_path (path, path_len);
        (void)result;

        /* Also test with the raw data length (may include nulls) */
        result = fuzz_validate_path (path, path_data_len);
        (void)result;
      }
      break;

    case OP_IS_ABSTRACT:
      {
        /* Test abstract path detection */
        int is_abstract = fuzz_is_abstract_path (path);
        (void)is_abstract;

        /* Test with NULL */
        is_abstract = fuzz_is_abstract_path (NULL);
        (void)is_abstract;

        /* Test with empty string */
        is_abstract = fuzz_is_abstract_path ("");
        (void)is_abstract;
      }
      break;

    case OP_SETUP_ABSTRACT:
      {
        /* Test abstract socket setup */
        if (path_len > 0 && path[0] == '@')
          {
            fuzz_setup_abstract_socket (&addr, path, path_len);
            /* Verify structure is valid */
            assert (addr.sun_family == AF_UNIX);
            assert (addr.sun_path[0] == '\0');
          }
        else
          {
            /* Force test with @ prefix */
            char abstract_path[256];
            abstract_path[0] = '@';
            size_t copy_len = path_len > sizeof (abstract_path) - 2
                                  ? sizeof (abstract_path) - 2
                                  : path_len;
            memcpy (abstract_path + 1, path, copy_len);
            abstract_path[copy_len + 1] = '\0';
            fuzz_setup_abstract_socket (&addr, abstract_path, copy_len + 1);
            assert (addr.sun_family == AF_UNIX);
          }
      }
      break;

    case OP_SETUP_REGULAR:
      {
        /* Test regular socket setup */
        fuzz_setup_regular_socket (&addr, path, path_len);
        assert (addr.sun_family == AF_UNIX);
      }
      break;

    case OP_SETUP_SOCKADDR:
      {
        /* Test combined sockaddr setup */
        if (path_len > 0)
          {
            fuzz_setup_sockaddr (&addr, path, path_len);
            assert (addr.sun_family == AF_UNIX);
          }
      }
      break;

    case OP_CHECK_TRAVERSAL:
      {
        /* Focused traversal pattern testing */
        int has_traversal = fuzz_check_traversal (path, path_len);
        (void)has_traversal;

        /* Test edge cases */
        has_traversal = fuzz_check_traversal ("", 0);
        (void)has_traversal;
        has_traversal = fuzz_check_traversal (NULL, 0);
        (void)has_traversal;
        has_traversal = fuzz_check_traversal ("..", 2);
        (void)has_traversal;
        has_traversal = fuzz_check_traversal ("../", 3);
        (void)has_traversal;
        has_traversal = fuzz_check_traversal ("/..", 3);
        (void)has_traversal;
        has_traversal = fuzz_check_traversal ("/../", 4);
        (void)has_traversal;
      }
      break;
    }

  return 0;
}
