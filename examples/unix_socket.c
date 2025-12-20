/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * unix_socket.c - Unix Domain Socket with File Descriptor Passing Example
 *
 * Demonstrates Unix domain sockets and advanced IPC features:
 * - Creating Unix domain socket server that binds to a filesystem path
 * - Client connecting to Unix socket
 * - Passing file descriptors between processes using SCM_RIGHTS
 * - Receiving file descriptors on the other end
 * - Getting peer credentials (UID/GID/PID) on Linux
 * - Proper cleanup of socket files
 *
 * This example uses fork() to demonstrate both server and client in one
 * program.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_unix_socket
 *
 * Usage:
 *   ./example_unix_socket [socket_path]
 *   ./example_unix_socket /tmp/test.sock
 *
 * Features demonstrated:
 * - AF_UNIX socket creation with SOCK_STREAM
 * - Manual bind to filesystem path using sockaddr_un
 * - File descriptor passing via sendmsg/recvmsg with SCM_RIGHTS
 * - Peer credential retrieval with SO_PEERCRED (Linux)
 * - Fork-based client/server demonstration
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "core/Except.h"
#include "socket/Socket.h"

/* Default Unix socket path */
#define DEFAULT_SOCKET_PATH "/tmp/socket_example.sock"

/* Test file to pass between processes */
#define TEST_FILE_PATH "/tmp/socket_test_file.txt"
#define TEST_FILE_CONTENT                                                     \
  "Hello from the parent process via file descriptor passing!"

/* Helper function to send a file descriptor over a Unix socket */
static int
send_fd (Socket_T sock, int fd_to_send)
{
  struct msghdr msg = { 0 };
  struct iovec iov[1];
  char ctrl_buf[CMSG_SPACE (sizeof (int))];
  char data_buf[1] = { 'X' }; /* Dummy data, required by some systems */

  /* Setup the message */
  iov[0].iov_base = data_buf;
  iov[0].iov_len = sizeof (data_buf);

  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctrl_buf;
  msg.msg_controllen = sizeof (ctrl_buf);

  /* Setup the control message for file descriptor passing */
  struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (sizeof (int));

  /* Copy the file descriptor into the control message */
  memcpy (CMSG_DATA (cmsg), &fd_to_send, sizeof (int));

  /* Send the message */
  ssize_t n = Socket_sendmsg (sock, &msg, 0);
  return (n > 0) ? 0 : -1;
}

/* Helper function to receive a file descriptor over a Unix socket */
static int
recv_fd (Socket_T sock)
{
  struct msghdr msg = { 0 };
  struct iovec iov[1];
  char ctrl_buf[CMSG_SPACE (sizeof (int))];
  char data_buf[1];

  /* Setup the message */
  iov[0].iov_base = data_buf;
  iov[0].iov_len = sizeof (data_buf);

  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctrl_buf;
  msg.msg_controllen = sizeof (ctrl_buf);

  /* Receive the message */
  ssize_t n = Socket_recvmsg (sock, &msg, 0);
  if (n <= 0)
    return -1;

  /* Extract the file descriptor from control message */
  struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
  if (cmsg == NULL || cmsg->cmsg_len != CMSG_LEN (sizeof (int)))
    return -1;

  if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
    return -1;

  int received_fd;
  memcpy (&received_fd, CMSG_DATA (cmsg), sizeof (int));
  return received_fd;
}

/* Helper function to get peer credentials (Linux-specific) */
static int
get_peer_credentials (Socket_T sock, pid_t *pid, uid_t *uid, gid_t *gid)
{
#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof (cred);
  int fd = Socket_fd (sock);

  if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
    {
      if (pid)
        *pid = cred.pid;
      if (uid)
        *uid = cred.uid;
      if (gid)
        *gid = cred.gid;
      return 0;
    }
#else
  (void)sock;
  (void)pid;
  (void)uid;
  (void)gid;
#endif
  return -1;
}

/* Helper function to bind a socket to a Unix domain path */
static void
bind_unix_path (Socket_T sock, const char *path)
{
  struct sockaddr_un addr;
  int fd = Socket_fd (sock);

  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;

  if (strlen (path) >= sizeof (addr.sun_path))
    {
      fprintf (stderr, "[FAIL] Socket path too long: %s\n", path);
      RAISE (Socket_Failed);
    }

  strncpy (addr.sun_path, path, sizeof (addr.sun_path) - 1);

  /* Remove existing socket file if it exists */
  unlink (path);

  if (bind (fd, (struct sockaddr *)&addr, sizeof (addr)) < 0)
    {
      fprintf (stderr, "[FAIL] bind() failed: %s\n", strerror (errno));
      RAISE (Socket_Failed);
    }
}

/* Helper function to connect to a Unix domain socket */
static void
connect_unix_path (Socket_T sock, const char *path)
{
  struct sockaddr_un addr;
  int fd = Socket_fd (sock);

  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;

  if (strlen (path) >= sizeof (addr.sun_path))
    {
      fprintf (stderr, "[FAIL] Socket path too long: %s\n", path);
      RAISE (Socket_Failed);
    }

  strncpy (addr.sun_path, path, sizeof (addr.sun_path) - 1);

  if (connect (fd, (struct sockaddr *)&addr, sizeof (addr)) < 0)
    {
      fprintf (stderr, "[FAIL] connect() failed: %s\n", strerror (errno));
      RAISE (Socket_Failed);
    }
}

/* Server process: accepts connection, receives FD, reads from it */
static int
run_server (const char *socket_path)
{
  Socket_T server = NULL;
  Socket_T client = NULL;
  volatile int result = 0;

  printf ("[INFO] Server starting...\n");

  TRY
  {
    /* Create Unix domain socket */
    server = Socket_new (AF_UNIX, SOCK_STREAM, 0);
    printf ("[OK]   Created Unix domain socket (fd=%d)\n", Socket_fd (server));

    /* Bind to filesystem path */
    bind_unix_path (server, socket_path);
    printf ("[OK]   Bound to %s\n", socket_path);

    /* Listen for connections */
    Socket_listen (server, 1);
    printf ("[OK]   Listening for connections\n");

    /* Accept client connection */
    printf ("[INFO] Waiting for client...\n");
    client = Socket_accept (server);

    if (client == NULL)
      {
        fprintf (stderr, "[FAIL] accept() returned NULL\n");
        result = 1;
        goto cleanup;
      }

    printf ("[OK]   Client connected\n");

    /* Get peer credentials (Linux-specific) */
    pid_t peer_pid;
    uid_t peer_uid;
    gid_t peer_gid;

    if (get_peer_credentials (client, &peer_pid, &peer_uid, &peer_gid) == 0)
      {
        printf ("[OK]   Peer credentials: PID=%d, UID=%d, GID=%d\n", peer_pid,
                peer_uid, peer_gid);
      }
    else
      {
        printf ("[INFO] Peer credentials not available (not Linux or "
                "unsupported)\n");
      }

    /* Receive file descriptor from client */
    printf ("[INFO] Waiting to receive file descriptor...\n");
    int received_fd = recv_fd (client);

    if (received_fd < 0)
      {
        fprintf (stderr, "[FAIL] Failed to receive file descriptor\n");
        result = 1;
        goto cleanup;
      }

    printf ("[OK]   Received file descriptor: %d\n", received_fd);

    /* Read from the received file descriptor */
    char buffer[256];
    ssize_t n = read (received_fd, buffer, sizeof (buffer) - 1);

    if (n > 0)
      {
        buffer[n] = '\0';
        printf ("[OK]   Read from received FD (%zd bytes): \"%s\"\n", n,
                buffer);
      }
    else
      {
        fprintf (stderr, "[FAIL] Failed to read from received FD\n");
        result = 1;
      }

    /* Close the received file descriptor */
    close (received_fd);

    /* Send confirmation back to client */
    const char *response = "ACK";
    Socket_sendall (client, response, strlen (response));
    printf ("[OK]   Sent acknowledgment to client\n");
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "[FAIL] Socket error in server\n");
    result = 1;
  }
  END_TRY;

cleanup:
  if (client)
    Socket_free (&client);
  if (server)
    Socket_free (&server);

  /* Clean up socket file */
  unlink (socket_path);
  printf ("[INFO] Server shutting down\n");

  return result;
}

/* Client process: connects, passes FD to server */
static int
run_client (const char *socket_path)
{
  Socket_T client = NULL;
  volatile int test_fd = -1;
  volatile int result = 0;

  /* Give server time to start */
  sleep (1);

  printf ("[INFO] Client starting...\n");

  TRY
  {
    /* Create test file to pass */
    test_fd = open (TEST_FILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (test_fd < 0)
      {
        fprintf (stderr, "[FAIL] Failed to create test file: %s\n",
                 strerror (errno));
        result = 1;
        goto cleanup;
      }

    /* Write test content */
    if (write (test_fd, TEST_FILE_CONTENT, strlen (TEST_FILE_CONTENT)) < 0)
      {
        fprintf (stderr, "[FAIL] Failed to write test file: %s\n",
                 strerror (errno));
        result = 1;
        goto cleanup;
      }

    /* Reset file position to beginning */
    lseek (test_fd, 0, SEEK_SET);
    printf ("[OK]   Created test file: %s (fd=%d)\n", TEST_FILE_PATH, test_fd);

    /* Create Unix domain socket */
    client = Socket_new (AF_UNIX, SOCK_STREAM, 0);
    printf ("[OK]   Created Unix domain socket (fd=%d)\n", Socket_fd (client));

    /* Connect to server */
    connect_unix_path (client, socket_path);
    printf ("[OK]   Connected to server at %s\n", socket_path);

    /* Pass the file descriptor to server */
    printf ("[INFO] Sending file descriptor %d to server...\n", test_fd);
    if (send_fd (client, test_fd) < 0)
      {
        fprintf (stderr, "[FAIL] Failed to send file descriptor\n");
        result = 1;
        goto cleanup;
      }

    printf ("[OK]   File descriptor sent successfully\n");

    /* Wait for acknowledgment */
    char ack_buffer[10];
    ssize_t n = Socket_recv (client, ack_buffer, sizeof (ack_buffer) - 1);

    if (n > 0)
      {
        ack_buffer[n] = '\0';
        printf ("[OK]   Received acknowledgment: \"%s\"\n", ack_buffer);
      }
    else
      {
        fprintf (stderr, "[FAIL] Failed to receive acknowledgment\n");
        result = 1;
      }
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "[FAIL] Socket error in client\n");
    result = 1;
  }
  END_TRY;

cleanup:
  if (test_fd >= 0)
    close (test_fd);
  if (client)
    Socket_free (&client);

  /* Clean up test file */
  unlink (TEST_FILE_PATH);
  printf ("[INFO] Client shutting down\n");

  return result;
}

int
main (int argc, char **argv)
{
  const char *socket_path = DEFAULT_SOCKET_PATH;
  pid_t pid;
  int status;
  int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    socket_path = argv[1];

  /* Setup signal handling */
  signal (SIGPIPE, SIG_IGN);

  printf ("Unix Domain Socket Example\n");
  printf ("==========================\n\n");
  printf ("Socket path: %s\n", socket_path);
  printf ("Test file: %s\n\n", TEST_FILE_PATH);

  /* Fork to create client and server processes */
  pid = fork ();

  if (pid < 0)
    {
      fprintf (stderr, "[FAIL] fork() failed: %s\n", strerror (errno));
      return 1;
    }
  else if (pid == 0)
    {
      /* Child process - run client */
      result = run_client (socket_path);
      exit (result);
    }
  else
    {
      /* Parent process - run server */
      result = run_server (socket_path);

      /* Wait for child to complete */
      waitpid (pid, &status, 0);

      if (WIFEXITED (status) && WEXITSTATUS (status) != 0)
        {
          fprintf (stderr, "[FAIL] Client process failed with exit code %d\n",
                   WEXITSTATUS (status));
          result = 1;
        }
    }

  printf ("\n");
  if (result == 0)
    {
      printf ("[OK]   All tests passed!\n");
      printf ("\nDemonstrated features:\n");
      printf ("  - Unix domain socket creation (AF_UNIX)\n");
      printf ("  - Binding to filesystem path\n");
      printf ("  - File descriptor passing via SCM_RIGHTS\n");
#ifdef SO_PEERCRED
      printf ("  - Peer credential retrieval (SO_PEERCRED)\n");
#endif
      printf ("  - Bidirectional communication\n");
      printf ("  - Proper cleanup of socket files\n");
    }
  else
    {
      printf ("[FAIL] Tests failed\n");
    }

  return result;
}
