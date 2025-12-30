/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Reference: POSIX.1-2008, sendmsg/recvmsg with SCM_RIGHTS
 *
 * THREAD-SAFETY NOTE (CWE-367: TOCTOU):
 * The FD validation functions (validate_fd_open, validate_fd_array_nonclosing,
 * validate_fd_array_closing) check file descriptor validity using fcntl(F_GETFD).
 * However, there is an inherent Time-Of-Check to Time-Of-Use (TOCTOU) race
 * condition where an FD could be closed by another thread between validation
 * and actual use in sendmsg()/recvmsg().
 *
 * MITIGATION:
 * This limitation is documented in the public API (Socket.h). Callers MUST
 * ensure that file descriptors are not concurrently closed during FD passing
 * operations. This is a fundamental limitation of the FD passing API design
 * and cannot be fully eliminated without application-level synchronization.
 *
 * IMPACT: Low likelihood (requires concurrent FD operations), medium consequence
 * (sendmsg may fail with EBADF or pass closed FD to peer).
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* SCM_RIGHTS requires at least 1 byte of data to be sent */
#define FD_PASS_DUMMY_BYTE '\x00'

SOCKET_DECLARE_MODULE_EXCEPTION (SocketFD);

/* SCM_RIGHTS only works with Unix domain sockets */
static int
validate_unix_socket (const T socket)
{
        int domain;

        if (!socket || !socket->base)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "NULL socket passed to FD passing function");

        domain = SocketBase_domain (socket->base);
        if (domain != AF_UNIX)
                SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                  "FD passing requires Unix domain socket "
                                  "(AF_UNIX), got domain=%d",
                                  domain);

        return 1;
}

/*
 * TOCTOU WARNING: This check is inherently racy. FD could be closed by another
 * thread immediately after this function returns true but before sendmsg() is
 * called. Callers must ensure FD lifecycle synchronization at application level.
 */
static int
validate_fd_open (int fd)
{
        return (fd >= 0 && fcntl (fd, F_GETFD) >= 0);
}

/*
 * Validate FD array before sending. Note: TOCTOU race exists between this
 * check and sendmsg() - see file header for details.
 */
static int
validate_fd_array_nonclosing (const int *fds, size_t count, const char *context)
{
        size_t i;

        if (!fds)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "NULL fds array passed to FD passing function");

        if (count == 0)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "FD count must be at least 1");

        if (count > SOCKET_MAX_FDS_PER_MSG)
                SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                  "%s: FD count %zu exceeds maximum %d", context, count,
                                  SOCKET_MAX_FDS_PER_MSG);

        for (i = 0; i < count; i++)
        {
                if (fds[i] < 0)
                        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                          "%s: Invalid file descriptor at index "
                                          "%zu: fd=%d",
                                          context, i, fds[i]);

                if (!validate_fd_open (fds[i]))
                        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                          "%s: File descriptor is not open at "
                                          "index %zu: fd=%d",
                                          context, i, fds[i]);
        }

        return 1;
}

static void
close_received_fds (int *fds, size_t count)
{
        size_t i;

        for (i = 0; i < count; i++)
        {
                if (fds[i] >= 0)
                {
                        SAFE_CLOSE (fds[i]);
                        fds[i] = -1;
                }
        }
}

static void
setup_fd_msg_data (struct msghdr *msg, struct iovec *iov)
{
        memset (msg, 0, sizeof (*msg));
        msg->msg_iov = iov;
        msg->msg_iovlen = 1;
}

static void
setup_cmsg_buf (char *buf, size_t buf_size, size_t controllen, struct msghdr *msg)
{
        memset (buf, 0, buf_size);
        msg->msg_control = buf;
        msg->msg_controllen = controllen;
}

static void
build_rights_cmsg (struct cmsghdr *cmsg, size_t data_len, const int *fds)
{
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN (data_len);
        memcpy (CMSG_DATA (cmsg), fds, data_len);
}

static int
handle_fdmsg_error (ssize_t result, int is_recv, const char *op_name, size_t count)
{
        if (result < 0)
        {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                        return 0;
                if (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN)
                        RAISE (Socket_Closed);
                if (count > 0)
                {
                        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                          "%s with SCM_RIGHTS failed (errno=%d, count=%zu)",
                                          op_name, errno, count);
                }
                else
                {
                        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                          "%s for SCM_RIGHTS failed (errno=%d)",
                                          op_name, errno);
                }
        }
        else if (is_recv && result == 0)
        {
                RAISE (Socket_Closed);
        }
        return 1;
}

static int
validate_cmsg_data_len (const struct cmsghdr *cmsg)
{
        size_t data_len;

        if (cmsg->cmsg_len < CMSG_LEN (0))
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "Invalid SCM_RIGHTS cmsg_len too small");

        data_len = cmsg->cmsg_len - CMSG_LEN (0);
        if (data_len % sizeof (int) != 0)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "Invalid SCM_RIGHTS data_len not multiple "
                                  "of sizeof(int)");

        return 1;
}

/*
 * Validate received FDs. Note: TOCTOU race exists - an FD received from peer
 * could theoretically be closed by another thread before validation completes,
 * though this is extremely unlikely in practice as FDs are just received.
 */
static void
validate_fd_array_closing (int *fds, size_t *received_count, size_t count, const char *context)
{
        size_t i;

        for (i = 0; i < count; i++)
        {
                if (fds[i] < 0)
                {
                        close_received_fds (fds, count);
                        *received_count = 0;
                        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                          "%s: Received invalid FD (<0) at index %zu",
                                          context, i);
                }
                if (!validate_fd_open (fds[i]))
                {
                        close_received_fds (fds, count);
                        *received_count = 0;
                        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                          "%s: Received invalid FD (not open) at "
                                          "index %zu",
                                          context, i);
                }
        }
}

static size_t
process_single_cmsg (const struct cmsghdr *cmsg, int *temp_fds,
                     size_t *total_fds, size_t max_temp)
{
        size_t data_len;
        size_t this_num_fds;
        size_t space_left;
        size_t to_copy;
        int *cmsg_fds;

        validate_cmsg_data_len (cmsg);

        data_len = cmsg->cmsg_len - CMSG_LEN (0);
        this_num_fds = data_len / sizeof (int);

        if (this_num_fds == 0)
                return 0;

        if (this_num_fds > SOCKET_MAX_FDS_PER_MSG)
        {
                cmsg_fds = (int *)CMSG_DATA (cmsg);
                close_received_fds (cmsg_fds, SOCKET_MAX_FDS_PER_MSG);
                SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                  "SCM_RIGHTS cmsg has too many fds (%zu > %d)",
                                  this_num_fds, SOCKET_MAX_FDS_PER_MSG);
        }

        cmsg_fds = (int *)CMSG_DATA (cmsg);
        space_left = max_temp - *total_fds;
        to_copy = (this_num_fds < space_left) ? this_num_fds : space_left;

        if (to_copy > 0)
        {
                memcpy (temp_fds + *total_fds, cmsg_fds, to_copy * sizeof (int));
                *total_fds += to_copy;
        }

        /* Close excess FDs that don't fit in temp buffer */
        if (this_num_fds > to_copy)
                close_received_fds (cmsg_fds + to_copy, this_num_fds - to_copy);

        return to_copy;
}

static size_t
extract_rights_fds (const struct msghdr *msg, int *fds, size_t max_count)
{
        struct cmsghdr *cmsg;
        int temp_fds[SOCKET_MAX_FDS_PER_MSG];
        size_t total_fds = 0;
        size_t validated_count;
        size_t i;

        memset (temp_fds, -1, sizeof (temp_fds));

        cmsg = CMSG_FIRSTHDR ((struct msghdr *)msg);
        while (cmsg != NULL)
        {
                if (cmsg->cmsg_level == SOL_SOCKET
                    && cmsg->cmsg_type == SCM_RIGHTS)
                {
                        process_single_cmsg (cmsg, temp_fds, &total_fds,
                                             SOCKET_MAX_FDS_PER_MSG);
                }
                cmsg = CMSG_NXTHDR ((struct msghdr *)msg, cmsg);
        }

        if (total_fds > max_count)
        {
                close_received_fds (temp_fds, total_fds);
                SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                  "Received more FDs (%zu) than buffer can "
                                  "hold (%zu)",
                                  total_fds, max_count);
        }

        validated_count = total_fds;
        validate_fd_array_closing (temp_fds, &validated_count, total_fds, "FD extraction");

        memcpy (fds, temp_fds, validated_count * sizeof (int));

        for (i = validated_count; i < max_count; i++)
                fds[i] = -1;

        return validated_count;
}

static int
socket_sendfds_internal (const T socket, const int *fds, size_t count)
{
        struct msghdr msg;
        struct iovec iov;
        char cmsg_buf[CMSG_SPACE (sizeof (int) * SOCKET_MAX_FDS_PER_MSG)];
        struct cmsghdr *cmsg;
        char dummy[1];
        size_t cmsg_data_len;
        ssize_t result;
        int fd;

        fd = SocketBase_fd (socket->base);

        dummy[0] = FD_PASS_DUMMY_BYTE;
        iov.iov_base = dummy;
        iov.iov_len = sizeof (dummy[0]);

        setup_fd_msg_data (&msg, &iov);

        cmsg_data_len = sizeof (int) * count;
        setup_cmsg_buf (cmsg_buf, sizeof (cmsg_buf), CMSG_SPACE (cmsg_data_len), &msg);

        cmsg = CMSG_FIRSTHDR (&msg);
        build_rights_cmsg (cmsg, cmsg_data_len, fds);

        result = sendmsg (fd, &msg, MSG_NOSIGNAL);
        return handle_fdmsg_error (result, 0, "sendmsg", count);
}

static int
socket_recvfds_internal (const T socket, int *fds, size_t max_count,
                         size_t *received_count)
{
        struct msghdr msg;
        struct iovec iov;
        char cmsg_buf[CMSG_SPACE (sizeof (int) * SOCKET_MAX_FDS_PER_MSG)];
        char dummy[1];
        ssize_t result;
        size_t num_fds;
        size_t i;
        int fd;

        fd = SocketBase_fd (socket->base);

        *received_count = 0;
        for (i = 0; i < max_count; i++)
                fds[i] = -1;

        dummy[0] = FD_PASS_DUMMY_BYTE;
        iov.iov_base = dummy;
        iov.iov_len = sizeof (dummy[0]);

        setup_fd_msg_data (&msg, &iov);
        setup_cmsg_buf (cmsg_buf, sizeof (cmsg_buf), sizeof (cmsg_buf), &msg);

        result = recvmsg (fd, &msg, 0);
        if (!handle_fdmsg_error (result, 1, "recvmsg", 0))
                return 0;

        if (msg.msg_flags & MSG_CTRUNC)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "Control message truncated - FD array may "
                                  "be incomplete");

        if (msg.msg_flags & MSG_TRUNC)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "FD passing message data truncated - "
                                  "unexpected extra data from peer");

        num_fds = extract_rights_fds (&msg, fds, max_count);
        *received_count = num_fds;
        return 1;
}

int
Socket_sendfd (T socket, int fd_to_pass)
{
        validate_unix_socket (socket);
        validate_fd_array_nonclosing (&fd_to_pass, 1, "Socket_sendfd");

        return socket_sendfds_internal (socket, &fd_to_pass, 1);
}

int
Socket_recvfd (T socket, int *fd_received)
{
        size_t received_count = 0;

        if (!fd_received)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "NULL fd_received pointer");

        *fd_received = -1;
        validate_unix_socket (socket);

        return socket_recvfds_internal (socket, fd_received, 1, &received_count);
}

int
Socket_sendfds (T socket, const int *fds, size_t count)
{
        validate_unix_socket (socket);
        validate_fd_array_nonclosing (fds, count, "Socket_sendfds");

        return socket_sendfds_internal (socket, fds, count);
}

int
Socket_recvfds (T socket, int *fds, size_t max_count, size_t *received_count)
{
        if (!fds)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "NULL fds array pointer");

        if (!received_count)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "NULL received_count pointer");

        if (max_count == 0)
                SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                                  "max_count must be at least 1");

        if (max_count > SOCKET_MAX_FDS_PER_MSG)
                SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                  "max_count %zu exceeds maximum %d", max_count,
                                  SOCKET_MAX_FDS_PER_MSG);

        validate_unix_socket (socket);

        return socket_recvfds_internal (socket, fds, max_count, received_count);
}

#undef T
