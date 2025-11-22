#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define RAW_PORT 8081
#define RAW_BACKLOG 1024
#define RAW_BUF_SIZE 8192

static volatile int raw_running = 1;

static void
handle_raw_connection (int epfd, int client_fd)
{
  char buf[RAW_BUF_SIZE];
  ssize_t n;

  // Read available data (non-blocking)
  n = read (client_fd, buf, sizeof (buf));
  if (n > 0)
    {
      // Echo back what we read
      ssize_t written = write (client_fd, buf, n);
      if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
          // Write error - close connection
          close (client_fd);
          epoll_ctl (epfd, EPOLL_CTL_DEL, client_fd, NULL);
          return;
        }
    }
  else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
    {
      // EOF or error - close connection
      close (client_fd);
      epoll_ctl (epfd, EPOLL_CTL_DEL, client_fd, NULL);
      return;
    }
  // If n < 0 and errno == EAGAIN, just return - more data will come later
}

int
main ()
{
  int server_fd = socket (AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr = { .sin_family = AF_INET,
                              .sin_port = htons (RAW_PORT),
                              .sin_addr.s_addr = INADDR_ANY };
  int epfd = epoll_create1 (0);
  struct epoll_event ev, events[1024];

  signal (SIGPIPE, SIG_IGN);

  bind (server_fd, (struct sockaddr *)&addr, sizeof (addr));
  listen (server_fd, RAW_BACKLOG);
  fcntl (server_fd, F_SETFL, O_NONBLOCK);

  ev.events = EPOLLIN;
  ev.data.fd = server_fd;
  epoll_ctl (epfd, EPOLL_CTL_ADD, server_fd, &ev);

  printf ("Raw epoll server on port %d\n", RAW_PORT);

  while (raw_running)
    {
      int nfds = epoll_wait (epfd, events, 1024, 100);
      for (int i = 0; i < nfds; i++)
        {
          if (events[i].data.fd == server_fd)
            {
              int client_fd = accept (server_fd, NULL, NULL);
              if (client_fd >= 0)
                {
                  fcntl (client_fd, F_SETFL, O_NONBLOCK);
                  ev.events = EPOLLIN;
                  ev.data.fd = client_fd;
                  epoll_ctl (epfd, EPOLL_CTL_ADD, client_fd, &ev);
                }
            }
          else
            {
              handle_raw_connection (epfd, events[i].data.fd);
            }
        }
    }

  close (epfd);
  close (server_fd);
  return 0;
}
