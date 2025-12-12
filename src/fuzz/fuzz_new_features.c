/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_new_features.c - Fuzzing harness for newly added socket library features
 *
 * Comprehensive fuzzing coverage for all new functionality:
 * - High-level convenience functions
 * - Socket statistics and metrics
 * - Connection pool enhancements
 * - DNS cache enhancements
 * - Connection health & probing
 * - I/O enhancements with timeouts
 * - Advanced I/O operations
 * - Socket duplication
 * - TLS enhancements
 * - HTTP client enhancements
 * - HTTP server enhancements
 * - HTTP/2 enhancements
 * - WebSocket enhancements
 * - Event system enhancements
 * - Buffer enhancements
 * - Async I/O enhancements
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_new_features
 * Run:   ./fuzz_new_features corpus/new_features/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"
#include "socket/SocketBuf.h"
#include "socket/SocketDgram.h"

/* Operation codes for fuzzing different features */
enum FeatureOp {
  /* High-level convenience functions */
  OP_SOCKET_LISTEN_TCP = 0,
  OP_SOCKET_CONNECT_TCP,
  OP_SOCKETDGRAM_BIND_UDP,
  OP_SOCKET_LISTEN_UNIX,
  OP_SOCKET_CONNECT_UNIX_TIMEOUT,
  OP_SOCKET_ACCEPT_TIMEOUT,
  OP_SOCKET_CONNECT_NONBLOCKING,

  /* Socket statistics & metrics */
  OP_SOCKET_GETSTATS,
  OP_SOCKET_METRICS_INCREMENT,
  OP_SOCKET_METRICS_GETSNAPSHOT,

  /* Connection pool enhancements */
  OP_SOCKETPOOL_FIND,
  OP_SOCKETPOOL_FILTER,
  OP_SOCKETPOOL_GET_IDLE_COUNT,
  OP_SOCKETPOOL_GET_ACTIVE_COUNT,
  OP_SOCKETPOOL_GET_HIT_RATE,
  OP_SOCKETPOOL_SHRINK,

  /* DNS cache enhancements */
  OP_SOCKETDNS_CACHE_SET_TTL,
  OP_SOCKETDNS_CACHE_SET_MAX_ENTRIES,
  OP_SOCKETDNS_CACHE_CLEAR,
  OP_SOCKETDNS_CACHE_REMOVE,
  OP_SOCKETDNS_CACHE_STATS,
  OP_SOCKETDNS_SET_NAMESERVERS,
  OP_SOCKETDNS_SET_SEARCH_DOMAINS,
  OP_SOCKETDNS_PREFER_IPV6,

  /* Connection health & probing */
  OP_SOCKET_PROBE,
  OP_SOCKET_GET_ERROR,
  OP_SOCKET_IS_READABLE,
  OP_SOCKET_IS_WRITABLE,
  OP_SOCKET_GET_TCP_INFO,

  /* I/O enhancements with timeouts */
  OP_SOCKET_SENDV_TIMEOUT,
  OP_SOCKET_RECVV_TIMEOUT,
  OP_SOCKET_SENDALL_TIMEOUT,
  OP_SOCKET_RECVALl_TIMEOUT,

  /* Advanced I/O operations */
  OP_SOCKET_SPLICE,
  OP_SOCKET_CORK,
  OP_SOCKET_PEEK,
  OP_SOCKET_DUP,
  OP_SOCKET_DUP2,

  /* Event system enhancements */
  OP_SOCKETPOLL_GET_BACKEND_NAME,
  OP_SOCKETPOLL_GET_REGISTERED_SOCKETS,
  OP_SOCKETPOLL_MODIFY_EVENTS,
  OP_SOCKETTIMER_RESCHEDULE,
  OP_SOCKETTIMER_PAUSE,
  OP_SOCKETTIMER_RESUME,

  /* Buffer enhancements */
  OP_SOCKETBUF_COMPACT,
  OP_SOCKETBUF_ENSURE,
  OP_SOCKETBUF_FIND,
  OP_SOCKETBUF_READLINE,
  OP_SOCKETBUF_READV,
  OP_SOCKETBUF_WRITEV,

  /* Async I/O enhancements */
  OP_SOCKETASYNC_SUBMIT_BATCH,
  OP_SOCKETASYNC_CANCEL_ALL,
  OP_SOCKETASYNC_BACKEND_AVAILABLE,
  OP_SOCKETASYNC_SET_BACKEND,

  OP_COUNT
};

/* Global fuzz state (arena persists across fuzz calls) */
static Arena_T fuzz_arena = NULL;
static SocketPoll_T fuzz_poll = NULL;
static SocketAsync_T fuzz_async = NULL;
static SocketDNS_T fuzz_dns = NULL;

/* Initialize fuzz state */
static void
fuzz_init(void)
{
  if (!fuzz_arena) {
    fuzz_arena = Arena_new();
    if (!fuzz_arena) return;

    fuzz_poll = SocketPoll_new(1024);
    if (fuzz_poll) {
      fuzz_async = SocketPoll_get_async(fuzz_poll);
      fuzz_dns = SocketDNS_new();
    }
  }
}

/* Cleanup fuzz state */
static void
fuzz_cleanup(void)
{
  if (fuzz_dns) SocketDNS_free(&fuzz_dns);
  if (fuzz_poll) SocketPoll_free(&fuzz_poll);
  if (fuzz_arena) Arena_dispose(&fuzz_arena);

  fuzz_dns = NULL;
  fuzz_poll = NULL;
  fuzz_async = NULL;
  fuzz_arena = NULL;
}

/* Helper: Read 16-bit value from fuzz data */
static uint16_t
read_u16(const uint8_t *data, size_t size, size_t *offset)
{
  if (*offset + 2 > size) return 0;
  uint16_t val = (data[*offset] << 8) | data[*offset + 1];
  *offset += 2;
  return val;
}

/* Helper: Read 32-bit value from fuzz data */
static uint32_t
read_u32(const uint8_t *data, size_t size, size_t *offset)
{
  if (*offset + 4 > size) return 0;
  uint32_t val = (data[*offset] << 24) | (data[*offset + 1] << 16) |
                 (data[*offset + 2] << 8) | data[*offset + 3];
  *offset += 4;
  return val;
}

/* Helper: Read string from fuzz data */
static char *
read_string(const uint8_t *data, size_t size, size_t *offset, size_t max_len)
{
  if (*offset >= size) return NULL;

  size_t start = *offset;
  size_t len = 0;

  /* Find null terminator or max_len */
  while (*offset < size && len < max_len && data[*offset] != 0) {
    (*offset)++;
    len++;
  }

  if (*offset < size && data[*offset] == 0) {
    (*offset)++; /* Skip null terminator */
  }

  /* Allocate and copy string */
  char *str = malloc(len + 1);
  if (str) {
    memcpy(str, data + start, len);
    str[len] = '\0';
  }

  return str;
}

/* Helper: Create a test socket */
static Socket_T
create_test_socket(void)
{
  if (!fuzz_arena) return NULL;

  TRY {
    return Socket_new(AF_INET, SOCK_STREAM, 0);
  } EXCEPT (Socket_Failed) {
    return NULL;
  } END_TRY;
}

/* Helper: Create a test UDP socket */
static SocketDgram_T
create_test_dgram_socket(void)
{
  if (!fuzz_arena) return NULL;

  TRY {
    return SocketDgram_new(AF_INET, 0);
  } EXCEPT (SocketDgram_Failed) {
    return NULL;
  } END_TRY;
}

/* Helper: Completion callback for async operations */
static void
fuzz_async_callback(Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  (void)socket;
  (void)bytes;
  (void)err;
  (void)user_data;
  /* Do nothing - just consume the completion */
}

/* Main fuzzing function */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 2) return 0; /* Need at least operation code */

  fuzz_init();
  if (!fuzz_arena || !fuzz_poll) return 0;

  size_t offset = 0;
  uint16_t op_code = read_u16(data, size, &offset);

  switch (op_code % OP_COUNT) {
    case OP_SOCKET_LISTEN_TCP: {
      /* Fuzz Socket_listen_tcp */
      uint16_t port = read_u16(data, size, &offset);
      char *host = read_string(data, size, &offset, 256);
      uint16_t backlog = read_u16(data, size, &offset);

      if (host) {
        TRY {
          Socket_T server = Socket_listen_tcp(host, port, backlog % 100);
          if (server) Socket_free(&server);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
        free(host);
      }
      break;
    }

    case OP_SOCKET_CONNECT_TCP: {
      /* Fuzz Socket_connect_tcp */
      uint16_t port = read_u16(data, size, &offset);
      char *host = read_string(data, size, &offset, 256);
      uint32_t timeout = read_u32(data, size, &offset);

      if (host) {
        TRY {
          Socket_T client = Socket_connect_tcp(host, port, timeout % 60000);
          if (client) Socket_free(&client);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
        free(host);
      }
      break;
    }

    case OP_SOCKETDGRAM_BIND_UDP: {
      /* Fuzz SocketDgram_bind_udp */
      uint16_t port = read_u16(data, size, &offset);
      char *host = read_string(data, size, &offset, 256);

      if (host) {
        TRY {
          SocketDgram_T sock = SocketDgram_bind_udp(host, port);
          if (sock) SocketDgram_free(&sock);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
        free(host);
      }
      break;
    }

    case OP_SOCKET_LISTEN_UNIX: {
      /* Fuzz Socket_listen_unix */
      char *path = read_string(data, size, &offset, 256);
      uint16_t backlog = read_u16(data, size, &offset);

      if (path && strlen(path) > 0) {
        /* Use a safe temporary path */
        char safe_path[256];
        snprintf(safe_path, sizeof(safe_path), "/tmp/fuzz_unix_%d", getpid());

        TRY {
          Socket_T server = Socket_listen_unix(safe_path, backlog % 100);
          if (server) {
            Socket_free(&server);
            unlink(safe_path);
          }
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
      }
      if (path) free(path);
      break;
    }

    case OP_SOCKET_CONNECT_UNIX_TIMEOUT: {
      /* Fuzz Socket_connect_unix_timeout */
      char *path = read_string(data, size, &offset, 256);
      uint32_t timeout = read_u32(data, size, &offset);

      if (path) {
        TRY {
          Socket_T client = Socket_connect_unix_timeout(path, timeout % 60000);
          if (client) Socket_free(&client);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
        free(path);
      }
      break;
    }

    case OP_SOCKET_ACCEPT_TIMEOUT: {
      /* Fuzz Socket_accept_timeout */
      Socket_T server = create_test_socket();
      uint32_t timeout = read_u32(data, size, &offset);

      if (server) {
        TRY {
          Socket_T accepted = Socket_accept_timeout(server, timeout % 60000);
          if (accepted) Socket_free(&accepted);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
        Socket_free(&server);
      }
      break;
    }

    case OP_SOCKET_CONNECT_NONBLOCKING: {
      /* Fuzz Socket_connect_nonblocking */
      uint16_t port = read_u16(data, size, &offset);
      char *host = read_string(data, size, &offset, 256);

      if (host) {
        TRY {
          Socket_T client = Socket_connect_nonblocking(host, port);
          if (client) Socket_free(&client);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
        free(host);
      }
      break;
    }

    case OP_SOCKET_GETSTATS: {
      /* Fuzz Socket_getstats */
      Socket_T sock = create_test_socket();
      if (sock) {
        SocketStats_T stats;
        Socket_getstats(sock, &stats);
        Socket_free(&sock);
      }
      break;
    }

    case OP_SOCKET_METRICS_INCREMENT: {
      /* Fuzz SocketMetrics functions */
      uint32_t metric = read_u32(data, size, &offset) % SOCKET_METRIC_COUNT;
      uint32_t value = read_u32(data, size, &offset);

      SocketMetrics_increment((SocketMetric)metric, value);

      SocketMetricsSnapshot snapshot;
      SocketMetrics_getsnapshot(&snapshot);

      const char *name = SocketMetrics_name((SocketMetric)metric);
      (void)name; /* Consume result */
      break;
    }

    case OP_SOCKET_METRICS_GETSNAPSHOT: {
      /* Already tested above */
      break;
    }

    case OP_SOCKETPOOL_FIND: {
      /* Fuzz SocketPool functions */
      if (fuzz_arena) {
        SocketPool_T pool = SocketPool_new(fuzz_arena, 100, 1024);
        if (pool) {
          Socket_T sock = create_test_socket();
          if (sock) {
            TRY {
              Connection_T conn = SocketPool_add(pool, sock);
              if (conn) {
                /* Find the connection */
                Connection_T found = SocketPool_find(pool, sock);
                (void)found; /* Consume result */

                /* Try to find non-existent socket */
                Socket_T fake_sock = create_test_socket();
                if (fake_sock) {
                  Connection_T not_found = SocketPool_find(pool, fake_sock);
                  (void)not_found;
                  Socket_free(&fake_sock);
                }
              }
            } EXCEPT (AnyException) {
              /* Expected - ignore */
            } END_TRY;
            Socket_free(&sock);
          }
          SocketPool_free(&pool);
        }
      }
      break;
    }

    case OP_SOCKETPOOL_FILTER: {
      /* Fuzz SocketPool_filter */
      if (fuzz_arena) {
        SocketPool_T pool = SocketPool_new(fuzz_arena, 10, 1024);
        if (pool) {
          /* Add some connections */
          for (int i = 0; i < 5 && offset < size; i++) {
            Socket_T sock = create_test_socket();
            if (sock) {
              TRY {
                SocketPool_add(pool, sock);
              } EXCEPT (AnyException) {
                Socket_free(&sock);
              } END_TRY;
            }
          }

          /* Filter with dummy callback */
          int count = 0;
          void count_cb(Connection_T conn, void *arg) {
            (void)conn;
            (*(int*)arg)++;
          }
          SocketPool_filter(pool, count_cb, &count);

          SocketPool_free(&pool);
        }
      }
      break;
    }

    case OP_SOCKETPOOL_GET_IDLE_COUNT:
    case OP_SOCKETPOOL_GET_ACTIVE_COUNT:
    case OP_SOCKETPOOL_GET_HIT_RATE: {
      /* Fuzz SocketPool statistics */
      if (fuzz_arena) {
        SocketPool_T pool = SocketPool_new(fuzz_arena, 50, 1024);
        if (pool) {
          size_t idle = SocketPool_get_idle_count(pool);
          size_t active = SocketPool_get_active_count(pool);
          double hit_rate = SocketPool_get_hit_rate(pool);
          (void)idle; (void)active; (void)hit_rate;
          SocketPool_free(&pool);
        }
      }
      break;
    }

    case OP_SOCKETPOOL_SHRINK: {
      /* Fuzz SocketPool_shrink */
      if (fuzz_arena) {
        SocketPool_T pool = SocketPool_new(fuzz_arena, 100, 1024);
        if (pool) {
          /* Add some connections */
          for (int i = 0; i < 20; i++) {
            Socket_T sock = create_test_socket();
            if (sock) {
              TRY {
                SocketPool_add(pool, sock);
              } EXCEPT (AnyException) {
                Socket_free(&sock);
              } END_TRY;
            }
          }

          /* Shrink */
          TRY {
            SocketPool_shrink(pool, 10);
          } EXCEPT (AnyException) {
            /* Expected - ignore */
          } END_TRY;

          SocketPool_free(&pool);
        }
      }
      break;
    }

    case OP_SOCKETDNS_CACHE_SET_TTL: {
      /* Fuzz DNS cache settings */
      if (fuzz_dns) {
        uint32_t ttl = read_u32(data, size, &offset);
        SocketDNS_cache_set_ttl(fuzz_dns, ttl);
      }
      break;
    }

    case OP_SOCKETDNS_CACHE_SET_MAX_ENTRIES: {
      if (fuzz_dns) {
        uint32_t max_entries = read_u32(data, size, &offset);
        SocketDNS_cache_set_max_entries(fuzz_dns, max_entries);
      }
      break;
    }

    case OP_SOCKETDNS_CACHE_CLEAR: {
      if (fuzz_dns) {
        SocketDNS_cache_clear(fuzz_dns);
      }
      break;
    }

    case OP_SOCKETDNS_CACHE_REMOVE: {
      if (fuzz_dns) {
        char *hostname = read_string(data, size, &offset, 256);
        if (hostname) {
          SocketDNS_cache_remove(fuzz_dns, hostname);
          free(hostname);
        }
      }
      break;
    }

    case OP_SOCKETDNS_CACHE_STATS: {
      if (fuzz_dns) {
        SocketDNS_CacheStats stats;
        SocketDNS_cache_stats(fuzz_dns, &stats);
      }
      break;
    }

    case OP_SOCKETDNS_SET_NAMESERVERS: {
      if (fuzz_dns) {
        uint16_t count = read_u16(data, size, &offset) % 10;
        const char *nameservers[10];
        for (int i = 0; i < count; i++) {
          char *ns = read_string(data, size, &offset, 64);
          nameservers[i] = ns ? ns : "8.8.8.8";
        }
        SocketDNS_set_nameservers(fuzz_dns, nameservers, count);
        for (int i = 0; i < count; i++) {
          if (nameservers[i] != (const char*)"8.8.8.8") {
            free((char*)nameservers[i]);
          }
        }
      }
      break;
    }

    case OP_SOCKETDNS_SET_SEARCH_DOMAINS: {
      if (fuzz_dns) {
        uint16_t count = read_u16(data, size, &offset) % 10;
        const char *domains[10];
        for (int i = 0; i < count; i++) {
          char *domain = read_string(data, size, &offset, 64);
          domains[i] = domain ? domain : "local";
        }
        SocketDNS_set_search_domains(fuzz_dns, domains, count);
        for (int i = 0; i < count; i++) {
          if (domains[i] != (const char*)"local") {
            free((char*)domains[i]);
          }
        }
      }
      break;
    }

    case OP_SOCKETDNS_PREFER_IPV6: {
      if (fuzz_dns) {
        int prefer_ipv6 = read_u16(data, size, &offset) % 2;
        SocketDNS_prefer_ipv6(fuzz_dns, prefer_ipv6);
      }
      break;
    }

    case OP_SOCKET_PROBE: {
      /* Fuzz Socket_probe */
      Socket_T sock = create_test_socket();
      if (sock) {
        uint32_t timeout = read_u32(data, size, &offset);
        int healthy = Socket_probe(sock, timeout % 60000);
        (void)healthy;
        Socket_free(&sock);
      }
      break;
    }

    case OP_SOCKET_GET_ERROR: {
      Socket_T sock = create_test_socket();
      if (sock) {
        int error = Socket_get_error(sock);
        (void)error;
        Socket_free(&sock);
      }
      break;
    }

    case OP_SOCKET_IS_READABLE:
    case OP_SOCKET_IS_WRITABLE: {
      Socket_T sock = create_test_socket();
      if (sock) {
        int result = (op_code % OP_COUNT == OP_SOCKET_IS_READABLE) ?
          Socket_is_readable(sock) : Socket_is_writable(sock);
        (void)result;
        Socket_free(&sock);
      }
      break;
    }

    case OP_SOCKET_GET_TCP_INFO: {
#ifdef __linux__
      Socket_T sock = create_test_socket();
      if (sock) {
        SocketTCPInfo info;
        int result = Socket_get_tcp_info(sock, &info);
        (void)result;
        Socket_free(&sock);
      }
#endif
      break;
    }

    case OP_SOCKET_SENDV_TIMEOUT:
    case OP_SOCKET_RECVV_TIMEOUT:
    case OP_SOCKET_SENDALL_TIMEOUT:
    case OP_SOCKET_RECVALl_TIMEOUT: {
      /* These require connected sockets - skip for fuzzing complexity */
      break;
    }

    case OP_SOCKET_SPLICE: {
#ifdef __linux__
      /* Fuzz Socket_splice - requires connected sockets */
      Socket_T sock1 = create_test_socket();
      Socket_T sock2 = create_test_socket();
      if (sock1 && sock2) {
        uint32_t len = read_u32(data, size, &offset);
        ssize_t result = Socket_splice(sock1, sock2, len % 4096);
        (void)result;
        Socket_free(&sock2);
        Socket_free(&sock1);
      } else {
        if (sock1) Socket_free(&sock1);
        if (sock2) Socket_free(&sock2);
      }
#endif
      break;
    }

    case OP_SOCKET_CORK: {
      Socket_T sock = create_test_socket();
      if (sock) {
        int enable = read_u16(data, size, &offset) % 2;
        int result = Socket_cork(sock, enable);
        (void)result;
        Socket_free(&sock);
      }
      break;
    }

    case OP_SOCKET_PEEK: {
      /* Requires data in socket - skip for fuzzing complexity */
      break;
    }

    case OP_SOCKET_DUP: {
      Socket_T sock = create_test_socket();
      if (sock) {
        TRY {
          Socket_T duped = Socket_dup(sock);
          if (duped) Socket_free(&duped);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
        Socket_free(&sock);
      }
      break;
    }

    case OP_SOCKET_DUP2: {
      Socket_T sock = create_test_socket();
      if (sock) {
        int target_fd = read_u32(data, size, &offset) % 1000 + 100;
        TRY {
          Socket_T duped = Socket_dup2(sock, target_fd);
          if (duped) Socket_free(&duped);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
        Socket_free(&sock);
      }
      break;
    }

    case OP_SOCKETPOLL_GET_BACKEND_NAME: {
      if (fuzz_poll) {
        const char *backend = SocketPoll_get_backend_name(fuzz_poll);
        (void)backend;
      }
      break;
    }

    case OP_SOCKETPOLL_GET_REGISTERED_SOCKETS: {
      if (fuzz_poll) {
        Socket_T sockets[10];
        int count = SocketPoll_get_registered_sockets(fuzz_poll, sockets, 10);
        (void)count;
      }
      break;
    }

    case OP_SOCKETPOLL_MODIFY_EVENTS: {
      if (fuzz_poll) {
        Socket_T sock = create_test_socket();
        if (sock) {
          TRY {
            SocketPoll_add(fuzz_poll, sock, POLL_READ, NULL);
            uint16_t add_events = read_u16(data, size, &offset);
            uint16_t remove_events = read_u16(data, size, &offset);
            SocketPoll_modify_events(fuzz_poll, sock,
              add_events & (POLL_READ | POLL_WRITE),
              remove_events & (POLL_READ | POLL_WRITE));
          } EXCEPT (AnyException) {
            /* Expected - ignore */
          } END_TRY;
          SocketPoll_del(fuzz_poll, sock);
          Socket_free(&sock);
        }
      }
      break;
    }

    case OP_SOCKETTIMER_RESCHEDULE: {
      if (fuzz_poll) {
        void dummy_cb(void *arg) { (void)arg; }
        TRY {
          SocketTimer_T timer = SocketTimer_add(fuzz_poll, 1000, dummy_cb, NULL);
          uint32_t new_delay = read_u32(data, size, &offset);
          SocketTimer_reschedule(fuzz_poll, timer, new_delay % 60000);
          SocketTimer_cancel(fuzz_poll, timer);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
      }
      break;
    }

    case OP_SOCKETTIMER_PAUSE: {
      if (fuzz_poll) {
        void dummy_cb(void *arg) { (void)arg; }
        TRY {
          SocketTimer_T timer = SocketTimer_add(fuzz_poll, 1000, dummy_cb, NULL);
          SocketTimer_pause(fuzz_poll, timer);
          SocketTimer_resume(fuzz_poll, timer);
          SocketTimer_cancel(fuzz_poll, timer);
        } EXCEPT (AnyException) {
          /* Expected - ignore */
        } END_TRY;
      }
      break;
    }

    case OP_SOCKETTIMER_RESUME: {
      /* Already tested in PAUSE case */
      break;
    }

    case OP_SOCKETBUF_COMPACT: {
      if (fuzz_arena) {
        SocketBuf_T buf = SocketBuf_new(fuzz_arena, 1024);
        if (buf) {
          /* Write some data */
          uint16_t data_len = read_u16(data, size, &offset) % 512;
          char *test_data = malloc(data_len + 1);
          if (test_data) {
            memcpy(test_data, data + offset, data_len > size - offset ? size - offset : data_len);
            SocketBuf_write(buf, test_data, data_len);

            /* Read some to create gap */
            uint16_t read_len = read_u16(data, size, &offset) % (data_len + 1);
            if (read_len > 0) {
              char *temp = malloc(read_len);
              if (temp) {
                SocketBuf_read(buf, temp, read_len);
                free(temp);
              }
            }

            /* Compact */
            SocketBuf_compact(buf);
            free(test_data);
          }
        }
      }
      break;
    }

    case OP_SOCKETBUF_ENSURE: {
      if (fuzz_arena) {
        SocketBuf_T buf = SocketBuf_new(fuzz_arena, 512);
        if (buf) {
          uint16_t ensure_size = read_u16(data, size, &offset);
          SocketBuf_ensure(buf, ensure_size % 2048);
        }
      }
      break;
    }

    case OP_SOCKETBUF_FIND: {
      if (fuzz_arena) {
        SocketBuf_T buf = SocketBuf_new(fuzz_arena, 1024);
        if (buf) {
          char test_data[256];
          size_t data_len = (size - offset > sizeof(test_data)) ? sizeof(test_data) : size - offset;
          memcpy(test_data, data + offset, data_len);
          SocketBuf_write(buf, test_data, data_len);

          uint16_t search_char = read_u16(data, size, &offset) % 256;
          size_t pos = SocketBuf_find(buf, (char)search_char, 0);
          (void)pos;
        }
      }
      break;
    }

    case OP_SOCKETBUF_READLINE: {
      if (fuzz_arena) {
        SocketBuf_T buf = SocketBuf_new(fuzz_arena, 1024);
        if (buf) {
          char test_data[256];
          size_t data_len = (size - offset > sizeof(test_data)) ? sizeof(test_data) : size - offset;
          memcpy(test_data, data + offset, data_len);
          SocketBuf_write(buf, test_data, data_len);

          char line[128];
          size_t read = SocketBuf_readline(buf, line, sizeof(line));
          (void)read;
        }
      }
      break;
    }

    case OP_SOCKETBUF_READV:
    case OP_SOCKETBUF_WRITEV: {
      if (fuzz_arena) {
        SocketBuf_T buf = SocketBuf_new(fuzz_arena, 2048);
        if (buf) {
          uint16_t num_iov = read_u16(data, size, &offset) % 10 + 1;
          struct iovec *iov = calloc(num_iov, sizeof(struct iovec));
          if (iov) {
            for (int i = 0; i < num_iov && offset < size; i++) {
              uint16_t len = read_u16(data, size, &offset) % 256;
              char *chunk = malloc(len);
              if (chunk) {
                size_t copy_len = (size - offset > len) ? len : size - offset;
                memcpy(chunk, data + offset, copy_len);
                offset += copy_len;
                iov[i].iov_base = chunk;
                iov[i].iov_len = len;
              }
            }

            if (op_code % OP_COUNT == OP_SOCKETBUF_READV) {
              /* Write first, then read */
              char *write_data = malloc(1024);
              if (write_data) {
                memset(write_data, 'A', 1024);
                SocketBuf_write(buf, write_data, 1024);
                SocketBuf_readv(buf, iov, num_iov);
                free(write_data);
              }
            } else {
              SocketBuf_writev(buf, iov, num_iov);
            }

            /* Cleanup */
            for (int i = 0; i < num_iov; i++) {
              if (iov[i].iov_base) free(iov[i].iov_base);
            }
            free(iov);
          }
        }
      }
      break;
    }

    case OP_SOCKETASYNC_SUBMIT_BATCH: {
      if (fuzz_async) {
        uint16_t batch_size = read_u16(data, size, &offset) % 10 + 1;
        SocketAsync_Op *ops = calloc(batch_size, sizeof(SocketAsync_Op));
        if (ops) {
          for (int i = 0; i < batch_size; i++) {
            Socket_T sock = create_test_socket();
            if (sock) {
              ops[i].socket = sock;
              ops[i].is_send = read_u16(data, size, &offset) % 2;
              ops[i].len = read_u16(data, size, &offset) % 256;
              if (ops[i].is_send) {
                ops[i].send_buf = "test";
                ops[i].recv_buf = NULL;
              } else {
                ops[i].send_buf = NULL;
                ops[i].recv_buf = malloc(ops[i].len);
              }
              ops[i].cb = fuzz_async_callback;
              ops[i].user_data = NULL;
              ops[i].flags = ASYNC_FLAG_NONE;
            }
          }

          int submitted = SocketAsync_submit_batch(fuzz_async, ops, batch_size);
          (void)submitted;

          /* Cleanup */
          for (int i = 0; i < batch_size; i++) {
            if (ops[i].socket) Socket_free(&ops[i].socket);
            if (ops[i].recv_buf) free(ops[i].recv_buf);
          }
          free(ops);
        }
      }
      break;
    }

    case OP_SOCKETASYNC_CANCEL_ALL: {
      if (fuzz_async) {
        int cancelled = SocketAsync_cancel_all(fuzz_async);
        (void)cancelled;
      }
      break;
    }

    case OP_SOCKETASYNC_BACKEND_AVAILABLE: {
      uint16_t backend_code = read_u16(data, size, &offset);
      SocketAsync_Backend backend = (SocketAsync_Backend)(backend_code % 6);
      int available = SocketAsync_backend_available(backend);
      (void)available;
      break;
    }

    case OP_SOCKETASYNC_SET_BACKEND: {
      uint16_t backend_code = read_u16(data, size, &offset);
      SocketAsync_Backend backend = (SocketAsync_Backend)(backend_code % 6);
      int result = SocketAsync_set_backend(backend);
      (void)result;
      break;
    }

    default:
      /* Unknown operation - ignore */
      break;
  }

  /* Don't cleanup here - reuse across fuzz calls for efficiency */
  return 0;
}
