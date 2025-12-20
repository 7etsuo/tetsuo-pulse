---
name: platform
description: Platform-specific backend development for epoll, kqueue, and poll abstractions. Use when working on SocketPoll backends, adding new platform support, or files in src/poll/SocketPoll_*.c.
---

You are an expert C developer specializing in cross-platform I/O multiplexing using epoll (Linux), kqueue (BSD/macOS), and poll (POSIX fallback).

## Backend Architecture

```
SocketPoll_T (abstract interface)
    │
    ├── SocketPoll_epoll.c   (Linux)
    │   └── epoll_create1(), epoll_ctl(), epoll_wait()
    │
    ├── SocketPoll_kqueue.c  (BSD/macOS)
    │   └── kqueue(), kevent()
    │
    └── SocketPoll_poll.c    (POSIX fallback)
        └── poll()

Build-time selection via CMake:
    Linux   → HAVE_EPOLL=1
    BSD     → HAVE_KQUEUE=1
    Other   → poll fallback
```

## Abstract Interface

All backends implement this interface:

```c
// include/poll/SocketPoll.h

// Event flags (unified across backends)
#define POLL_READ   0x01
#define POLL_WRITE  0x02
#define POLL_ERROR  0x04
#define POLL_HANGUP 0x08

typedef struct SocketEvent {
    int fd;
    int events;       // POLL_READ | POLL_WRITE | ...
    void *data;       // User data
} SocketEvent_T;

// Core operations
SocketPoll_T SocketPoll_new(int max_events);
void         SocketPoll_free(SocketPoll_T *poll);
int          SocketPoll_add(SocketPoll_T poll, int fd, int events, void *data);
int          SocketPoll_mod(SocketPoll_T poll, int fd, int events, void *data);
int          SocketPoll_del(SocketPoll_T poll, int fd);
int          SocketPoll_wait(SocketPoll_T poll, SocketEvent_T **events, int timeout_ms);
const char * SocketPoll_get_backend_name(SocketPoll_T poll);
```

## epoll Backend (Linux)

```c
// src/poll/SocketPoll_epoll.c

struct SocketPoll {
    int epfd;                    // epoll file descriptor
    struct epoll_event *events;  // Event buffer
    int max_events;
    HashTable_T fd_data;         // fd -> userdata mapping
    pthread_mutex_t mutex;
};

SocketPoll_T SocketPoll_new(int max_events) {
    SocketPoll_T poll = ALLOC(arena, sizeof(*poll));

    // EPOLL_CLOEXEC prevents fd leak to child processes
    poll->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (poll->epfd < 0) {
        RAISE(Socket_Failed);
    }

    poll->events = CALLOC(arena, max_events, sizeof(struct epoll_event));
    poll->max_events = max_events;
    poll->fd_data = HashTable_new(arena, max_events * 2);

    return poll;
}

int SocketPoll_add(SocketPoll_T poll, int fd, int events, void *data) {
    struct epoll_event ev = {0};

    // Translate unified flags to epoll flags
    if (events & POLL_READ)  ev.events |= EPOLLIN;
    if (events & POLL_WRITE) ev.events |= EPOLLOUT;
    ev.events |= EPOLLET;  // Edge-triggered mode
    ev.data.fd = fd;

    // Store userdata mapping
    HashTable_put(poll->fd_data, fd, data);

    return epoll_ctl(poll->epfd, EPOLL_CTL_ADD, fd, &ev);
}

int SocketPoll_wait(SocketPoll_T poll, SocketEvent_T **events_out, int timeout_ms) {
    int n = epoll_wait(poll->epfd, poll->events, poll->max_events, timeout_ms);

    // Translate epoll events to unified format
    for (int i = 0; i < n; i++) {
        poll->unified_events[i].fd = poll->events[i].data.fd;
        poll->unified_events[i].events = 0;

        if (poll->events[i].events & EPOLLIN)  poll->unified_events[i].events |= POLL_READ;
        if (poll->events[i].events & EPOLLOUT) poll->unified_events[i].events |= POLL_WRITE;
        if (poll->events[i].events & EPOLLERR) poll->unified_events[i].events |= POLL_ERROR;
        if (poll->events[i].events & EPOLLHUP) poll->unified_events[i].events |= POLL_HANGUP;

        poll->unified_events[i].data = HashTable_get(poll->fd_data,
                                                      poll->events[i].data.fd);
    }

    *events_out = poll->unified_events;
    return n;
}
```

## kqueue Backend (BSD/macOS)

```c
// src/poll/SocketPoll_kqueue.c

struct SocketPoll {
    int kq;                       // kqueue descriptor
    struct kevent *events;        // Event buffer
    struct kevent *changes;       // Pending changes
    int max_events;
    int num_changes;
    HashTable_T fd_data;
    pthread_mutex_t mutex;
};

SocketPoll_T SocketPoll_new(int max_events) {
    SocketPoll_T poll = ALLOC(arena, sizeof(*poll));

    poll->kq = kqueue();
    if (poll->kq < 0) {
        RAISE(Socket_Failed);
    }

    poll->events = CALLOC(arena, max_events, sizeof(struct kevent));
    poll->changes = CALLOC(arena, max_events * 2, sizeof(struct kevent));

    return poll;
}

int SocketPoll_add(SocketPoll_T poll, int fd, int events, void *data) {
    // kqueue uses separate filters for read/write
    if (events & POLL_READ) {
        EV_SET(&poll->changes[poll->num_changes++], fd, EVFILT_READ,
               EV_ADD | EV_CLEAR, 0, 0, data);
    }
    if (events & POLL_WRITE) {
        EV_SET(&poll->changes[poll->num_changes++], fd, EVFILT_WRITE,
               EV_ADD | EV_CLEAR, 0, 0, data);
    }

    HashTable_put(poll->fd_data, fd, data);
    return 0;
}

int SocketPoll_wait(SocketPoll_T poll, SocketEvent_T **events_out, int timeout_ms) {
    struct timespec ts = {
        .tv_sec = timeout_ms / 1000,
        .tv_nsec = (timeout_ms % 1000) * 1000000
    };

    // Submit changes and wait
    int n = kevent(poll->kq, poll->changes, poll->num_changes,
                   poll->events, poll->max_events,
                   timeout_ms >= 0 ? &ts : NULL);
    poll->num_changes = 0;  // Changes consumed

    // Translate to unified format
    // Note: kqueue returns separate events for read/write
    for (int i = 0; i < n; i++) {
        poll->unified_events[i].fd = poll->events[i].ident;
        poll->unified_events[i].data = poll->events[i].udata;
        poll->unified_events[i].events = 0;

        if (poll->events[i].filter == EVFILT_READ)
            poll->unified_events[i].events |= POLL_READ;
        if (poll->events[i].filter == EVFILT_WRITE)
            poll->unified_events[i].events |= POLL_WRITE;
        if (poll->events[i].flags & EV_ERROR)
            poll->unified_events[i].events |= POLL_ERROR;
        if (poll->events[i].flags & EV_EOF)
            poll->unified_events[i].events |= POLL_HANGUP;
    }

    *events_out = poll->unified_events;
    return n;
}
```

## poll Backend (POSIX Fallback)

```c
// src/poll/SocketPoll_poll.c

struct SocketPoll {
    struct pollfd *fds;
    void **userdata;
    int capacity;
    int count;
    pthread_mutex_t mutex;
};

int SocketPoll_add(SocketPoll_T poll, int fd, int events, void *data) {
    // O(n) add - find empty slot or append
    int slot = find_empty_slot(poll);
    if (slot < 0) return -1;

    poll->fds[slot].fd = fd;
    poll->fds[slot].events = 0;
    if (events & POLL_READ)  poll->fds[slot].events |= POLLIN;
    if (events & POLL_WRITE) poll->fds[slot].events |= POLLOUT;
    poll->userdata[slot] = data;

    return 0;
}

int SocketPoll_wait(SocketPoll_T poll, SocketEvent_T **events_out, int timeout_ms) {
    int n = poll(poll->fds, poll->count, timeout_ms);
    if (n <= 0) return n;

    // Translate and compact results
    int result_count = 0;
    for (int i = 0; i < poll->count && result_count < n; i++) {
        if (poll->fds[i].revents == 0) continue;

        poll->unified_events[result_count].fd = poll->fds[i].fd;
        poll->unified_events[result_count].data = poll->userdata[i];
        poll->unified_events[result_count].events = 0;

        if (poll->fds[i].revents & POLLIN)
            poll->unified_events[result_count].events |= POLL_READ;
        if (poll->fds[i].revents & POLLOUT)
            poll->unified_events[result_count].events |= POLL_WRITE;
        if (poll->fds[i].revents & POLLERR)
            poll->unified_events[result_count].events |= POLL_ERROR;
        if (poll->fds[i].revents & POLLHUP)
            poll->unified_events[result_count].events |= POLL_HANGUP;

        result_count++;
    }

    *events_out = poll->unified_events;
    return result_count;
}
```

## Edge-Triggered vs Level-Triggered

```c
// Edge-triggered (epoll EPOLLET, kqueue EV_CLEAR)
// - Only notifies on state CHANGE
// - Must drain all data or you miss events
// - More efficient, fewer syscalls

// Level-triggered (default poll behavior)
// - Notifies while condition is true
// - Simpler to program
// - More syscalls for busy sockets

// This library uses edge-triggered for epoll/kqueue
// Application pattern for edge-triggered:
while (true) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;  // Drained, wait for next event
        }
        // Real error
        handle_error();
        break;
    }
    if (n == 0) {
        // Connection closed
        handle_close();
        break;
    }
    process_data(buf, n);
}
```

## Adding a New Backend

To add support for a new platform:

1. **Create backend file**: `src/poll/SocketPoll_newplatform.c`

2. **Implement all interface functions**:
```c
SocketPoll_T SocketPoll_new(int max_events);
void         SocketPoll_free(SocketPoll_T *poll);
int          SocketPoll_add(SocketPoll_T poll, int fd, int events, void *data);
int          SocketPoll_mod(SocketPoll_T poll, int fd, int events, void *data);
int          SocketPoll_del(SocketPoll_T poll, int fd);
int          SocketPoll_wait(SocketPoll_T poll, SocketEvent_T **events, int timeout_ms);
const char * SocketPoll_get_backend_name(SocketPoll_T poll);
```

3. **Update CMakeLists.txt**:
```cmake
if(HAVE_NEWPLATFORM)
    list(APPEND POLL_SOURCES src/poll/SocketPoll_newplatform.c)
    add_definitions(-DHAVE_NEWPLATFORM)
endif()
```

4. **Add detection in cmake**:
```cmake
check_function_exists(newplatform_wait HAVE_NEWPLATFORM)
```

## Thread Safety

```c
// SocketPoll_T operations are thread-safe via mutex
// Safe patterns:
//   - Multiple threads can call SocketPoll_wait() (but only one blocks)
//   - add/mod/del can be called from any thread

// Recommended pattern:
//   - One thread owns SocketPoll_wait() loop
//   - Other threads use add/mod/del to register/modify
//   - Wake sleeping thread via SocketPoll_wakeup()

int SocketPoll_wakeup(SocketPoll_T poll) {
    // Write to internal eventfd/pipe
    uint64_t val = 1;
    return write(poll->wakeup_fd, &val, sizeof(val));
}
```

## Files Reference

| File | Purpose |
|------|---------|
| `include/poll/SocketPoll.h` | Abstract interface |
| `include/poll/SocketPoll_backend.h` | Backend-specific declarations |
| `src/poll/SocketPoll_epoll.c` | Linux epoll backend |
| `src/poll/SocketPoll_kqueue.c` | BSD/macOS kqueue backend |
| `src/poll/SocketPoll_poll.c` | POSIX poll fallback |
| `src/test/test_poll.c` | Backend tests |
