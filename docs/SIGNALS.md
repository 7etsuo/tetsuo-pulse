# Signal Handling Guide

This document describes signal handling requirements and best practices for applications using the socket library in production environments.

## Overview

The socket library is designed to be **signal-safe** with these key properties:

1. **No signal handlers installed** - The library never installs signal handlers
2. **SIGPIPE suppressed internally** - Applications don't need to handle SIGPIPE
3. **EINTR handled automatically** - Interrupted system calls are retried where appropriate
4. **Async-signal-safe design** - Library functions are NOT async-signal-safe (don't call from handlers)

## SIGPIPE Handling

### How It Works

SIGPIPE is automatically suppressed to prevent unexpected process termination when writing to a closed connection:

| Platform | Mechanism | Applied |
|----------|-----------|---------|
| Linux | `MSG_NOSIGNAL` flag | Every `send()` operation |
| FreeBSD | `MSG_NOSIGNAL` flag | Every `send()` operation |
| macOS | `SO_NOSIGPIPE` option | Socket creation time |
| Other BSD | `SO_NOSIGPIPE` option | Socket creation time |

### Application Requirements

**None.** Applications do NOT need to:
- Call `signal(SIGPIPE, SIG_IGN)`
- Install custom SIGPIPE handlers
- Use `MSG_NOSIGNAL` manually

### Optional Convenience Function

For legacy code migration or defense-in-depth, a convenience function is provided:

```c
#include "socket/Socket.h"

int main(void)
{
    /* Optional - not required when using this library */
    Socket_ignore_sigpipe();
    
    /* Rest of application */
}
```

**Warning:** Do not call `Socket_ignore_sigpipe()` if your application needs SIGPIPE for other purposes (e.g., detecting broken pipes in shell pipelines).

## EINTR Handling

The library handles `EINTR` (interrupted by signal) internally in these operations:

| Operation | Behavior |
|-----------|----------|
| `poll()` / `epoll_wait()` / `kevent()` | Returns 0 (timeout) on EINTR |
| `connect()` (non-blocking) | Continues async operation |
| `close()` | No retry (POSIX.1-2008 compliant) |
| `read()` / `write()` in loops | Retries automatically |
| Nanosleep in retry delays | Continues remaining sleep |

Applications do NOT need to wrap library calls in EINTR retry loops.

## Async-Signal-Safe Requirements

### What is Async-Signal-Safe?

A function is async-signal-safe if it can be safely called from a signal handler. Only a small subset of POSIX functions are async-signal-safe.

### Critical Rule

**Do NOT call library functions from signal handlers.**

All socket library functions are NOT async-signal-safe because they may:
- Allocate memory (`malloc()`)
- Use mutexes (`pthread_mutex_lock()`)
- Call non-reentrant functions (`strerror()`, `snprintf()`)
- Modify global state

### POSIX Async-Signal-Safe Functions (Partial List)

These functions CAN be called from signal handlers:

```c
/* I/O */
write(), read(), close(), dup(), dup2()

/* Process */
_exit(), fork(), getpid(), getppid()
kill(), raise(), abort()

/* Signal */
signal(), sigaction(), sigaddset(), sigemptyset()
sigfillset(), sigdelset(), sigismember(), sigpending()
sigprocmask(), sigsuspend()

/* File */
access(), chdir(), chmod(), chown()
creat(), fcntl(), fstat(), fsync()
link(), lseek(), mkdir(), mkfifo()
open(), rename(), rmdir(), stat()
unlink(), utime()

/* Other */
alarm(), cfgetispeed(), cfgetospeed()
cfsetispeed(), cfsetospeed(), clock_gettime()
execle(), execve(), pathconf(), pause()
pipe(), select(), sem_post(), setgid()
setpgid(), setsid(), setuid(), sleep()
sysconf(), tcdrain(), tcflow(), tcflush()
tcgetattr(), tcgetpgrp(), tcsendbreak()
tcsetattr(), tcsetpgrp(), time()
times(), umask(), uname(), wait(), waitpid()
```

### Functions NOT Async-Signal-Safe (Examples)

These functions CANNOT be called from signal handlers:

```c
/* Memory */
malloc(), free(), realloc(), calloc()

/* I/O */
printf(), fprintf(), sprintf(), snprintf()
fopen(), fclose(), fread(), fwrite()

/* Strings */
strerror(), strtok()

/* Threading */
pthread_mutex_lock(), pthread_mutex_unlock()
pthread_cond_signal(), pthread_cond_wait()

/* Most library functions */
Socket_send(), Socket_recv(), Socket_connect()
SocketPoll_wait(), SocketPool_add(), etc.
```

## Recommended Patterns

### Pattern 1: Self-Pipe Trick (Recommended)

The self-pipe trick allows async-signal-safe notification to event loops:

```c
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include "poll/SocketPoll.h"
#include "pool/SocketPool.h"

/* Global self-pipe file descriptors */
static int g_signal_pipe[2] = {-1, -1};

/**
 * Async-signal-safe signal handler
 * ONLY performs write() which is async-signal-safe
 */
static void
signal_handler(int signo)
{
    int saved_errno = errno;
    char byte = (char)signo;
    
    /* write() is async-signal-safe */
    (void)write(g_signal_pipe[1], &byte, 1);
    
    errno = saved_errno;
}

/**
 * Initialize signal handling infrastructure
 */
static int
setup_signal_handling(void)
{
    /* Create self-pipe */
    if (pipe(g_signal_pipe) < 0)
        return -1;
    
    /* Make both ends non-blocking */
    fcntl(g_signal_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(g_signal_pipe[1], F_SETFL, O_NONBLOCK);
    
    /* Set close-on-exec */
    fcntl(g_signal_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(g_signal_pipe[1], F_SETFD, FD_CLOEXEC);
    
    /* Install signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;  /* Restart interrupted syscalls */
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    
    return 0;
}

/**
 * Drain signal pipe and return received signals
 */
static int
drain_signal_pipe(void)
{
    char buf[16];
    ssize_t n;
    int signals_received = 0;
    
    while ((n = read(g_signal_pipe[0], buf, sizeof(buf))) > 0)
        signals_received += (int)n;
    
    return signals_received;
}

/**
 * Main event loop with signal integration
 */
int
main(void)
{
    if (setup_signal_handling() < 0)
        return 1;
    
    SocketPoll_T poll = SocketPoll_new(1000);
    SocketPool_T pool = SocketPool_new(NULL, 100, 8192);
    
    /* Add signal pipe to poll set */
    SocketPoll_add_fd(poll, g_signal_pipe[0], POLL_READ, NULL);
    
    /* Main event loop */
    int running = 1;
    while (running)
    {
        SocketEvent_T *events;
        int n = SocketPoll_wait(poll, &events, 1000);
        
        for (int i = 0; i < n; i++)
        {
            if (events[i].fd == g_signal_pipe[0])
            {
                /* Signal received - drain pipe and initiate shutdown */
                drain_signal_pipe();
                printf("Shutdown signal received\n");
                running = 0;
            }
            else
            {
                /* Handle socket events */
            }
        }
    }
    
    /* Graceful shutdown with 30 second timeout */
    printf("Draining connections...\n");
    SocketPool_drain(pool, 30000);
    
    while (SocketPool_drain_poll(pool) > 0)
    {
        SocketEvent_T *events;
        int timeout = SocketPool_drain_remaining_ms(pool);
        SocketPoll_wait(poll, &events, timeout > 0 ? timeout : 100);
    }
    
    /* Cleanup */
    close(g_signal_pipe[0]);
    close(g_signal_pipe[1]);
    SocketPool_free(&pool);
    SocketPoll_free(&poll);
    
    return 0;
}
```

### Pattern 2: Volatile Flag (Simple but Limited)

For simple applications without event loops:

```c
#include <signal.h>
#include <stdatomic.h>

/* Use sig_atomic_t for async-signal-safe access */
static volatile sig_atomic_t g_shutdown_requested = 0;

static void
signal_handler(int signo)
{
    (void)signo;
    g_shutdown_requested = 1;
}

int
main(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    while (!g_shutdown_requested)
    {
        /* Do work... */
        
        /* Check flag periodically */
        if (g_shutdown_requested)
            break;
    }
    
    /* Cleanup */
    return 0;
}
```

**Limitations:**
- Can't interrupt blocking operations
- Must poll the flag frequently
- No information about which signal was received

### Pattern 3: Dedicated Signal Thread (Advanced)

For complex multi-threaded applications:

```c
#include <pthread.h>
#include <signal.h>

static pthread_t g_signal_thread;
static volatile int g_shutdown = 0;

static void *
signal_thread_func(void *arg)
{
    (void)arg;
    sigset_t set;
    int signo;
    
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    
    while (!g_shutdown)
    {
        if (sigwait(&set, &signo) == 0)
        {
            switch (signo)
            {
            case SIGINT:
            case SIGTERM:
                g_shutdown = 1;
                /* Notify other threads via condition variable, etc. */
                break;
            case SIGHUP:
                /* Reload configuration */
                break;
            }
        }
    }
    
    return NULL;
}

int
main(void)
{
    /* Block signals in main thread (inherited by all threads) */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    
    /* Create dedicated signal handling thread */
    pthread_create(&g_signal_thread, NULL, signal_thread_func, NULL);
    
    /* Worker threads... */
    
    /* Cleanup */
    pthread_join(g_signal_thread, NULL);
    return 0;
}
```

## Interaction with Application Handlers

### Library Behavior

The socket library:
- Does NOT install signal handlers
- Does NOT mask or block signals
- Does NOT modify signal dispositions
- Handles EINTR internally where appropriate

### Safe to Install

Applications can freely install handlers for:
- `SIGINT` - Interrupt (Ctrl+C)
- `SIGTERM` - Termination request
- `SIGHUP` - Hangup / config reload
- `SIGUSR1`, `SIGUSR2` - User-defined
- `SIGCHLD` - Child process status change
- `SIGALRM` - Timer expiration
- Any other signal

### Recommendations

1. **Use `sigaction()` not `signal()`** - More reliable, portable behavior
2. **Keep handlers minimal** - Only set flags or write to pipes
3. **Use `SA_RESTART`** - Restart interrupted syscalls automatically
4. **Block during init** - Block signals during library initialization if paranoid

```c
/* Block signals during initialization */
sigset_t block, old;
sigemptyset(&block);
sigaddset(&block, SIGINT);
sigaddset(&block, SIGTERM);
pthread_sigmask(SIG_BLOCK, &block, &old);

/* Initialize library resources */
SocketPool_T pool = SocketPool_new(NULL, 100, 8192);

/* Restore signals */
pthread_sigmask(SIG_SETMASK, &old, NULL);
```

## Common Pitfalls

### Pitfall 1: Calling Library Functions from Handlers

**Wrong:**
```c
static void bad_handler(int signo)
{
    (void)signo;
    /* DANGEROUS: These are NOT async-signal-safe! */
    printf("Signal received\n");           /* NOT safe */
    Socket_free(&global_socket);           /* NOT safe */
    SocketPool_drain(global_pool, 1000);   /* NOT safe */
}
```

**Correct:**
```c
static volatile sig_atomic_t shutdown_flag = 0;

static void good_handler(int signo)
{
    (void)signo;
    shutdown_flag = 1;  /* Safe - atomic write */
}

/* In main code */
if (shutdown_flag)
{
    printf("Signal received\n");           /* Safe here */
    SocketPool_drain(global_pool, 1000);   /* Safe here */
    Socket_free(&global_socket);           /* Safe here */
}
```

### Pitfall 2: Missing Non-Blocking Flag on Self-Pipe

**Wrong:**
```c
pipe(signal_pipe);
/* Missing O_NONBLOCK - write in handler could block! */
```

**Correct:**
```c
pipe(signal_pipe);
fcntl(signal_pipe[0], F_SETFL, O_NONBLOCK);
fcntl(signal_pipe[1], F_SETFL, O_NONBLOCK);
```

### Pitfall 3: Using `signal()` Instead of `sigaction()`

**Wrong:**
```c
signal(SIGINT, handler);  /* Unreliable on some platforms */
```

**Correct:**
```c
struct sigaction sa = {0};
sa.sa_handler = handler;
sigemptyset(&sa.sa_mask);
sa.sa_flags = SA_RESTART;
sigaction(SIGINT, &sa, NULL);
```

### Pitfall 4: Not Preserving errno in Handlers

**Wrong:**
```c
static void handler(int signo)
{
    (void)signo;
    write(pipe_fd, "x", 1);  /* May modify errno */
}
```

**Correct:**
```c
static void handler(int signo)
{
    (void)signo;
    int saved_errno = errno;
    write(pipe_fd, "x", 1);
    errno = saved_errno;
}
```

## Platform-Specific Notes

### Linux

- `MSG_NOSIGNAL` is used for SIGPIPE suppression
- `eventfd()` can be used instead of self-pipe (more efficient)
- `signalfd()` available for signal-to-fd conversion

### macOS / BSD

- `SO_NOSIGPIPE` socket option is used
- `kqueue` can monitor signals directly via `EVFILT_SIGNAL`

### Multi-threaded Programs

- Signals are delivered to an arbitrary thread (unless blocked)
- Use `pthread_sigmask()` to control per-thread signal mask
- Consider dedicated signal handling thread pattern

## Testing Signal Handling

The library includes signal interrupt tests in `src/test/test_signals.c`:

```bash
# Run signal handling tests
cd build
./test_signals
```

Test coverage includes:
- EINTR handling in poll operations
- Signal during DNS resolution
- Signal during connect
- Graceful shutdown with timeout

## References

- POSIX.1-2017 Signal Handling: https://pubs.opengroup.org/onlinepubs/9699919799/
- GNU C Library Signal Handling: https://www.gnu.org/software/libc/manual/html_node/Signal-Handling.html
- Linux `signal(7)` man page: `man 7 signal`
