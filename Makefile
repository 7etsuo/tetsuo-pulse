CC = gcc

# Auto-detect platform for backend selection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    POLL_BACKEND = epoll
    POLL_BACKEND_SRC = SocketPoll_epoll.c
else ifeq ($(UNAME_S),Darwin)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = SocketPoll_kqueue.c
else ifeq ($(UNAME_S),FreeBSD)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = SocketPoll_kqueue.c
else ifeq ($(UNAME_S),OpenBSD)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = SocketPoll_kqueue.c
else ifeq ($(UNAME_S),NetBSD)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = SocketPoll_kqueue.c
else
    POLL_BACKEND = poll
    POLL_BACKEND_SRC = SocketPoll_poll.c
endif

# Debug build (default) - includes symbols, optimizes for debugging
# Note: -fPIC included for shared library compatibility (negligible overhead)
CFLAGS_DEBUG = -Wall -Wextra -Werror -g -Og -D_GNU_SOURCE -pthread -std=gnu99 -fno-strict-aliasing -fPIC

# Release build - full optimization, no debug symbols
CFLAGS_RELEASE = -Wall -Wextra -Werror -O3 -DNDEBUG -D_GNU_SOURCE -pthread -std=gnu99 -fno-strict-aliasing -fPIC

# Default to debug build
CFLAGS = $(CFLAGS_DEBUG)

LDFLAGS = -pthread

# Build directory for object files
BUILD_DIR = build

TARGET = irc_server
SOURCES = Arena.c Except.c Socket.c SocketDgram.c SocketBuf.c SocketPoll.c $(POLL_BACKEND_SRC) SocketPool.c SocketError.c main.c
OBJECTS = $(SOURCES:%.c=$(BUILD_DIR)/%.o)
LIB_SOURCES = Arena.c Except.c Socket.c SocketDgram.c SocketBuf.c SocketPoll.c $(POLL_BACKEND_SRC) SocketPool.c SocketError.c
LIB_OBJECTS = $(LIB_SOURCES:%.c=$(BUILD_DIR)/%.o)
DEPS = $(SOURCES:%.c=$(BUILD_DIR)/%.d)

all: info $(TARGET) test_client

info:
	@echo "Building socket library with $(POLL_BACKEND) backend on $(UNAME_S)"

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_client: $(BUILD_DIR)/test_client.o $(LIB_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Shared library target (all objects built with -fPIC already)
libsocket.so: $(LIB_OBJECTS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Static library target
libsocket.a: $(LIB_OBJECTS)
	$(AR) rcs $@ $^

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compilation rule - output to build directory
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Auto-generated dependencies - manual dependencies removed as they're redundant
-include $(DEPS)

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET) test_client
	rm -f libsocket.so libsocket.a

# Release build target - optimized for production
release: CFLAGS = $(CFLAGS_RELEASE)
release: clean all

# Library targets
lib: libsocket.so libsocket.a

.PHONY: all clean release lib info
