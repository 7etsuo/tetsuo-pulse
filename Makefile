CC = gcc

# Auto-detect platform for backend selection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    POLL_BACKEND = epoll
    POLL_BACKEND_SRC = src/poll/SocketPoll_epoll.c
else ifeq ($(UNAME_S),Darwin)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = src/poll/SocketPoll_kqueue.c
else ifeq ($(UNAME_S),FreeBSD)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = src/poll/SocketPoll_kqueue.c
else ifeq ($(UNAME_S),OpenBSD)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = src/poll/SocketPoll_kqueue.c
else ifeq ($(UNAME_S),NetBSD)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = src/poll/SocketPoll_kqueue.c
else
    POLL_BACKEND = poll
    POLL_BACKEND_SRC = src/poll/SocketPoll_poll.c
endif

# Debug build (default) - includes symbols, optimizes for debugging
# Note: -fPIC included for shared library compatibility (negligible overhead)
CFLAGS_DEBUG = -Wall -Wextra -Werror -g -Og -D_GNU_SOURCE -pthread -std=gnu99 -fno-strict-aliasing -fPIC -Iinclude

# Release build - full optimization, no debug symbols
CFLAGS_RELEASE = -Wall -Wextra -Werror -O3 -DNDEBUG -D_GNU_SOURCE -pthread -std=gnu99 -fno-strict-aliasing -fPIC -Iinclude

# Default to debug build
CFLAGS = $(CFLAGS_DEBUG)

LDFLAGS = -pthread

# Build directory for object files
BUILD_DIR = build
TEST_DIR = $(BUILD_DIR)/test

LIB_SOURCES = src/core/Arena.c src/core/Except.c src/socket/Socket.c src/socket/SocketDgram.c src/socket/SocketBuf.c src/poll/SocketPoll.c $(POLL_BACKEND_SRC) src/pool/SocketPool.c src/dns/SocketDNS.c src/core/SocketError.c
LIB_OBJECTS = $(LIB_SOURCES:src/%.c=$(BUILD_DIR)/%.o)
DEPS = $(LIB_SOURCES:src/%.c=$(BUILD_DIR)/%.d)

# Test framework source
TEST_FRAMEWORK_SRC = src/test/Test.c
TEST_FRAMEWORK_OBJ = $(BUILD_DIR)/test/Test.o

# Test source files
TEST_SOURCES = src/test/test_arena.c src/test/test_except.c src/test/test_socket.c src/test/test_socketbuf.c src/test/test_socketdgram.c src/test/test_socketpoll.c src/test/test_socketpool.c src/test/test_socketdns.c
TEST_OBJECTS = $(TEST_SOURCES:src/%.c=$(BUILD_DIR)/%.o)
TEST_EXECUTABLES = $(TEST_SOURCES:src/test/test_%.c=$(TEST_DIR)/test_%)

# Test dependencies
TEST_DEPS = $(TEST_SOURCES:src/%.c=$(BUILD_DIR)/%.d)

all: info lib

info:
	@echo "Building socket library with $(POLL_BACKEND) backend on $(UNAME_S)"

# Shared library target (all objects built with -fPIC already)
libsocket.so: $(LIB_OBJECTS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Static library target
libsocket.a: $(LIB_OBJECTS)
	$(AR) rcs $@ $^

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Create test directory if it doesn't exist
$(TEST_DIR):
	mkdir -p $(TEST_DIR)

# Compilation rule - output to build directory
$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Auto-generated dependencies - manual dependencies removed as they're redundant
-include $(DEPS)

clean:
	rm -rf $(BUILD_DIR)
	rm -f libsocket.so libsocket.a

test-clean:
	rm -rf $(TEST_DIR)
	rm -f $(TEST_EXECUTABLES)

# Test framework compilation
$(BUILD_DIR)/test/Test.o: src/test/Test.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Test source compilation
$(BUILD_DIR)/test/%.o: src/test/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Test executables - link test framework + library objects + test object
$(TEST_DIR)/test_%: $(BUILD_DIR)/test/test_%.o $(TEST_FRAMEWORK_OBJ) $(LIB_OBJECTS) | $(TEST_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Test targets
test: $(TEST_EXECUTABLES)
	@echo "Running all tests..."
	@for test in $(TEST_EXECUTABLES); do \
		echo ""; \
		echo "=== Running $$(basename $$test) ==="; \
		$$test || exit 1; \
	done
	@echo ""
	@echo "All tests passed!"

test-arena: $(TEST_DIR)/test_arena
	$(TEST_DIR)/test_arena

test-except: $(TEST_DIR)/test_except
	$(TEST_DIR)/test_except

test-socket: $(TEST_DIR)/test_socket
	$(TEST_DIR)/test_socket

test-socketbuf: $(TEST_DIR)/test_socketbuf
	$(TEST_DIR)/test_socketbuf

test-socketdgram: $(TEST_DIR)/test_socketdgram
	$(TEST_DIR)/test_socketdgram

test-socketpoll: $(TEST_DIR)/test_socketpoll
	$(TEST_DIR)/test_socketpoll

test-socketpool: $(TEST_DIR)/test_socketpool
	$(TEST_DIR)/test_socketpool

test-socketdns: $(TEST_DIR)/test_socketdns
	$(TEST_DIR)/test_socketdns

# Include test dependencies
-include $(TEST_DEPS)

# Release build target - optimized for production
release: CFLAGS = $(CFLAGS_RELEASE)
release: clean lib

# Library targets
lib: libsocket.so libsocket.a

.PHONY: all clean release lib info test test-clean test-arena test-except test-socket test-socketbuf test-socketdgram test-socketpoll test-socketpool test-socketdns
