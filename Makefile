CC = gcc

# Debug build (default) - includes symbols, optimizes for debugging
CFLAGS_DEBUG = -Wall -Wextra -Werror -g -Og -D_GNU_SOURCE -pthread -std=gnu99 -fno-strict-aliasing

# Release build - full optimization, no debug symbols
CFLAGS_RELEASE = -Wall -Wextra -Werror -O3 -DNDEBUG -D_GNU_SOURCE -pthread -std=gnu99 -fno-strict-aliasing

# Default to debug build
CFLAGS = $(CFLAGS_DEBUG)

LDFLAGS = -pthread
TARGET = irc_server
SOURCES = Arena.c Except.c Socket.c SocketBuf.c SocketPoll.c SocketPool.c SocketError.c main.c
OBJECTS = $(SOURCES:.c=.o)
LIB_SOURCES = Arena.c Except.c Socket.c SocketBuf.c SocketPoll.c SocketPool.c SocketError.c
LIB_OBJECTS = $(LIB_SOURCES:.c=.o)
DEPS = $(SOURCES:.c=.d)

all: $(TARGET) test_client

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_client: test_client.o $(LIB_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Auto-generated dependencies - manual dependencies removed as they're redundant
-include $(DEPS)

clean:
	rm -f $(OBJECTS) test_client.o $(TARGET) test_client $(DEPS) test_client.d

# Release build target - optimized for production
release: CFLAGS = $(CFLAGS_RELEASE)
release: clean all

.PHONY: all clean release
