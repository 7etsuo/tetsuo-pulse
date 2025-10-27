CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -O2 -D_GNU_SOURCE -pthread -std=gnu99 -I..
LDFLAGS = -pthread

# Build directory for object files
BUILD_DIR = build

# Parent directory build and object files
PARENT_DIR = ..
PARENT_BUILD = $(PARENT_DIR)/build
LIB_OBJECTS = $(PARENT_BUILD)/Arena.o $(PARENT_BUILD)/Except.o \
              $(PARENT_BUILD)/Socket.o $(PARENT_BUILD)/SocketDgram.o \
              $(PARENT_BUILD)/SocketBuf.o $(PARENT_BUILD)/SocketPoll.o \
              $(PARENT_BUILD)/SocketPool.o $(PARENT_BUILD)/SocketError.o

# Determine backend
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LIB_OBJECTS += $(PARENT_BUILD)/SocketPoll_epoll.o
else ifeq ($(UNAME_S),Darwin)
    LIB_OBJECTS += $(PARENT_BUILD)/SocketPoll_kqueue.o
else ifeq ($(UNAME_S),FreeBSD)
    LIB_OBJECTS += $(PARENT_BUILD)/SocketPoll_kqueue.o
else
    LIB_OBJECTS += $(PARENT_BUILD)/SocketPoll_poll.o
endif

EXAMPLES = udp_echo_server unix_ipc_server unix_ipc_client

all: $(EXAMPLES)

udp_echo_server: $(BUILD_DIR)/udp_echo_server.o $(LIB_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

unix_ipc_server: $(BUILD_DIR)/unix_ipc_server.o $(LIB_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

unix_ipc_client: $(BUILD_DIR)/unix_ipc_client.o $(LIB_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build parent library objects if needed
$(LIB_OBJECTS):
	$(MAKE) -C $(PARENT_DIR)

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(EXAMPLES)

.PHONY: all clean

