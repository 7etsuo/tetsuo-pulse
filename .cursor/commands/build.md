# Build System Helper - Socket Library

Analyze the project structure and generate/update a Makefile with the following specifications for the socket library:

## 1. Project Structure Analysis
- Scan for all `.c` source files in `src/` directory structure:
  - `src/core/` - Core modules (Arena, Except, SocketError)
  - `src/socket/` - Socket modules (Socket, SocketBuf, SocketDgram)
  - `src/poll/` - Polling backends (SocketPoll_epoll, SocketPoll_kqueue, SocketPoll_poll)
  - `src/pool/` - Connection pool (SocketPool)
  - `src/dns/` - DNS resolution (SocketDNS)
  - `src/test/` - Test files (if applicable)
- Identify the main executable target (if any)
- Detect all object files needed from source files
- Identify header dependencies in `include/` directory
- Detect platform-specific backend selection (epoll, kqueue, poll)

## 2. Compiler Configuration
- Set CC to `gcc` (or detect system default)
- Apply strict compiler flags: `-Wall -Wextra -Werror` (already enforced)
- Use GNU C standard: `-std=gnu99` (socket library uses gnu99)
- Enable debug symbols for debug builds (`-g`)
- Include platform-specific defines: `-D_GNU_SOURCE` for Linux
- Enable thread support: `-pthread`
- Include PIC for shared library: `-fPIC`
- Disable strict aliasing: `-fno-strict-aliasing`
- Include directory: `-Iinclude`

## 3. Dependency Configuration
- Link against pthread library: `-pthread`
- No external library dependencies (pure C socket library)
- Platform-specific backend selection (automatic detection)
- Ensure proper library linking order

## 4. Build Targets

### Debug Target (`make debug` or `make`)
- Build with debug symbols (`-g`)
- Optimize for debugging (`-Og`)
- Include all debug information
- Default build type
- Target: static library `libsocket.a` or shared library `libsocket.so`

### Release Target (`make release`)
- Build with optimization (`-O3`)
- Strip debug symbols (`-DNDEBUG`)
- Optimize for performance
- Target: static library `libsocket.a` or shared library `libsocket.so`

### Clean Target (`make clean`)
- Remove all object files from `build/` directory
- Remove the library file(s)
- Remove any temporary files

### Install Target (`make install`) [Optional]
- Install headers to system include path
- Install library to system library path
- Set proper permissions

## 5. Platform-Specific Backend Selection

### Auto-Detection Pattern
```makefile
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    POLL_BACKEND = epoll
    POLL_BACKEND_SRC = src/poll/SocketPoll_epoll.c
else ifeq ($(UNAME_S),Darwin)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = src/poll/SocketPoll_kqueue.c
# ... etc
endif
```

## 6. Makefile Structure
- Use variables for CC, CFLAGS, LDFLAGS, TARGET, SRCS, OBJS, BUILD_DIR
- Support build directory (`BUILD_DIR = build`)
- Automatic dependency generation (`.d` files) if possible
- Proper phony targets declaration (`.PHONY: all debug release clean install`)
- Include pattern rules for object file compilation
- Platform-specific backend source file selection
- Header include path configuration

## 7. Example Structure
```makefile
CC = gcc

# Auto-detect platform for backend selection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    POLL_BACKEND = epoll
    POLL_BACKEND_SRC = src/poll/SocketPoll_epoll.c
else ifeq ($(UNAME_S),Darwin)
    POLL_BACKEND = kqueue
    POLL_BACKEND_SRC = src/poll/SocketPoll_kqueue.c
else
    POLL_BACKEND = poll
    POLL_BACKEND_SRC = src/poll/SocketPoll_poll.c
endif

# Debug build (default)
CFLAGS_DEBUG = -Wall -Wextra -Werror -g -Og -D_GNU_SOURCE -pthread -std=gnu99 -fno-strict-aliasing -fPIC -Iinclude

# Release build
CFLAGS_RELEASE = -Wall -Wextra -Werror -O3 -DNDEBUG -D_GNU_SOURCE -pthread -std=gnu99 -fno-strict-aliasing -fPIC -Iinclude

CFLAGS = $(CFLAGS_DEBUG)
LDFLAGS = -pthread

BUILD_DIR = build
TARGET_STATIC = libsocket.a
TARGET_SHARED = libsocket.so

# Core sources
CORE_SRCS = src/core/Arena.c src/core/Except.c src/core/SocketError.c

# Socket sources
SOCKET_SRCS = src/socket/Socket.c src/socket/SocketBuf.c src/socket/SocketDgram.c

# Other module sources
OTHER_SRCS = src/pool/SocketPool.c src/dns/SocketDNS.c

# Poll backend (platform-specific)
POLL_SRCS = $(POLL_BACKEND_SRC) src/poll/SocketPoll.c

ALL_SRCS = $(CORE_SRCS) $(SOCKET_SRCS) $(OTHER_SRCS) $(POLL_SRCS)
OBJS = $(ALL_SRCS:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all debug release clean install

all: debug

debug: CFLAGS = $(CFLAGS_DEBUG)
debug: $(TARGET_STATIC)

release: CFLAGS = $(CFLAGS_RELEASE)
release: $(TARGET_STATIC)

$(TARGET_STATIC): $(OBJS)
	ar rcs $@ $^

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET_STATIC) $(TARGET_SHARED)

install: $(TARGET_STATIC)
	install -d /usr/local/include/socket
	install -m 644 include/**/*.h /usr/local/include/socket/
	install -m 644 $(TARGET_STATIC) /usr/local/lib/
```

## 8. Generation Rules
- Generate Makefile in project root
- If Makefile exists, update it preserving any custom additions where possible
- Ensure proper formatting (tabs for commands, not spaces)
- Add comments explaining each section
- Verify all source files exist before including them
- Handle edge cases (no source files, missing headers, etc.)
- Preserve platform detection logic
- Support both static and shared library builds if needed

## 9. Validation
- Verify the generated Makefile syntax is correct
- Ensure all referenced source files exist
- Check that library dependencies are correctly specified
- Confirm build targets work correctly
- Verify platform detection works correctly
- Test both debug and release builds
- Verify include paths are correct

## 10. Socket Library-Specific Considerations

### Module Organization
- Respect module structure (core/, socket/, poll/, pool/, dns/)
- Include appropriate headers from `include/` directory
- Handle platform-specific backend selection correctly

### Build Artifacts
- Library files: `libsocket.a` (static), `libsocket.so` (shared)
- Object files in `build/` directory matching source structure
- Dependency files (`.d`) if generated

### Compiler Flags
- Must include `-Wall -Wextra -Werror` (zero warnings policy)
- Must use `-std=gnu99` (socket library standard)
- Must include `-pthread` for thread support
- Must include `-fPIC` for shared library compatibility
- Must include `-Iinclude` for header paths

The generated Makefile should be production-ready, follow GNU Make conventions, and correctly build the socket library with platform-specific backend selection.
