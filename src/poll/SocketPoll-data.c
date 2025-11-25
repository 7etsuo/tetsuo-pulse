/**
 * SocketPoll-data.c - Hash table and socket data management
 *
 * This file contains the hash functions and socket-to-data mapping
 * implementation for the SocketPoll module.
 *
 * Thread-safe: Functions marked "unlocked" require caller to hold mutex.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"

#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketError.h"
#include "core/SocketLog.h"
#include "poll/SocketPoll-private.h"
#include "socket/Socket.h"

#define T SocketPoll_T

extern const Except_T SocketPoll_Failed;

/* ==================== Hash Functions ==================== */

/**
 * socket_hash - Hash function for socket file descriptors
 * @socket: Socket to hash
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 *
 * Uses multiplicative hashing with the golden ratio constant for
 * good distribution across hash buckets. This provides O(1) average
 * case performance for socket data lookups.
 */
unsigned
socket_hash (const Socket_T socket)
{
  int fd;

  assert (socket);
  fd = Socket_fd (socket);

  if (fd < 0)
    {
      SocketLog_emitf (
          SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
          "Attempt to hash closed/invalid socket (fd=%d); returning 0", fd);
      return 0;
    }

  /* Multiplicative hash with golden ratio for good distribution */
  return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
}

/**
 * compute_fd_hash - Compute hash for file descriptor
 * @fd: File descriptor
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 */
unsigned
compute_fd_hash (int fd)
{
  return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
}

/* ==================== Allocation Helpers ==================== */

/**
 * allocate_socket_data_entry - Allocate socket data entry from arena
 * @poll: Poll instance
 * Returns: Allocated entry
 * Raises: SocketPoll_Failed on allocation failure
 */
SocketData *
allocate_socket_data_entry (T poll)
{
  SocketData *volatile volatile_entry = NULL;

  TRY
  {
    volatile_entry = CALLOC (poll->arena, 1, sizeof (SocketData));
  }
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket data mapping");
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  return volatile_entry;
}

/**
 * allocate_fd_socket_entry - Allocate FD to socket entry from arena
 * @poll: Poll instance
 * Returns: Allocated entry
 * Raises: SocketPoll_Failed on allocation failure
 */
FdSocketEntry *
allocate_fd_socket_entry (T poll)
{
  FdSocketEntry *volatile volatile_entry = NULL;

  TRY
  {
    volatile_entry = CALLOC (poll->arena, 1, sizeof (FdSocketEntry));
  }
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate fd to socket mapping");
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  return volatile_entry;
}

/* ==================== Hash Table Insertion ==================== */

/**
 * insert_socket_data_entry - Insert socket data entry into hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @entry: Entry to insert
 * Thread-safe: Yes - caller must hold mutex
 */
static void
insert_socket_data_entry (T poll, unsigned hash, SocketData *entry)
{
  entry->next = poll->socket_data_map[hash];
  poll->socket_data_map[hash] = entry;
}

/**
 * insert_fd_socket_entry - Insert FD to socket entry into hash table
 * @poll: Poll instance
 * @fd_hash: Hash bucket index
 * @entry: Entry to insert
 * Thread-safe: Yes - caller must hold mutex
 */
static void
insert_fd_socket_entry (T poll, unsigned fd_hash, FdSocketEntry *entry)
{
  entry->next = poll->fd_to_socket_map[fd_hash];
  poll->fd_to_socket_map[fd_hash] = entry;
}

/* ==================== Hash Table Lookup ==================== */

/**
 * socket_data_lookup_unlocked - Retrieve user data for socket
 * @poll: Poll instance
 * @socket: Socket to look up
 * Returns: User data associated with socket, or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 *
 * Performs O(1) average case lookup in the socket data hash table.
 */
void *
socket_data_lookup_unlocked (T poll, Socket_T socket)
{
  unsigned hash;
  SocketData *entry;

  if (!poll || !socket)
    return NULL;

  hash = socket_hash (socket);
  if (hash >= SOCKET_DATA_HASH_SIZE)
    return NULL;

  entry = poll->socket_data_map[hash];
  while (entry)
    {
      if (entry->socket == socket)
        return entry->data;
      entry = entry->next;
    }

  return NULL;
}

/**
 * find_socket_data_entry - Find socket data entry in hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to find
 * Returns: Entry or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 */
static SocketData *
find_socket_data_entry (T poll, unsigned hash, Socket_T socket)
{
  SocketData *entry = poll->socket_data_map[hash];
  while (entry)
    {
      if (entry->socket == socket)
        return entry;
      entry = entry->next;
    }
  return NULL;
}

/* ==================== Hash Table Removal ==================== */

/**
 * remove_socket_data_entry - Remove socket data entry from hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to remove
 * Thread-safe: No (caller must hold mutex)
 */
static void
remove_socket_data_entry (T poll, unsigned hash, Socket_T socket)
{
  SocketData **pp = &poll->socket_data_map[hash];
  while (*pp)
    {
      if ((*pp)->socket == socket)
        {
          *pp = (*pp)->next;
          break;
        }
      pp = &(*pp)->next;
    }
}

/**
 * remove_fd_socket_entry - Remove FD to socket entry from hash table
 * @poll: Poll instance
 * @fd_hash: Hash bucket index
 * @fd: File descriptor to remove
 * Thread-safe: No (caller must hold mutex)
 */
static void
remove_fd_socket_entry (T poll, unsigned fd_hash, int fd)
{
  FdSocketEntry **fd_pp = &poll->fd_to_socket_map[fd_hash];
  while (*fd_pp)
    {
      if ((*fd_pp)->fd == fd)
        {
          *fd_pp = (*fd_pp)->next;
          break;
        }
      fd_pp = &(*fd_pp)->next;
    }
}

/* ==================== Fallback Entry Addition ==================== */

/**
 * add_fallback_socket_data_entry - Add socket data entry as fallback
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to add
 * @data: User data to associate
 * Raises: SocketPoll_Failed on allocation failure
 * Thread-safe: No (caller must hold mutex)
 */
static void
add_fallback_socket_data_entry (T poll, unsigned hash, Socket_T socket,
                                void *data)
{
  SocketData *volatile volatile_entry = NULL;

#ifndef NDEBUG
  fprintf (stderr, "WARNING: socket_data_update fallback (fd %d)\n",
           Socket_fd (socket));
#endif

  TRY
  {
    volatile_entry = CALLOC (poll->arena, 1, sizeof (SocketData));
  }
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket data mapping");
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  volatile_entry->socket = socket;
  volatile_entry->data = data;
  volatile_entry->next = poll->socket_data_map[hash];
  poll->socket_data_map[hash] = volatile_entry;
}

/* ==================== Public Unlocked Operations ==================== */

/**
 * socket_data_add_unlocked - Add socket data mapping (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 * @data: User data
 * Raises: SocketPoll_Failed on allocation failure
 */
void
socket_data_add_unlocked (T poll, Socket_T socket, void *data)
{
  unsigned hash = socket_hash (socket);
  unsigned fd_hash = compute_fd_hash (Socket_fd (socket));
  SocketData *data_entry = allocate_socket_data_entry (poll);
  FdSocketEntry *fd_entry = allocate_fd_socket_entry (poll);

  data_entry->socket = socket;
  data_entry->data = data;
  fd_entry->fd = Socket_fd (socket);
  fd_entry->socket = socket;

  insert_socket_data_entry (poll, hash, data_entry);
  insert_fd_socket_entry (poll, fd_hash, fd_entry);
}

/**
 * socket_data_update_unlocked - Update data (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 * @data: New data
 * Raises: SocketPoll_Failed on allocation failure (fallback)
 */
void
socket_data_update_unlocked (T poll, Socket_T socket, void *data)
{
  unsigned hash = socket_hash (socket);
  SocketData *entry = find_socket_data_entry (poll, hash, socket);
  if (entry)
    {
      entry->data = data;
    }
  else
    {
#ifndef NDEBUG
      fprintf (stderr, "WARNING: socket_data_update_unlocked fallback (fd %d)\n",
               Socket_fd (socket));
#endif
      add_fallback_socket_data_entry (poll, hash, socket, data);
    }
}

/**
 * socket_data_remove_unlocked - Remove mappings (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 */
void
socket_data_remove_unlocked (T poll, Socket_T socket)
{
  unsigned hash = socket_hash (socket);
  int fd = Socket_fd (socket);
  unsigned fd_hash = compute_fd_hash (fd);

  remove_socket_data_entry (poll, hash, socket);
  remove_fd_socket_entry (poll, fd_hash, fd);
}

#undef T

