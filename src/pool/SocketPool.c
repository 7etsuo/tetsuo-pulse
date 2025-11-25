/**
 * SocketPool.c - Main entry point for SocketPool module
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * All functions are defined in split files:
 * - SocketPool-core.c: Pool creation and destruction
 * - SocketPool-resize.c: Runtime capacity management
 * - SocketPool-tuning.c: Pre-warming, buffer config, iteration
 * - SocketPool-connections.c: Connection add/get/remove, hash operations
 * - SocketPool-cleanup.c: Idle connection cleanup
 * - SocketPool-accept.c: Batch connection acceptance
 * - SocketPool-hash.c: Hash table operations
 * - SocketPool-async.c: Async connection preparation
 * - SocketPool-accessors.c: Connection accessor functions
 */

#include "pool/SocketPool-private.h"

/* All functions defined in split files; no additional code here */
