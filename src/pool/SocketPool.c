/**
 * SocketPool.c - Main entry point for SocketPool module (delegates to split files)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 * This file is now a thin wrapper; core logic split for maintainability.
 */

#include "pool/SocketPool-core.h"
#include "pool/SocketPool-connections.h"
#include "pool/SocketPool-accept.h"
#include "pool/SocketPool-cleanup.h"
#include "pool/SocketPool-private.h"

/* All functions defined in split files; no additional code here */
