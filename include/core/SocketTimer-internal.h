/**
 * SocketTimer-internal.h - Deprecated internal header
 *
 * This header is deprecated and kept for backwards compatibility only.
 * All SocketTimer internals are now consolidated in SocketTimer.c.
 *
 * For timer heap operations, use SocketTimer-private.h which provides
 * the heap API needed by SocketPoll integration.
 */

#ifndef SOCKETTIMER_INTERNAL_INCLUDED
#define SOCKETTIMER_INTERNAL_INCLUDED

/* All internal declarations are now in SocketTimer-private.h */
#include "core/SocketTimer-private.h"

#endif /* SOCKETTIMER_INTERNAL_INCLUDED */

