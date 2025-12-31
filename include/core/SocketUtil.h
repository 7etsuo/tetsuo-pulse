/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_INCLUDED
#define SOCKETUTIL_INCLUDED

/**
 * @file SocketUtil.h
 * @ingroup foundation
 * @brief Consolidated utility header for socket library.
 *
 * This is an umbrella header that includes all SocketUtil sub-modules.
 * For reduced compilation dependencies, include only the specific
 * sub-headers you need from SocketUtil/.
 *
 * Provides:
 * - Core macros (bit manipulation, array length, MIN/MAX)
 * - Constants (port limits, buffer sizes)
 * - Hash functions (golden ratio, DJB2 variants)
 * - Time utilities (monotonic clock, timespec conversions)
 * - Timeout utilities (deadline calculations)
 * - TTL utilities (expiry checking)
 * - Byte order utilities (big-endian pack/unpack)
 * - String utilities (arena strdup, safe copy)
 * - URL utilities (percent-decoding)
 * - Safe arithmetic (overflow detection)
 * - I/O utilities (EINTR-safe read/write)
 * - Error formatting macros
 * - Exception infrastructure
 * - Mutex + arena allocation pattern
 *
 * @see SocketUtil/Core.h for bit macros and foundational utilities
 * @see SocketUtil/Hash.h for hash functions
 * @see SocketUtil/Time.h for monotonic clock utilities
 * @see SocketUtil/Timeout.h for deadline calculations
 */

/* Pre-split modules - kept for backward compatibility */
#include "core/SocketError.h"
#include "core/SocketEvent.h"
#include "core/SocketLog.h"

/* ============================================================================
 * SOCKETUTIL SUB-HEADERS
 * ============================================================================
 *
 * These sub-modules have been split from the original monolithic SocketUtil.h
 * for improved maintainability and reduced compilation dependencies.
 * Include order respects dependencies between headers.
 */

/* Foundational - no internal dependencies */
#include "core/SocketUtil/Core.h"        /* Bit macros, MIN/MAX, ARRAY_LENGTH */
#include "core/SocketUtil/Constants.h"   /* Port limits, buffer sizes */
#include "core/SocketUtil/ByteOrder.h"   /* Big-endian pack/unpack */
#include "core/SocketUtil/TTL.h"         /* TTL expiry utilities */
#include "core/SocketUtil/Arithmetic.h"  /* Safe overflow-checked arithmetic */
#include "core/SocketUtil/IO.h"          /* EINTR-safe read/write */
#include "core/SocketUtil/StringUtils.h" /* Arena strdup, safe copy */
#include "core/SocketUtil/URL.h"         /* URL percent-decoding */

/* Depend on Core.h */
#include "core/SocketUtil/Hash.h" /* Hash functions (uses DJB2_STEP, etc.) */

/* Depend on other sub-headers */
#include "core/SocketUtil/Time.h"    /* Monotonic time (standalone) */
#include "core/SocketUtil/Timeout.h" /* Deadline calculations (uses Time.h) */

/* Depend on SocketError.h and SocketLog.h */
#include "core/SocketUtil/Error.h"     /* Error formatting macros */
#include "core/SocketUtil/Exception.h" /* Exception infrastructure */

/* Depend on Exception.h and Arena.h */
#include "core/SocketUtil/MutexArena.h" /* Mutex + arena allocation pattern */

#endif /* SOCKETUTIL_INCLUDED */
