/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_CONSTANTS_H
#define SOCKETUTIL_CONSTANTS_H

/**
 * @file SocketUtil/Constants.h
 * @ingroup foundation
 * @brief Common constants for ports, buffer sizes, and protocol limits.
 */

/* ============================================================================
 * PORT VALIDATION CONSTANTS
 * ============================================================================
 */

/**
 * @brief Maximum valid TCP/UDP port number (2^16 - 1).
 * @ingroup foundation
 *
 * Valid port numbers range from 1 to 65535. Port 0 is reserved and typically
 * used to request automatic port assignment by the operating system.
 *
 * Used for:
 * - Port validation in connection establishment
 * - DTLS and TLS endpoint configuration
 * - HTTP server port binding
 * - DNS server port validation
 *
 * @see RFC 793 (TCP) - Ports are 16-bit unsigned integers
 * @see RFC 768 (UDP) - Port range 0-65535
 */
#define SOCKET_MAX_PORT 65535

/* ============================================================================
 * BUFFER SIZE CONSTANTS
 * ============================================================================
 */

/**
 * @brief Standard initial buffer capacity for protocol message assembly.
 * @ingroup foundation
 *
 * Default size for initial message buffers in WebSocket and other protocol
 * implementations. Sized to accommodate typical messages while allowing
 * growth for larger payloads.
 *
 * Used for:
 * - WebSocket message reassembly initial capacity
 * - Protocol message parsing buffers
 * - Initial allocation for dynamic buffers
 *
 * @see SocketBuf_T for dynamic buffer implementation
 */
#define SOCKET_INITIAL_MESSAGE_CAPACITY 4096

/**
 * @brief Standard buffer growth factor for dynamic buffers.
 * @ingroup foundation
 *
 * Multiplicative factor for buffer capacity growth when resizing.
 * Value of 2 provides good balance between memory usage and reallocation
 * frequency (amortized O(1) appends).
 *
 * Used for:
 * - SocketBuf dynamic resizing
 * - WebSocket message buffer growth
 * - General dynamic buffer expansion
 */
#define SOCKET_BUFFER_GROWTH_FACTOR 2

#endif /* SOCKETUTIL_CONSTANTS_H */
