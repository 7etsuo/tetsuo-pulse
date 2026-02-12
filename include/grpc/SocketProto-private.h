/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketProto-private.h
 * @brief Internal protobuf runtime definitions.
 */

#ifndef SOCKETPROTO_PRIVATE_INCLUDED
#define SOCKETPROTO_PRIVATE_INCLUDED

#include "grpc/SocketProto.h"

struct SocketProto_Message
{
  Arena_T arena;
  int owns_arena;
  SocketProto_Limits limits;
  const SocketProto_Schema *schema;
  SocketProto_Field *fields;
  size_t field_count;
  size_t field_capacity;
  size_t unknown_count;
};

static inline int
socketproto_size_add (size_t a, size_t b, size_t *out)
{
  return __builtin_add_overflow (a, b, out);
}

static inline int
socketproto_size_mul (size_t a, size_t b, size_t *out)
{
  return __builtin_mul_overflow (a, b, out);
}

#endif /* SOCKETPROTO_PRIVATE_INCLUDED */
