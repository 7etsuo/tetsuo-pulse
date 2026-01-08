/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-blocked.c
 * @brief QPACK Blocked Stream Management (RFC 9204 Sections 2.1.2, 2.2.1)
 *
 * Implements blocked stream tracking for the QPACK decoder. When the
 * Required Insert Count > Insert Count, field sections cannot be decoded
 * immediately and are queued until the dynamic table advances.
 *
 * Key behaviors per RFC 9204:
 * - Section 2.1.2: Encoder must not exceed SETTINGS_QPACK_BLOCKED_STREAMS
 * - Section 2.2.1: Decoder must block when RIC > Insert Count
 * - Blocked sections processed in FIFO order per stream
 * - Automatic unblocking when Insert Count advances
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-2.1.2
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-2.2.1
 */

#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketSecurity.h"

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================
 */

/** Growth factor for dynamic arrays */
#define BLOCKED_GROWTH_FACTOR 2

/** Initial section array capacity per stream */
#define INITIAL_SECTION_CAPACITY 4

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Find a blocked stream by stream ID.
 *
 * @param manager   Blocked stream manager
 * @param stream_id Stream ID to find
 * @return Pointer to blocked stream, or NULL if not found
 */
static SocketQPACK_BlockedStream *
find_blocked_stream (SocketQPACK_BlockedManager_T manager, uint64_t stream_id)
{
  for (size_t i = 0; i < manager->stream_count; i++)
    {
      if (manager->streams[i].stream_id == stream_id)
        return &manager->streams[i];
    }
  return NULL;
}

/**
 * @brief Ensure streams array has capacity for one more stream.
 *
 * @param manager Blocked stream manager
 * @return true on success, false on allocation failure or limit exceeded
 */
static bool
ensure_stream_capacity (SocketQPACK_BlockedManager_T manager)
{
  size_t new_alloc;
  SocketQPACK_BlockedStream *new_streams;

  if (manager->stream_count < manager->stream_alloc)
    return true;

  /* Double the capacity */
  if (!SocketSecurity_check_multiply (
          manager->stream_alloc, BLOCKED_GROWTH_FACTOR, &new_alloc))
    return false;

  new_streams
      = ALLOC (manager->arena, new_alloc * sizeof (SocketQPACK_BlockedStream));
  if (new_streams == NULL)
    return false;

  /* Copy existing streams */
  if (manager->stream_count > 0)
    memcpy (new_streams,
            manager->streams,
            manager->stream_count * sizeof (SocketQPACK_BlockedStream));

  manager->streams = new_streams;
  manager->stream_alloc = new_alloc;

  return true;
}

/**
 * @brief Ensure a stream has capacity for one more section.
 *
 * @param manager Blocked stream manager (for arena)
 * @param stream  Blocked stream to expand
 * @return QPACK_BLOCKED_OK on success,
 *         QPACK_BLOCKED_ERR_SECTION_LIMIT if per-stream limit exceeded,
 *         QPACK_BLOCKED_ERR_INTERNAL on allocation failure
 */
static SocketQPACK_BlockedResult
ensure_section_capacity (SocketQPACK_BlockedManager_T manager,
                         SocketQPACK_BlockedStream *stream)
{
  size_t new_alloc;
  SocketQPACK_BlockedSection *new_sections;

  if (stream->section_count < stream->section_alloc)
    return QPACK_BLOCKED_OK;

  /* Double the capacity or use initial */
  if (stream->section_alloc == 0)
    new_alloc = INITIAL_SECTION_CAPACITY;
  else if (!SocketSecurity_check_multiply (
               stream->section_alloc, BLOCKED_GROWTH_FACTOR, &new_alloc))
    return QPACK_BLOCKED_ERR_INTERNAL;

  /* Enforce per-stream section limit */
  if (new_alloc > QPACK_MAX_SECTIONS_PER_STREAM)
    new_alloc = QPACK_MAX_SECTIONS_PER_STREAM;

  if (stream->section_count >= new_alloc)
    return QPACK_BLOCKED_ERR_SECTION_LIMIT;

  new_sections
      = ALLOC (manager->arena, new_alloc * sizeof (SocketQPACK_BlockedSection));
  if (new_sections == NULL)
    return QPACK_BLOCKED_ERR_INTERNAL;

  /* Copy existing sections */
  if (stream->section_count > 0)
    memcpy (new_sections,
            stream->sections,
            stream->section_count * sizeof (SocketQPACK_BlockedSection));

  stream->sections = new_sections;
  stream->section_alloc = new_alloc;

  return QPACK_BLOCKED_OK;
}

/**
 * @brief Remove a stream from the blocked streams array.
 *
 * @param manager Blocked stream manager
 * @param index   Index of stream to remove
 */
static void
remove_blocked_stream (SocketQPACK_BlockedManager_T manager, size_t index)
{
  if (index >= manager->stream_count)
    return;

  /* Subtract this stream's bytes from total */
  manager->total_blocked_bytes -= manager->streams[index].total_bytes;

  /* Shift remaining streams */
  if (index < manager->stream_count - 1)
    {
      memmove (&manager->streams[index],
               &manager->streams[index + 1],
               (manager->stream_count - index - 1)
                   * sizeof (SocketQPACK_BlockedStream));
    }

  manager->stream_count--;
}

/**
 * @brief Remove a section from a blocked stream.
 *
 * @param manager Blocked stream manager
 * @param stream  Blocked stream
 * @param index   Index of section to remove
 */
static void
remove_blocked_section (SocketQPACK_BlockedManager_T manager,
                        SocketQPACK_BlockedStream *stream,
                        size_t index)
{
  if (index >= stream->section_count)
    return;

  /* Update byte counts */
  size_t section_bytes = stream->sections[index].data_len;
  stream->total_bytes -= section_bytes;
  manager->total_blocked_bytes -= section_bytes;

  /* Shift remaining sections */
  if (index < stream->section_count - 1)
    {
      memmove (&stream->sections[index],
               &stream->sections[index + 1],
               (stream->section_count - index - 1)
                   * sizeof (SocketQPACK_BlockedSection));
    }

  stream->section_count--;
}

/**
 * @brief Update the minimum RIC for a blocked stream.
 *
 * @param stream Blocked stream to update
 */
static void
update_stream_min_ric (SocketQPACK_BlockedStream *stream)
{
  if (stream->section_count == 0)
    {
      stream->min_required_insert_count = 0;
      return;
    }

  stream->min_required_insert_count = stream->sections[0].required_insert_count;
  for (size_t i = 1; i < stream->section_count; i++)
    {
      if (stream->sections[i].required_insert_count
          < stream->min_required_insert_count)
        stream->min_required_insert_count
            = stream->sections[i].required_insert_count;
    }
}

/* ============================================================================
 * PUBLIC API IMPLEMENTATION
 * ============================================================================
 */

SocketQPACK_BlockedManager_T
SocketQPACK_BlockedManager_new (Arena_T arena,
                                const SocketQPACK_BlockedConfig *config)
{
  SocketQPACK_BlockedManager_T manager;

  if (arena == NULL)
    return NULL;

  manager = ALLOC (arena, sizeof (struct SocketQPACK_BlockedManager));
  if (manager == NULL)
    return NULL;

  memset (manager, 0, sizeof (struct SocketQPACK_BlockedManager));
  manager->arena = arena;

  /* Apply configuration or defaults */
  if (config != NULL)
    {
      manager->max_blocked_streams = config->max_blocked_streams;
      manager->max_blocked_bytes = config->max_blocked_bytes;
    }
  else
    {
      manager->max_blocked_streams = SOCKETQPACK_MAX_BLOCKED_STREAMS;
      manager->max_blocked_bytes = QPACK_DEFAULT_MAX_BLOCKED_BYTES;
    }

  /* Allocate initial streams array */
  manager->stream_alloc = QPACK_BLOCKED_INITIAL_CAPACITY;
  manager->streams = ALLOC (
      arena, manager->stream_alloc * sizeof (SocketQPACK_BlockedStream));
  if (manager->streams == NULL)
    return NULL;

  return manager;
}

bool
SocketQPACK_would_block (uint64_t required_insert_count,
                         uint64_t current_insert_count)
{
  return required_insert_count > current_insert_count;
}

SocketQPACK_BlockedResult
SocketQPACK_queue_blocked (SocketQPACK_BlockedManager_T manager,
                           uint64_t stream_id,
                           uint64_t ric,
                           const unsigned char *data,
                           size_t data_len)
{
  SocketQPACK_BlockedStream *stream;
  SocketQPACK_BlockedSection *section;
  unsigned char *data_copy;
  size_t new_total;
  bool is_new_stream;

  if (manager == NULL)
    return QPACK_BLOCKED_ERR_NULL_PARAM;

  if (data_len > 0 && data == NULL)
    return QPACK_BLOCKED_ERR_NULL_PARAM;

  /* Check byte limit */
  if (!SocketSecurity_check_add (
          manager->total_blocked_bytes, data_len, &new_total))
    return QPACK_BLOCKED_LIMIT_BYTES;

  if (new_total > manager->max_blocked_bytes)
    return QPACK_BLOCKED_LIMIT_BYTES;

  /* Find or create stream */
  stream = find_blocked_stream (manager, stream_id);
  is_new_stream = (stream == NULL);

  if (is_new_stream)
    {
      /* Check stream count limit for new streams */
      if (manager->stream_count >= manager->max_blocked_streams)
        return QPACK_BLOCKED_LIMIT_STREAMS;

      /* Ensure capacity */
      if (!ensure_stream_capacity (manager))
        return QPACK_BLOCKED_ERR_INTERNAL;

      /* Initialize new stream */
      stream = &manager->streams[manager->stream_count];
      memset (stream, 0, sizeof (SocketQPACK_BlockedStream));
      stream->stream_id = stream_id;
      stream->min_required_insert_count = ric;
      manager->stream_count++;

      /* Update peak count */
      if (manager->stream_count > manager->peak_blocked_count)
        manager->peak_blocked_count = manager->stream_count;
    }

  /* Ensure section capacity */
  SocketQPACK_BlockedResult cap_result
      = ensure_section_capacity (manager, stream);
  if (cap_result != QPACK_BLOCKED_OK)
    {
      /* Remove empty stream if we just created it */
      if (is_new_stream && stream->section_count == 0)
        manager->stream_count--;
      return cap_result;
    }

  /* Copy data */
  if (data_len > 0)
    {
      data_copy = ALLOC (manager->arena, data_len);
      if (data_copy == NULL)
        {
          if (is_new_stream && stream->section_count == 0)
            manager->stream_count--;
          return QPACK_BLOCKED_ERR_INTERNAL;
        }
      memcpy (data_copy, data, data_len);
    }
  else
    {
      data_copy = NULL;
    }

  /* Add section */
  section = &stream->sections[stream->section_count];
  section->required_insert_count = ric;
  section->data = data_copy;
  section->data_len = data_len;
  stream->section_count++;

  /* Update byte counts */
  stream->total_bytes += data_len;
  manager->total_blocked_bytes += data_len;

  /* Update minimum RIC */
  if (ric < stream->min_required_insert_count)
    stream->min_required_insert_count = ric;

  return QPACK_BLOCKED_OK;
}

SocketQPACK_BlockedResult
SocketQPACK_process_unblocked (SocketQPACK_BlockedManager_T manager,
                               uint64_t current_insert_count,
                               SocketQPACK_UnblockCallback callback,
                               void *user_data,
                               size_t *unblocked_count)
{
  size_t count;
  size_t i;
  int cb_result;

  if (manager == NULL)
    return QPACK_BLOCKED_ERR_NULL_PARAM;

  if (callback == NULL)
    return QPACK_BLOCKED_ERR_NULL_PARAM;

  count = 0;
  i = 0;

  /* Process all streams */
  while (i < manager->stream_count)
    {
      SocketQPACK_BlockedStream *stream = &manager->streams[i];
      bool stream_modified = false;
      size_t j = 0;

      /* Process all unblocked sections in this stream (FIFO order) */
      while (j < stream->section_count)
        {
          SocketQPACK_BlockedSection *section = &stream->sections[j];

          /* Check if section can be unblocked */
          if (section->required_insert_count <= current_insert_count)
            {
              /* Call the unblock callback */
              cb_result = callback (stream->stream_id,
                                    section->data,
                                    section->data_len,
                                    section->required_insert_count,
                                    user_data);

              /* Remove section regardless of callback result */
              remove_blocked_section (manager, stream, j);
              stream_modified = true;
              count++;
              manager->total_unblock_count++;

              /* Stop if callback returns non-zero */
              if (cb_result != 0)
                {
                  if (unblocked_count != NULL)
                    *unblocked_count = count;
                  return QPACK_BLOCKED_ERR_INTERNAL;
                }

              /* Don't increment j - next section shifted to current position */
            }
          else
            {
              j++;
            }
        }

      /* Update min RIC if stream was modified */
      if (stream_modified)
        update_stream_min_ric (stream);

      /* Remove empty stream */
      if (stream->section_count == 0)
        {
          remove_blocked_stream (manager, i);
          /* Don't increment i - next stream shifted to current position */
        }
      else
        {
          i++;
        }
    }

  if (unblocked_count != NULL)
    *unblocked_count = count;

  return QPACK_BLOCKED_OK;
}

SocketQPACK_BlockedResult
SocketQPACK_cancel_blocked_stream (SocketQPACK_BlockedManager_T manager,
                                   uint64_t stream_id)
{
  if (manager == NULL)
    return QPACK_BLOCKED_ERR_NULL_PARAM;

  /* Find and remove stream */
  for (size_t i = 0; i < manager->stream_count; i++)
    {
      if (manager->streams[i].stream_id == stream_id)
        {
          remove_blocked_stream (manager, i);
          return QPACK_BLOCKED_OK;
        }
    }

  /* Not found is not an error - stream may not have been blocked */
  return QPACK_BLOCKED_OK;
}

size_t
SocketQPACK_get_blocked_stream_count (SocketQPACK_BlockedManager_T manager)
{
  if (manager == NULL)
    return 0;
  return manager->stream_count;
}

size_t
SocketQPACK_get_blocked_bytes (SocketQPACK_BlockedManager_T manager)
{
  if (manager == NULL)
    return 0;
  return manager->total_blocked_bytes;
}

uint64_t
SocketQPACK_get_peak_blocked_count (SocketQPACK_BlockedManager_T manager)
{
  if (manager == NULL)
    return 0;
  return manager->peak_blocked_count;
}

uint64_t
SocketQPACK_get_total_unblock_count (SocketQPACK_BlockedManager_T manager)
{
  if (manager == NULL)
    return 0;
  return manager->total_unblock_count;
}

bool
SocketQPACK_is_stream_blocked (SocketQPACK_BlockedManager_T manager,
                               uint64_t stream_id)
{
  if (manager == NULL)
    return false;
  return find_blocked_stream (manager, stream_id) != NULL;
}

uint64_t
SocketQPACK_get_min_blocked_ric (SocketQPACK_BlockedManager_T manager)
{
  uint64_t min_ric;

  if (manager == NULL || manager->stream_count == 0)
    return 0;

  min_ric = manager->streams[0].min_required_insert_count;
  for (size_t i = 1; i < manager->stream_count; i++)
    {
      if (manager->streams[i].min_required_insert_count < min_ric)
        min_ric = manager->streams[i].min_required_insert_count;
    }

  return min_ric;
}

const char *
SocketQPACK_blocked_result_string (SocketQPACK_BlockedResult result)
{
  switch (result)
    {
    case QPACK_BLOCKED_OK:
      return "OK";
    case QPACK_BLOCKED_WOULD_BLOCK:
      return "Would block";
    case QPACK_BLOCKED_LIMIT_STREAMS:
      return "Max blocked streams exceeded";
    case QPACK_BLOCKED_LIMIT_BYTES:
      return "Max blocked bytes exceeded";
    case QPACK_BLOCKED_ERR_NULL_PARAM:
      return "NULL parameter";
    case QPACK_BLOCKED_ERR_NOT_FOUND:
      return "Stream not found";
    case QPACK_BLOCKED_ERR_INTERNAL:
      return "Internal error";
    case QPACK_BLOCKED_ERR_INVALID_RIC:
      return "Invalid Required Insert Count";
    case QPACK_BLOCKED_ERR_SECTION_LIMIT:
      return "Per-stream section limit exceeded";
    default:
      return "Unknown error";
    }
}
