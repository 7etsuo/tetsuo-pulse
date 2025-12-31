/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_json_injection.c - Test JSON injection vulnerability fix
 *
 * Tests for issue #1947: Security vulnerability in
 * Socket_simple_http_server_response_error that allowed JSON injection
 * via unescaped user input.
 *
 * This test verifies the fix by checking that JSON output from
 * Socket_simple_http_server_response_error properly escapes special
 * characters and prevents injection attacks.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "test/Test.h"

/* Test the internal json_escape_string function directly */
/* Since it's not static anymore (for testing), we can call it */
void json_escape_string (char *dest, size_t dest_size, const char *src);

TEST (json_escape_null_input)
{
  char output[256];

  json_escape_string (output, sizeof (output), NULL);
  ASSERT (strcmp (output, "") == 0);
}

TEST (json_escape_empty_string)
{
  char output[256];

  json_escape_string (output, sizeof (output), "");
  ASSERT (strcmp (output, "") == 0);
}

TEST (json_escape_normal_text)
{
  char output[256];

  json_escape_string (output, sizeof (output), "Hello World");
  ASSERT (strcmp (output, "Hello World") == 0);
}

TEST (json_escape_double_quotes)
{
  char output[256];

  json_escape_string (output, sizeof (output), "He said \"hello\"");
  ASSERT (strcmp (output, "He said \\\"hello\\\"") == 0);
}

TEST (json_injection_attempt_quotes)
{
  char output[256];

  /* Test injection attempt with quotes */
  json_escape_string (output, sizeof (output), "foo\",\"injected\":\"attack");
  ASSERT (strstr (output, "\\\"") != NULL);
  ASSERT (strstr (output, "\"injected\"") == NULL);
}

TEST (json_escape_backslash)
{
  char output[256];

  json_escape_string (output, sizeof (output), "C:\\Program Files\\");
  ASSERT (strcmp (output, "C:\\\\Program Files\\\\") == 0);
}

TEST (json_escape_backslash_and_quote)
{
  char output[256];

  json_escape_string (output, sizeof (output), "\\\"");
  ASSERT (strcmp (output, "\\\\\\\"") == 0);
}

TEST (json_escape_newline)
{
  char output[256];

  json_escape_string (output, sizeof (output), "line1\nline2");
  ASSERT (strcmp (output, "line1\\nline2") == 0);
}

TEST (json_escape_carriage_return)
{
  char output[256];

  json_escape_string (output, sizeof (output), "CR\rhere");
  ASSERT (strcmp (output, "CR\\rhere") == 0);
}

TEST (json_escape_tab)
{
  char output[256];

  json_escape_string (output, sizeof (output), "tab\there");
  ASSERT (strcmp (output, "tab\\there") == 0);
}

TEST (json_escape_backspace)
{
  char output[256];

  json_escape_string (output, sizeof (output), "back\bspace");
  ASSERT (strcmp (output, "back\\bspace") == 0);
}

TEST (json_escape_form_feed)
{
  char output[256];

  json_escape_string (output, sizeof (output), "form\ffeed");
  ASSERT (strcmp (output, "form\\ffeed") == 0);
}

TEST (json_escape_null_byte_terminates)
{
  char output[256];
  char null_input[10] = { 'a', '\0', 'b', 0 };

  json_escape_string (output, sizeof (output), null_input);
  ASSERT (strcmp (output, "a") == 0);
}

TEST (json_escape_control_char_0x01)
{
  char output[256];
  char ctrl_input[3] = { 'x', 0x01, 0 };

  json_escape_string (output, sizeof (output), ctrl_input);
  ASSERT (strstr (output, "\\u0001") != NULL);
}

TEST (json_escape_control_char_0x1F)
{
  char output[256];
  char ctrl_input[3] = { 'y', 0x1F, 0 };

  json_escape_string (output, sizeof (output), ctrl_input);
  ASSERT (strstr (output, "\\u001f") != NULL);
}

TEST (json_injection_classic_attack)
{
  char output[256];
  const char *attack = "foo\"},{\"injected\":\"attack\",\"admin\":true";

  json_escape_string (output, sizeof (output), attack);
  ASSERT (strstr (output, "\\\"") != NULL);
  ASSERT (strstr (output, "\"admin\"") == NULL);
}

TEST (json_injection_newline_attack)
{
  char output[256];
  const char *attack = "error\\n\"},{\"evil\":true";

  json_escape_string (output, sizeof (output), attack);
  ASSERT (strstr (output, "\\\\") != NULL);
  ASSERT (strstr (output, "\\n\\\"") != NULL);
}

TEST (json_injection_multiline_attack)
{
  char output[256];
  const char *attack = "msg\"},\n{\"hacked\":true";

  json_escape_string (output, sizeof (output), attack);
  ASSERT (strstr (output, "\\\"") != NULL);
  ASSERT (strstr (output, "\\n") != NULL);
}

TEST (json_escape_buffer_overflow_protection)
{
  char small_buffer[10];
  const char *long_input = "This is a very long string that won't fit";

  json_escape_string (small_buffer, sizeof (small_buffer), long_input);

  ASSERT (strlen (small_buffer) < sizeof (small_buffer));
  ASSERT (small_buffer[sizeof (small_buffer) - 1] == '\0');
}

TEST (json_escape_buffer_overflow_with_escaping)
{
  char small_buffer[10];
  const char *input_with_quotes = "\"quote\"quote\"quote\"";

  json_escape_string (small_buffer, sizeof (small_buffer), input_with_quotes);
  ASSERT (strlen (small_buffer) < sizeof (small_buffer));
}

TEST (json_escape_zero_size_buffer)
{
  char zero_buf[1];

  /* Should not crash */
  json_escape_string (zero_buf, 0, "test");
}

TEST (json_escape_single_char_buffer)
{
  char single_buf[1];

  json_escape_string (single_buf, 1, "test");
  ASSERT (single_buf[0] == '\0');
}

TEST (json_escape_all_special_chars)
{
  char output[256];

  json_escape_string (output, sizeof (output), "\"\\\n\r\t");
  ASSERT (strcmp (output, "\\\"\\\\\\n\\r\\t") == 0);
}

TEST (json_escape_utf8_passthrough)
{
  char output[256];

  json_escape_string (output, sizeof (output), "Hello World Test");
  ASSERT (strcmp (output, "Hello World Test") == 0);
}

TEST (json_escape_realistic_error_message)
{
  char output[512];

  json_escape_string (
      output, sizeof (output), "File not found: /path/to/file.txt");
  ASSERT (strcmp (output, "File not found: /path/to/file.txt") == 0);
}

TEST (json_escape_error_with_quotes)
{
  char output[512];

  json_escape_string (
      output, sizeof (output), "Database error: \"connection timeout\"");
  ASSERT (strstr (output, "\\\"connection timeout\\\"") != NULL);
}

TEST (json_escape_multiline_stack_trace)
{
  char output[512];

  json_escape_string (
      output, sizeof (output), "Stack trace:\nline 1\nline 2\nline 3");
  ASSERT (strstr (output, "\\n") != NULL);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
