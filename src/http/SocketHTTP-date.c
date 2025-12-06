/**
 * SocketHTTP-date.c - HTTP Date Parsing (RFC 9110 Section 5.6.7)
 *
 * Part of the Socket Library
 *
 * Implements HTTP-date parsing supporting all three formats required by RFC 9110:
 * - IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT (preferred)
 * - RFC 850: Sunday, 06-Nov-94 08:49:37 GMT (obsolete)
 * - ANSI C: Sun Nov  6 08:49:37 1994 (obsolete)
 */

#include "http/SocketHTTP.h"
#include "http/SocketHTTP-private.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Minimum length for IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT" */
#define IMF_FIXDATE_MIN_LEN 29

/** Minimum length for RFC 850: "X, DD-Mon-YY HH:MM:SS GMT" */
#define RFC850_MIN_LEN 26

/** Minimum length for ANSI C: "Sun Nov  6 08:49:37 1994" */
#define ASCTIME_MIN_LEN 24

/** Maximum valid hour value */
#define MAX_HOUR 23

/** Maximum valid minute value */
#define MAX_MINUTE 59

/** Maximum valid second value (60 for leap second) */
#define MAX_SECOND 60

/** Maximum valid day value */
#define MAX_DAY 31

/** Two-digit year cutoff: years >= 69 are 1900s, < 69 are 2000s */
#define YEAR_2DIGIT_CUTOFF 69

/* ============================================================================
 * Lookup Tables
 * ============================================================================ */

/** Day names for IMF-fixdate format (3 chars) */
static const char *const day_names_short[] = { "Sun", "Mon", "Tue", "Wed",
                                               "Thu", "Fri", "Sat" };

/** Day names for RFC 850 format (full names) */
static const char *const day_names_long[] = { "Sunday",    "Monday",
                                              "Tuesday",   "Wednesday",
                                              "Thursday",  "Friday",
                                              "Saturday" };

/** Month lookup table */
static const struct
{
  const char *name;
  int month; /* 0-11 */
} month_table[] = {
  { "Jan", 0 },  { "Feb", 1 },  { "Mar", 2 },  { "Apr", 3 },
  { "May", 4 },  { "Jun", 5 },  { "Jul", 6 },  { "Aug", 7 },
  { "Sep", 8 },  { "Oct", 9 },  { "Nov", 10 }, { "Dec", 11 },
  { NULL, -1 }
};

/* Suppress unused variable warning for day_names_long */
static const char *const *const suppress_unused_long
    __attribute__ ((unused)) = day_names_long;

/* ============================================================================
 * Parsed Date Components
 * ============================================================================ */

/**
 * DateParts - Holds parsed date/time components before conversion
 *
 * Separating parsing from conversion enables cleaner code and better testing.
 */
typedef struct
{
  int year;   /* Full 4-digit year */
  int month;  /* 0-11 */
  int day;    /* 1-31 */
  int hour;   /* 0-23 */
  int minute; /* 0-59 */
  int second; /* 0-60 (60 for leap second) */
} DateParts;

/* ============================================================================
 * Low-Level Parsing Helpers
 * ============================================================================ */

/**
 * parse_month - Parse 3-character month name (case-insensitive)
 * @s: String to parse (must have at least 3 chars available)
 *
 * Returns: Month index 0-11, or -1 if invalid
 */
static int
parse_month (const char *s)
{
  for (int i = 0; month_table[i].name != NULL; i++)
    {
      if (strncasecmp (s, month_table[i].name, 3) == 0)
        return month_table[i].month;
    }
  return -1;
}

/**
 * parse_2digit - Parse exactly 2 ASCII digit characters
 * @s: String to parse (must have at least 2 chars available)
 *
 * Returns: Parsed value 0-99, or -1 if not two digits
 */
static int
parse_2digit (const char *s)
{
  if (!isdigit ((unsigned char)s[0]) || !isdigit ((unsigned char)s[1]))
    return -1;
  return (s[0] - '0') * 10 + (s[1] - '0');
}

/**
 * parse_4digit - Parse exactly 4 ASCII digit characters
 * @s: String to parse (must have at least 4 chars available)
 *
 * Returns: Parsed value 0-9999, or -1 if not four digits
 */
static int
parse_4digit (const char *s)
{
  for (int i = 0; i < 4; i++)
    {
      if (!isdigit ((unsigned char)s[i]))
        return -1;
    }
  return (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10
         + (s[3] - '0');
}

/**
 * parse_1or2digit - Parse 1 or 2 ASCII digit characters
 * @s: String to parse
 * @max: Maximum characters available
 * @consumed: Output - number of characters consumed
 *
 * Returns: Parsed value 0-99, or -1 if no digits found
 */
static int
parse_1or2digit (const char *s, size_t max, int *consumed)
{
  if (max < 1 || !isdigit ((unsigned char)s[0]))
    return -1;

  if (max >= 2 && isdigit ((unsigned char)s[1]))
    {
      *consumed = 2;
      return (s[0] - '0') * 10 + (s[1] - '0');
    }

  *consumed = 1;
  return s[0] - '0';
}

/* ============================================================================
 * Mid-Level Parsing Helpers
 * ============================================================================ */

/**
 * expect_char - Check for expected character and advance
 * @p: Current position pointer (updated on success)
 * @end: End of input buffer
 * @expected: Character to expect
 *
 * Returns: 0 on success, -1 on failure
 */
static int
expect_char (const char **p, const char *end, char expected)
{
  if (*p >= end || **p != expected)
    return -1;
  (*p)++;
  return 0;
}

/**
 * skip_whitespace - Skip space/tab characters
 * @s: Start of string
 * @max: Maximum characters to skip
 *
 * Returns: Number of characters skipped
 */
static int
skip_whitespace (const char *s, size_t max)
{
  int n = 0;
  while ((size_t)n < max && (s[n] == ' ' || s[n] == '\t'))
    n++;
  return n;
}

/**
 * expect_space_gmt - Verify " GMT" suffix
 * @p: Current position pointer (updated on success)
 * @end: End of input buffer
 *
 * Returns: 0 on success, -1 on failure
 */
static int
expect_space_gmt (const char **p, const char *end)
{
  if (expect_char (p, end, ' ') < 0)
    return -1;
  if (*p + 3 > end || strncmp (*p, "GMT", 3) != 0)
    return -1;
  return 0;
}

/**
 * parse_time_hms - Parse HH:MM:SS time component
 * @p: Current position pointer (updated on success)
 * @end: End of input buffer
 * @parts: Output DateParts (hour, minute, second fields set)
 *
 * Returns: 0 on success, -1 on failure
 */
static int
parse_time_hms (const char **p, const char *end, DateParts *parts)
{
  if (*p + 2 > end)
    return -1;
  parts->hour = parse_2digit (*p);
  if (parts->hour < 0 || parts->hour > MAX_HOUR)
    return -1;
  *p += 2;

  if (expect_char (p, end, ':') < 0)
    return -1;

  if (*p + 2 > end)
    return -1;
  parts->minute = parse_2digit (*p);
  if (parts->minute < 0 || parts->minute > MAX_MINUTE)
    return -1;
  *p += 2;

  if (expect_char (p, end, ':') < 0)
    return -1;

  if (*p + 2 > end)
    return -1;
  parts->second = parse_2digit (*p);
  if (parts->second < 0 || parts->second > MAX_SECOND)
    return -1;
  *p += 2;

  return 0;
}

/* ============================================================================
 * Time Conversion
 * ============================================================================ */

/**
 * tm_to_time_t - Convert struct tm (UTC) to time_t
 * @tm: Broken-down time in UTC
 *
 * Returns: time_t value
 *
 * Uses timegm() on POSIX systems, falls back to TZ manipulation otherwise.
 */
static time_t
tm_to_time_t (struct tm *tm)
{
#if defined(_GNU_SOURCE) || defined(__linux__) || defined(__APPLE__)           \
    || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  return timegm (tm);
#else
  /* Fallback: temporarily set TZ to UTC */
  char *tz = getenv ("TZ");
  setenv ("TZ", "", 1);
  tzset ();
  time_t result = mktime (tm);
  if (tz)
    setenv ("TZ", tz, 1);
  else
    unsetenv ("TZ");
  tzset ();
  return result;
#endif
}

/**
 * convert_parts_to_time - Convert DateParts to time_t
 * @parts: Parsed date components
 * @out: Output time_t value
 *
 * Returns: 0 on success
 */
static int
convert_parts_to_time (const DateParts *parts, time_t *out)
{
  struct tm tm = { 0 };
  tm.tm_year = parts->year - 1900;
  tm.tm_mon = parts->month;
  tm.tm_mday = parts->day;
  tm.tm_hour = parts->hour;
  tm.tm_min = parts->minute;
  tm.tm_sec = parts->second;
  *out = tm_to_time_t (&tm);
  return 0;
}

/* ============================================================================
 * Format-Specific Parsers
 * ============================================================================ */

/**
 * find_comma - Find comma in string
 * @s: Start of string
 * @end: End of string
 *
 * Returns: Pointer to comma, or NULL if not found
 */
static const char *
find_comma (const char *s, const char *end)
{
  while (s < end && *s != ',')
    s++;
  return (s < end) ? s : NULL;
}

/**
 * parse_imf_date_part - Parse date portion of IMF-fixdate
 * @p: Current position (after ", ")
 * @end: End of buffer
 * @parts: Output for day, month, year
 *
 * Parses: "DD MMM YYYY "
 * Returns: 0 on success, -1 on failure
 */
static int
parse_imf_date_part (const char **p, const char *end, DateParts *parts)
{
  /* Parse day (2 digits) */
  if (*p + 2 > end)
    return -1;
  parts->day = parse_2digit (*p);
  if (parts->day < 1 || parts->day > MAX_DAY)
    return -1;
  *p += 2;

  if (expect_char (p, end, ' ') < 0)
    return -1;

  /* Parse month (3 chars) */
  if (*p + 3 > end)
    return -1;
  parts->month = parse_month (*p);
  if (parts->month < 0)
    return -1;
  *p += 3;

  if (expect_char (p, end, ' ') < 0)
    return -1;

  /* Parse year (4 digits) */
  if (*p + 4 > end)
    return -1;
  parts->year = parse_4digit (*p);
  if (parts->year < 0)
    return -1;
  *p += 4;

  if (expect_char (p, end, ' ') < 0)
    return -1;

  return 0;
}

/**
 * parse_imf_fixdate - Parse IMF-fixdate format
 * @s: Input string
 * @len: Input length
 * @out: Output time_t
 *
 * Format: Sun, 06 Nov 1994 08:49:37 GMT
 * Returns: 0 on success, -1 on failure
 */
static int
parse_imf_fixdate (const char *s, size_t len, time_t *out)
{
  if (len < IMF_FIXDATE_MIN_LEN)
    return -1;

  const char *end = s + len;
  const char *p = find_comma (s, end);
  if (!p)
    return -1;
  p++; /* Skip comma */

  if (expect_char (&p, end, ' ') < 0)
    return -1;

  DateParts parts = { 0 };
  if (parse_imf_date_part (&p, end, &parts) < 0)
    return -1;
  if (parse_time_hms (&p, end, &parts) < 0)
    return -1;
  if (expect_space_gmt (&p, end) < 0)
    return -1;

  return convert_parts_to_time (&parts, out);
}

/**
 * parse_rfc850_date_part - Parse date portion of RFC 850
 * @p: Current position (after ", ")
 * @end: End of buffer
 * @parts: Output for day, month, year
 *
 * Parses: "DD-Mon-YY "
 * Returns: 0 on success, -1 on failure
 */
static int
parse_rfc850_date_part (const char **p, const char *end, DateParts *parts)
{
  /* Parse day (2 digits) */
  if (*p + 2 > end)
    return -1;
  parts->day = parse_2digit (*p);
  if (parts->day < 1 || parts->day > MAX_DAY)
    return -1;
  *p += 2;

  if (expect_char (p, end, '-') < 0)
    return -1;

  /* Parse month (3 chars) */
  if (*p + 3 > end)
    return -1;
  parts->month = parse_month (*p);
  if (parts->month < 0)
    return -1;
  *p += 3;

  if (expect_char (p, end, '-') < 0)
    return -1;

  /* Parse 2-digit year */
  if (*p + 2 > end)
    return -1;
  int year2 = parse_2digit (*p);
  if (year2 < 0)
    return -1;
  *p += 2;

  /* Convert 2-digit year: >= 69 -> 1900s, < 69 -> 2000s */
  parts->year = (year2 >= YEAR_2DIGIT_CUTOFF) ? (1900 + year2) : (2000 + year2);

  if (expect_char (p, end, ' ') < 0)
    return -1;

  return 0;
}

/**
 * parse_rfc850 - Parse RFC 850 format
 * @s: Input string
 * @len: Input length
 * @out: Output time_t
 *
 * Format: Sunday, 06-Nov-94 08:49:37 GMT
 * Returns: 0 on success, -1 on failure
 */
static int
parse_rfc850 (const char *s, size_t len, time_t *out)
{
  if (len < RFC850_MIN_LEN)
    return -1;

  const char *end = s + len;
  const char *p = find_comma (s, end);
  if (!p)
    return -1;
  p++; /* Skip comma */

  if (expect_char (&p, end, ' ') < 0)
    return -1;

  DateParts parts = { 0 };
  if (parse_rfc850_date_part (&p, end, &parts) < 0)
    return -1;
  if (parse_time_hms (&p, end, &parts) < 0)
    return -1;
  if (expect_space_gmt (&p, end) < 0)
    return -1;

  return convert_parts_to_time (&parts, out);
}

/**
 * parse_asctime - Parse ANSI C asctime() format
 * @s: Input string
 * @len: Input length
 * @out: Output time_t
 *
 * Format: Sun Nov  6 08:49:37 1994
 * Returns: 0 on success, -1 on failure
 */
static int
parse_asctime (const char *s, size_t len, time_t *out)
{
  if (len < ASCTIME_MIN_LEN)
    return -1;

  const char *end = s + len;
  const char *p = s;

  /* Skip day name (3 chars) + space */
  if (p + 4 > end)
    return -1;
  p += 3;
  if (expect_char (&p, end, ' ') < 0)
    return -1;

  DateParts parts = { 0 };

  /* Parse month (3 chars) */
  if (p + 3 > end)
    return -1;
  parts.month = parse_month (p);
  if (parts.month < 0)
    return -1;
  p += 3;

  /* Skip space(s) before day */
  if (expect_char (&p, end, ' ') < 0)
    return -1;
  int ws = skip_whitespace (p, (size_t)(end - p));
  p += ws;

  /* Parse day (1 or 2 digits) */
  int consumed;
  parts.day = parse_1or2digit (p, (size_t)(end - p), &consumed);
  if (parts.day < 1 || parts.day > MAX_DAY)
    return -1;
  p += consumed;

  if (expect_char (&p, end, ' ') < 0)
    return -1;

  /* Parse time HH:MM:SS */
  if (parse_time_hms (&p, end, &parts) < 0)
    return -1;

  if (expect_char (&p, end, ' ') < 0)
    return -1;

  /* Parse year (4 digits) */
  if (p + 4 > end)
    return -1;
  parts.year = parse_4digit (p);
  if (parts.year < 0)
    return -1;

  return convert_parts_to_time (&parts, out);
}

/* ============================================================================
 * Format Detection
 * ============================================================================ */

/**
 * is_imf_fixdate - Check if string looks like IMF-fixdate
 * @s: Input string
 * @len: Input length
 *
 * IMF-fixdate has comma at position 3 (e.g., "Sun,")
 */
static int
is_imf_fixdate (const char *s, size_t len)
{
  return (len >= 5 && s[3] == ',');
}

/**
 * is_rfc850 - Check if string looks like RFC 850
 * @s: Input string
 * @len: Input length
 *
 * RFC 850 has comma after full day name (position 3-9)
 */
static int
is_rfc850 (const char *s, size_t len)
{
  if (len < 10)
    return 0;
  for (size_t i = 3; i < 10 && i < len; i++)
    {
      if (s[i] == ',')
        return 1;
    }
  return 0;
}

/**
 * is_asctime - Check if string looks like ANSI C asctime
 * @s: Input string
 * @len: Input length
 *
 * asctime has space at position 3 (e.g., "Sun ")
 */
static int
is_asctime (const char *s, size_t len)
{
  return (len >= ASCTIME_MIN_LEN && s[3] == ' ');
}

/* ============================================================================
 * Public API
 * ============================================================================ */

/**
 * SocketHTTP_date_parse - Parse HTTP-date in any RFC 9110 format
 * @date_str: Input date string
 * @len: Length (0 to use strlen)
 * @time_out: Output time_t value
 *
 * Returns: 0 on success, -1 on parse failure
 */
int
SocketHTTP_date_parse (const char *date_str, size_t len, time_t *time_out)
{
  if (!date_str || !time_out)
    return -1;

  if (len == 0)
    len = strlen (date_str);

  /* Skip leading whitespace */
  while (len > 0 && (*date_str == ' ' || *date_str == '\t'))
    {
      date_str++;
      len--;
    }

  /* Try each format based on signature */
  if (is_imf_fixdate (date_str, len))
    {
      if (parse_imf_fixdate (date_str, len, time_out) == 0)
        return 0;
    }

  if (is_rfc850 (date_str, len))
    {
      if (parse_rfc850 (date_str, len, time_out) == 0)
        return 0;
    }

  if (is_asctime (date_str, len))
    {
      if (parse_asctime (date_str, len, time_out) == 0)
        return 0;
    }

  return -1;
}

/**
 * SocketHTTP_date_format - Format time_t as HTTP-date (IMF-fixdate)
 * @t: Time to format
 * @output: Output buffer (must be at least SOCKETHTTP_DATE_BUFSIZE bytes)
 *
 * Returns: Number of characters written (excluding null), or -1 on error
 */
int
SocketHTTP_date_format (time_t t, char *output)
{
  if (!output)
    return -1;

  struct tm *tm = gmtime (&t);
  if (!tm)
    return -1;

  /* Validate and clamp indices for safety */
  int wday = tm->tm_wday;
  if (wday < 0 || wday > 6)
    wday = 0;

  int mon = tm->tm_mon;
  if (mon < 0 || mon > 11)
    mon = 0;

  /* Format: "Sun, 06 Nov 1994 08:49:37 GMT" */
  int n = snprintf (output, SOCKETHTTP_DATE_BUFSIZE,
                    "%s, %02d %s %04d %02d:%02d:%02d GMT",
                    day_names_short[wday], tm->tm_mday, month_table[mon].name,
                    tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);

  if (n < 0 || n >= SOCKETHTTP_DATE_BUFSIZE)
    return -1;

  return n;
}
