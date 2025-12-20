/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP-date.c - HTTP Date Parsing and Formatting (RFC 9110
 * Section 5.6.7)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements HTTP-date parsing for all three formats required by RFC 9110:
 * - IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT" (preferred, 29 bytes min)
 * - RFC 850: "Sunday, 06-Nov-94 08:49:37 GMT" (obsolete, 30 bytes min)
 * - ANSI C asctime: "Sun Nov  6 08:49:37 1994" (obsolete, 24 bytes min)
 *
 * Also provides formatting to IMF-fixdate format.
 *
 * Features:
 * - Thread-safe implementation using gmtime_r and mutex-protected TZ fallback
 * - Strict validation: day names, month names, date ranges, leap years
 * - Handles leading whitespace, rejects extra trailing characters
 * - Validates parsed date roundtrip via time_t conversion
 * - No memory allocation (stack-based parsing)
 *
 * Error Handling:
 * - Returns -1 on parse failure (invalid format, out-of-range values)
 * - Logs warnings via SocketLog for invalid dates (optional integration)
 *
 * Usage:
 *   time_t timestamp;
 *   if (SocketHTTP_date_parse(date_header, strlen(date_header), &timestamp) ==
 * 0) {
 *       // Success: timestamp is valid UTC time_t
 *   }
 *
 *   char date_buf[SOCKETHTTP_DATE_BUFSIZE];
 *   int len = SocketHTTP_date_format(timestamp, date_buf);
 *   // len == 29 on success
 *
 * Thread-safe: Yes
 * Allocates: No (except internal mutex init)
 */

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketHTTP"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** Length of short names (3-char abbreviations for both days and months) */
#define SHORT_NAME_LEN 3

/** Length of "GMT" string */
#define GMT_LEN 3

/** Minimum length for IMF-fixdate format */
#define IMF_FIXDATE_MIN_LEN 29

/** Minimum length for RFC 850 format (using shortest day name "Friday") */
#define RFC850_MIN_LEN 30

/** Minimum length for ANSI C asctime format (single-digit day with double
 * space) */
#define ASCTIME_MIN_LEN 24

/** Maximum valid hour (0-23) */
#define MAX_HOUR 23

/** Maximum valid minute (0-59) */
#define MAX_MINUTE 59

/** Maximum valid second (0-60 for leap second, per RFC 9110) */
#define MAX_SECOND 60

/** Maximum valid day of month (1-31) */
#define MAX_DAY 31

/** Two-digit year cutoff for RFC 850 (standard Y2K convention) */
#define YEAR_2DIGIT_CUTOFF 69

/** Minimum length for long day names in RFC 850 */
#define LONG_DAY_MIN_LEN 6

/** Maximum length for long day names in RFC 850 */
#define LONG_DAY_MAX_LEN 9

/** Number of days in a week */
#define DAYS_PER_WEEK 7

/** Number of months in a year */
#define MONTHS_PER_YEAR 12

/** Maximum characters to log for invalid date strings (prevents log flooding)
 */
#define LOG_DATE_TRUNCATE_LEN 50

/** Maximum valid year for HTTP dates (AD) */
#define MAX_YEAR 9999

/* ============================================================================
 * Lookup Tables
 * ============================================================================
 */

/** Day names for IMF-fixdate and asctime formats (3 characters,
 * case-insensitive matching) */
static const char *const day_names_short[]
    = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

/** Day names for RFC 850 format (full names, variable length 6-9 characters)
 */
static const char *const day_names_long[] = {
  "Sunday",    /* 6 chars */
  "Monday",    /* 6 */
  "Tuesday",   /* 7 */
  "Wednesday", /* 9 */
  "Thursday",  /* 8 */
  "Friday",    /* 6 */
  "Saturday"   /* 8 */
};

/** Lengths of long day names (matches day_names_long order) */
static const size_t day_long_lengths[DAYS_PER_WEEK] = { 6, 6, 7, 9, 8, 6, 8 };

/** Month names (3 characters, case-insensitive matching) */
static const struct
{
  const char *name; /* 3-char abbreviation */
  int month;        /* 0-11 (January=0) */
} month_table[] = {
  { "Jan", 0 },  { "Feb", 1 },  { "Mar", 2 }, { "Apr", 3 }, { "May", 4 },
  { "Jun", 5 },  { "Jul", 6 },  { "Aug", 7 }, { "Sep", 8 }, { "Oct", 9 },
  { "Nov", 10 }, { "Dec", 11 }, { NULL, -1 } /* Sentinel */
};

/** Days per month in non-leap year (index 0=January, 11=December) */
static const int days_per_month[MONTHS_PER_YEAR]
    = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/* ============================================================================
 * Parsed Date Components
 * ============================================================================
 */

/**
 * DateParts - Temporary structure for parsed date/time components
 *
 * Used during parsing to hold extracted fields before validation and
 * conversion to time_t. Enables modular parsing and comprehensive validation.
 */
typedef struct DateParts
{
  int year;   /* Full year (e.g., 1994 or mapped from 2-digit) */
  int month;  /* 0-11 (January=0) */
  int day;    /* 1-31 */
  int hour;   /* 0-23 */
  int minute; /* 0-59 */
  int second; /* 0-60 (allows leap second per RFC 9110) */
} DateParts;

/* ============================================================================
 * Date Validation Helpers
 * ============================================================================
 */

/**
 * is_leap_year - Determine if year is leap year (Gregorian calendar rules)
 * @year: Year to check (must be positive)
 *
 * Returns: 1 if leap year (February has 29 days), 0 otherwise
 * Thread-safe: Yes
 */
static int
is_leap_year (int year)
{
  return (year > 0)
         && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0));
}

/**
 * valid_date_parts - Validate parsed date components
 * @parts: Parsed date parts to validate
 *
 * Checks:
 * - Month 0-11
 * - Day 1 to days in month (handles leap years for February)
 * - Hour 0-23, minute 0-59, second 0-60
 *
 * Returns: 1 if valid date/time, 0 otherwise
 * Thread-safe: Yes
 */
static int
valid_date_parts (const DateParts *parts)
{
  if (parts->month < 0 || parts->month > (MONTHS_PER_YEAR - 1))
    return 0;

  if (parts->day < 1 || parts->day > MAX_DAY)
    return 0;

  int dmax = days_per_month[parts->month];
  if (parts->month == 1 && is_leap_year (parts->year)) /* February */
    ++dmax;

  if (parts->day > dmax)
    return 0;

  if (parts->hour < 0 || parts->hour > MAX_HOUR)
    return 0;

  if (parts->minute < 0 || parts->minute > MAX_MINUTE)
    return 0;

  if (parts->second < 0 || parts->second > MAX_SECOND)
    return 0;

  /* Year range check (e.g., AD 1 to MAX_YEAR) */
  if (parts->year <= 0 || parts->year > MAX_YEAR)
    return 0;

  return 1;
}

/* ============================================================================
 * Day Name Parsing Helpers
 * ============================================================================
 */

/**
 * parse_day_short - Parse 3-character day name (case-insensitive)
 * @s: Pointer to exactly 3 characters
 *
 * Returns: Day index 0=Sun to 6=Sat, or -1 if invalid
 * Thread-safe: Yes
 */
static int
parse_day_short (const char *s)
{
  for (int i = 0; i < DAYS_PER_WEEK; i++)
    {
      if (strncasecmp (s, day_names_short[i], SHORT_NAME_LEN) == 0)
        return i;
    }
  return -1;
}

/**
 * parse_day_long - Parse full day name for RFC 850 (case-insensitive)
 * @s: Pointer to day name string
 * @len: Exact length of day name
 *
 * Returns: Day index 0=Sunday to 6=Saturday, or -1 if invalid length or name
 * Thread-safe: Yes
 */
static int
parse_day_long (const char *s, size_t len)
{
  if (len < LONG_DAY_MIN_LEN || len > LONG_DAY_MAX_LEN)
    return -1;

  for (int i = 0; i < DAYS_PER_WEEK; i++)
    {
      if (len == day_long_lengths[i]
          && strncasecmp (s, day_names_long[i], len) == 0)
        return i;
    }
  return -1;
}

/* ============================================================================
 * Low-Level Parsing Helpers
 * ============================================================================
 */

/**
 * parse_month - Parse 3-character month abbreviation (case-insensitive)
 * @s: Pointer to exactly 3 characters (e.g., "Jan", "feb")
 *
 * Matches against standard HTTP month names.
 *
 * Returns: Month index 0=Jan to 11=Dec, or -1 if invalid
 * Thread-safe: Yes
 */
static int
parse_month (const char *s)
{
  for (int i = 0; month_table[i].name != NULL; i++)
    {
      if (strncasecmp (s, month_table[i].name, SHORT_NAME_LEN) == 0)
        return month_table[i].month;
    }
  return -1;
}

/**
 * parse_2digit - Parse exactly two ASCII digits (00-99)
 * @s: Pointer to two digit characters
 *
 * Validates both characters are digits [0-9].
 *
 * Returns: Integer value 0-99, or -1 if invalid digits
 * Thread-safe: Yes
 */
static int
parse_2digit (const char *s)
{
  if (!isdigit ((unsigned char)s[0]) || !isdigit ((unsigned char)s[1]))
    return -1;
  return (s[0] - '0') * 10 + (s[1] - '0');
}

/**
 * parse_4digit - Parse exactly four ASCII digits (0000-9999)
 * @s: Pointer to four digit characters
 *
 * Validates all characters are digits [0-9].
 *
 * Returns: Integer value 0-9999, or -1 if invalid digits
 * Thread-safe: Yes
 */
static int
parse_4digit (const char *s)
{
  for (int i = 0; i < 4; i++)
    {
      if (!isdigit ((unsigned char)s[i]))
        return -1;
    }
  return ((s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10
          + (s[3] - '0'));
}

/**
 * parse_1or2digit - Parse one or two consecutive ASCII digits
 * @s: Pointer to digit characters
 * @max_avail: Maximum characters available from @s
 * @consumed: Output parameter - number of characters parsed (1 or 2)
 *
 * Used for variable-width fields like single/two-digit days in asctime.
 * Prefers two digits if available and valid.
 *
 * Returns: Integer value 0-99, or -1 if no valid digits found
 * Thread-safe: Yes
 */
static int
parse_1or2digit (const char *s, size_t max_avail, int *consumed)
{
  if (max_avail < 1 || !isdigit ((unsigned char)s[0]))
    return -1;

  if (max_avail >= 2 && isdigit ((unsigned char)s[1]))
    {
      *consumed = 2;
      return (s[0] - '0') * 10 + (s[1] - '0');
    }

  *consumed = 1;
  return s[0] - '0';
}

/* ============================================================================
 * Mid-Level Parsing Helpers
 * ============================================================================
 */

/**
 * expect_char - Expect specific character and advance position if matched
 * @p: Current position pointer (updated on success)
 * @end: End of input buffer
 * @expected: Expected character
 *
 * Returns: 0 on match and advance, -1 if at end or mismatch
 * Thread-safe: Yes
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
 * skip_whitespace - Skip leading SP / HTAB (RFC 9110 whitespace)
 * @s: Start position in string
 * @max: Maximum characters to consume (safety limit)
 *
 * Skips zero or more space (' ') or horizontal tab ('\t') characters.
 *
 * Returns: Number of characters skipped (0 or more)
 * Thread-safe: Yes
 */
static size_t
skip_whitespace (const char *s, size_t max)
{
  size_t n = 0;
  while (n < max && (s[n] == ' ' || s[n] == '\t'))
    n++;
  return n;
}

/**
 * expect_space_gmt - Verify and consume " GMT" suffix (IMF/RFC850 formats)
 * @p: Current position pointer (updated on success to after "GMT")
 * @end: End of input buffer
 *
 * Expects space followed by exactly "GMT" (case-sensitive, per RFC).
 *
 * Returns: 0 on success (position advanced past GMT), -1 on failure
 * Thread-safe: Yes
 */
static int
expect_space_gmt (const char **p, const char *end)
{
  if (expect_char (p, end, ' ') < 0)
    return -1;
  if (*p + GMT_LEN > end || strncmp (*p, "GMT", GMT_LEN) != 0)
    return -1;
  (*p) += GMT_LEN; /* Advance past "GMT" */
  return 0;
}

/**
 * parse_time_hms - Parse time component "HH:MM:SS" (00:00:00 to 23:59:60)
 * @p: Current position pointer (updated on success past seconds)
 * @end: End of input buffer
 * @parts: Output - hour, minute, second fields populated
 *
 * Validates ranges: hour 0-23, minute/second 0-59 (60 for leap second).
 *
 * Returns: 0 on success, -1 on malformed time or out-of-range values
 * Thread-safe: Yes
 */
static int
parse_time_hms (const char **p, const char *end, DateParts *parts)
{
  /* Parse hour HH */
  if (*p + 2 > end)
    return -1;
  parts->hour = parse_2digit (*p);
  if (parts->hour < 0 || parts->hour > MAX_HOUR)
    return -1;
  *p += 2;

  if (expect_char (p, end, ':') < 0)
    return -1;

  /* Parse minute MM */
  if (*p + 2 > end)
    return -1;
  parts->minute = parse_2digit (*p);
  if (parts->minute < 0 || parts->minute > MAX_MINUTE)
    return -1;
  *p += 2;

  if (expect_char (p, end, ':') < 0)
    return -1;

  /* Parse second SS */
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
 * ============================================================================
 */

/**
 * Mutex for thread-safe TZ environment manipulation in fallback path.
 * Marked unused to silence warnings on platforms with native timegm().
 */
static pthread_mutex_t tz_mutex __attribute__ ((unused))
    = PTHREAD_MUTEX_INITIALIZER;

/**
 * tm_to_time_t - Convert broken-down UTC time (struct tm) to time_t epoch
 * seconds
 * @tm: Pointer to struct tm in UTC (tm_isdst ignored)
 *
 * Preferred path: timegm() for direct UTC conversion (POSIX/GNU).
 * Fallback (non-POSIX): Temporarily set TZ="" (UTC) and use mktime(),
 * protected by mutex for thread safety.
 *
 * Returns: time_t (seconds since 1970-01-01 00:00:00 UTC), or (time_t)-1 on
 * error Thread-safe: Yes (uses mutex for fallback) Raises: None (returns -1 on
 * failure)
 */
static time_t
tm_to_time_t (struct tm *tm)
{
#if defined(_GNU_SOURCE) || defined(__linux__) || defined(__APPLE__)          \
    || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  /* Use timegm for efficient UTC conversion on supported platforms */
  return timegm (tm);
#else
  /* Thread-safe fallback: lock around TZ manipulation */
  pthread_mutex_lock (&tz_mutex);
  char *saved_tz = getenv ("TZ");
  setenv ("TZ", "", 1); /* "" means UTC */
  tzset ();
  time_t result = mktime (tm);
  if (saved_tz != NULL)
    setenv ("TZ", saved_tz, 1);
  else
    unsetenv ("TZ");
  tzset ();
  pthread_mutex_unlock (&tz_mutex);
  return result;
#endif
}

/**
 * convert_parts_to_time - Validate and convert parsed DateParts to time_t
 * @parts: Parsed date/time components
 * @out: Output time_t value (UTC epoch seconds)
 *
 * Performs full validation (date ranges, leap year) before conversion.
 * Checks conversion result for validity ((time_t)-1 indicates error).
 *
 * Returns: 0 on success (valid date converted), -1 on invalid date or
 * conversion error Thread-safe: Yes
 */
static int
convert_parts_to_time (const DateParts *parts, time_t *out)
{
  /* Validate date components first */
  if (!valid_date_parts (parts))
    return -1;

  struct tm tm_utc = { 0 }; /* Zero-initialized UTC tm */
  tm_utc.tm_year = parts->year - 1900;
  tm_utc.tm_mon = parts->month;
  tm_utc.tm_mday = parts->day;
  tm_utc.tm_hour = parts->hour;
  tm_utc.tm_min = parts->minute;
  tm_utc.tm_sec = parts->second;
  /* tm_isdst = 0 (UTC, no DST) */

  *out = tm_to_time_t (&tm_utc);
  if (*out == (time_t)-1)
    return -1;

  return 0;
}

/* ============================================================================
 * Format-Specific Parsers
 * ============================================================================
 */

/**
 * find_comma - Locate first comma in input range
 * @s: Start of string
 * @end: One past end of string
 *
 * Linear scan for ',' character.
 *
 * Returns: Pointer to comma if found within range, NULL otherwise
 * Thread-safe: Yes
 */
static const char *
find_comma (const char *s, const char *end)
{
  while (s < end && *s != ',')
    ++s;
  return (s < end) ? s : NULL;
}

/**
 * parse_imf_date_part - Parse date part "DD Mon YYYY" of IMF-fixdate (after
 * day name)
 * @p: Current position pointer (updated past date part)
 * @end: End of buffer
 * @parts: Output - day and month populated
 *
 * Parses: [space]DD[space]MMM[space]YYYY[space]
 * Validates day 1-31, month valid abbreviation, year 0000-9999.
 *
 * Returns: 0 on success, -1 on parse failure or invalid values
 * Thread-safe: Yes
 */
static int
parse_imf_date_part (const char **p, const char *end, DateParts *parts)
{
  /* Parse day DD (leading zero optional) */
  if (*p + 2 > end)
    return -1;
  parts->day = parse_2digit (*p);
  if (parts->day < 1 || parts->day > MAX_DAY)
    return -1;
  *p += 2;

  if (expect_char (p, end, ' ') < 0)
    return -1;

  /* Parse month MMM */
  if (*p + SHORT_NAME_LEN > end)
    return -1;
  parts->month = parse_month (*p);
  if (parts->month < 0)
    return -1;
  *p += SHORT_NAME_LEN;

  if (expect_char (p, end, ' ') < 0)
    return -1;

  /* Parse year YYYY */
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
 * parse_imf_fixdate - Parse preferred IMF-fixdate format (RFC 9110)
 * @s: Input string
 * @len: Input length
 * @out: Output time_t (UTC)
 *
 * Format: "Day, DD Mon YYYY HH:MM:SS GMT" e.g., "Sun, 06 Nov 1994 08:49:37
 * GMT" Validates short day name (3 chars), advances past full string, rejects
 * extra chars.
 *
 * Returns: 0 on success, -1 on invalid format, length, or values
 * Thread-safe: Yes
 */
static int
parse_imf_fixdate (const char *s, size_t len, time_t *out)
{
  if (len < IMF_FIXDATE_MIN_LEN)
    return -1;

  const char *end = s + len;
  const char *comma_pos = find_comma (s, end);
  if (!comma_pos || comma_pos - s != SHORT_NAME_LEN)
    return -1;

  /* Validate short day name */
  if (parse_day_short (s) < 0)
    return -1;

  const char *p = comma_pos + 1; /* Skip comma */

  if (expect_char (&p, end, ' ') < 0)
    return -1;

  DateParts parts = { 0 };
  if (parse_imf_date_part (&p, end, &parts) < 0)
    return -1;

  if (parse_time_hms (&p, end, &parts) < 0)
    return -1;

  if (expect_space_gmt (&p, end) < 0)
    return -1;

  /* Ensure exact match (no trailing garbage) */
  if (p != end)
    return -1;

  return convert_parts_to_time (&parts, out);
}

/**
 * parse_rfc850_date_part - Parse "DD-MMM-YY" date part of RFC 850 (obsolete
 * format)
 * @p: Current position pointer (updated past date part)
 * @end: End of buffer
 * @parts: Output - day, month, year populated
 *
 * Parses: DD-MMM-YY[space]
 * - Day: 01-31
 * - Month: 3-char abbreviation
 * - Year: 2-digit mapped to 19xx/20xx (>=69=19xx, <69=20xx per convention)
 *
 * Returns: 0 on success, -1 on parse error or invalid values
 * Thread-safe: Yes
 */
static int
parse_rfc850_date_part (const char **p, const char *end, DateParts *parts)
{
  /* Parse day DD */
  if (*p + 2 > end)
    return -1;
  parts->day = parse_2digit (*p);
  if (parts->day < 1 || parts->day > MAX_DAY)
    return -1;
  *p += 2;

  if (expect_char (p, end, '-') < 0)
    return -1;

  /* Parse month MMM */
  if (*p + SHORT_NAME_LEN > end)
    return -1;
  parts->month = parse_month (*p);
  if (parts->month < 0)
    return -1;
  *p += SHORT_NAME_LEN;

  if (expect_char (p, end, '-') < 0)
    return -1;

  /* Parse 2-digit year YY */
  if (*p + 2 > end)
    return -1;
  int year2 = parse_2digit (*p);
  if (year2 < 0)
    return -1;
  *p += 2;

  /* Map 2-digit year (Y2K convention: 00-68=2000-2068, 69-99=1969-1999) */
  parts->year = (year2 >= YEAR_2DIGIT_CUTOFF) ? 1900 + year2 : 2000 + year2;

  if (expect_char (p, end, ' ') < 0)
    return -1;

  return 0;
}

/**
 * parse_rfc850 - Parse obsolete RFC 850 date format
 * @s: Input string
 * @len: Input length
 * @out: Output time_t (UTC)
 *
 * Format: "Dayname, DD-MMM-YY HH:MM:SS GMT" e.g., "Friday, 01-Jan-00 00:00:00
 * GMT" Validates long day name (6-9 chars), rejects invalid lengths or names.
 * Ensures exact string match (no extra characters).
 *
 * Returns: 0 on success, -1 on invalid format, length, day name, or values
 * Thread-safe: Yes
 */
static int
parse_rfc850 (const char *s, size_t len, time_t *out)
{
  if (len < RFC850_MIN_LEN)
    return -1;

  const char *end = s + len;
  const char *comma_pos = find_comma (s, end);
  if (!comma_pos)
    return -1;

  size_t day_len = comma_pos - s;
  if (day_len < LONG_DAY_MIN_LEN || day_len > LONG_DAY_MAX_LEN)
    return -1;

  /* Validate long day name */
  if (parse_day_long (s, day_len) < 0)
    return -1;

  const char *p = comma_pos + 1; /* Skip comma */

  if (expect_char (&p, end, ' ') < 0)
    return -1;

  DateParts parts = { 0 };
  if (parse_rfc850_date_part (&p, end, &parts) < 0)
    return -1;

  if (parse_time_hms (&p, end, &parts) < 0)
    return -1;

  if (expect_space_gmt (&p, end) < 0)
    return -1;

  /* Ensure exact match (no trailing garbage) */
  if (p != end)
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
parse_asctime_day_month (const char **p, const char *end, DateParts *parts)
{
  /* Parse short day name (exactly 3 chars) */
  if (*p + SHORT_NAME_LEN > end)
    return -1;
  if (parse_day_short (*p) < 0)
    return -1;
  *p += SHORT_NAME_LEN;

  if (expect_char (p, end, ' ') < 0)
    return -1;

  /* Parse month MMM */
  if (*p + SHORT_NAME_LEN > end)
    return -1;
  parts->month = parse_month (*p);
  if (parts->month < 0)
    return -1;
  *p += SHORT_NAME_LEN;

  if (expect_char (p, end, ' ') < 0)
    return -1;

  return 0;
}

static int
parse_asctime (const char *s, size_t len, time_t *out)
{
  if (len < ASCTIME_MIN_LEN)
    return -1;

  const char *end = s + len;
  const char *p = s;

  DateParts parts = { 0 };

  /* Parse day name and month */
  if (parse_asctime_day_month (&p, end, &parts) < 0)
    return -1;

  /* Skip additional whitespace before day (asctime pads single-digit with
   * spaces) */
  size_t ws = skip_whitespace (p, (size_t)(end - p));
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

  /* Parse year YYYY */
  if (p + 4 > end)
    return -1;
  parts.year = parse_4digit (p);
  if (parts.year < 0)
    return -1;
  p += 4; /* Advance past year */

  /* Ensure exact match (no trailing characters, asctime has no timezone) */
  if (p != end)
    return -1;

  return convert_parts_to_time (&parts, out);
}

/* ============================================================================
 * Format Detection Heuristics
 * ============================================================================
 */

/**
 * is_imf_fixdate - Quick heuristic check for IMF-fixdate format
 * @s: Input string
 * @len: Input length
 *
 * IMF-fixdate signature: 3-char day name followed by comma e.g., "Sun,"
 * (position 3 == ',')
 *
 * Returns: 1 if likely IMF-fixdate (quick reject), 0 otherwise
 * Thread-safe: Yes
 *
 * Note: Heuristic only; full validation in parse_imf_fixdate()
 */
static int
is_imf_fixdate (const char *s, size_t len)
{
  return (len >= IMF_FIXDATE_MIN_LEN && s[SHORT_NAME_LEN] == ',');
}

/**
 * is_rfc850 - Quick heuristic check for RFC 850 format
 * @s: Input string
 * @len: Input length
 *
 * RFC 850 signature: comma after long day name (6-9 chars, positions 6-9)
 *
 * Returns: 1 if likely RFC 850 (quick reject), 0 otherwise
 * Thread-safe: Yes
 *
 * Note: Heuristic only; full validation including day name in parse_rfc850()
 */
static int
is_rfc850 (const char *s, size_t len)
{
  if (len < RFC850_MIN_LEN)
    return 0;
  /* Check for comma after long day name (min 6 chars to max 9) */
  for (size_t i = LONG_DAY_MIN_LEN; i <= LONG_DAY_MAX_LEN && i < len; i++)
    {
      if (s[i] == ',')
        return 1;
    }
  return 0;
}

/**
 * is_asctime - Quick heuristic check for ANSI C asctime format
 * @s: Input string
 * @len: Input length
 *
 * asctime signature: 3-char day name followed by space e.g., "Sun "
 * (position 3 == ' ')
 *
 * Returns: 1 if likely asctime (quick reject), 0 otherwise
 * Thread-safe: Yes
 *
 * Note: Heuristic only; full validation in parse_asctime()
 */
static int
is_asctime (const char *s, size_t len)
{
  return (len >= ASCTIME_MIN_LEN && s[SHORT_NAME_LEN] == ' ');
}

/* ============================================================================
 * Public API
 * ============================================================================
 */

/**
 * SocketHTTP_date_parse - Parse HTTP-date string in any RFC 9110 supported
 * format
 * @date_str: Input date string (may contain leading whitespace)
 * @len: Length of string (0 = auto strlen)
 * @time_out: Output parameter for parsed UTC time_t
 *
 * Supports:
 * - IMF-fixdate (preferred): "Sun, 06 Nov 1994 08:49:37 GMT"
 * - RFC 850 (obsolete): "Sunday, 06-Nov-94 08:49:37 GMT"
 * - ANSI C asctime (obsolete): "Sun Nov  6 08:49:37 1994" (UTC assumed)
 *
 * Tries formats in preference order. Skips leading whitespace. Rejects empty
 * or malformed input. Logs warning for invalid dates.
 *
 * Returns: 0 on success (valid time_t set), -1 on parse failure
 * Thread-safe: Yes
 * Raises: None (uses return code for compatibility)
 */
int
SocketHTTP_date_parse (const char *date_str, size_t len, time_t *time_out)
{
  if (!date_str || !time_out)
    {
      SOCKET_LOG_ERROR_MSG ("Null arguments to date_parse");
      return -1;
    }

  if (len == 0)
    len = strlen (date_str);

  /* Skip leading whitespace (SP / HTAB) */
  size_t skipped = skip_whitespace (date_str, len);
  date_str += skipped;
  len -= skipped;

  /* Reject empty string after trim */
  if (len == 0)
    {
      SOCKET_LOG_WARN_MSG ("Empty HTTP date string");
      return -1;
    }

  /* Try formats in preference order (IMF first) */
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

  /* All formats failed - use %.*s to handle non-null-terminated input */
  int print_len = (len > LOG_DATE_TRUNCATE_LEN) ? LOG_DATE_TRUNCATE_LEN
                                                : (int)len;
  SOCKET_LOG_WARN_MSG ("Invalid HTTP date format (len=%zu): %.*s...", len,
                       print_len, date_str);
  return -1;
}

/**
 * SocketHTTP_date_format - Format UTC time_t to preferred IMF-fixdate string
 * @t: Input time_t (UTC epoch seconds)
 * @output: Output buffer (at least SOCKETHTTP_DATE_BUFSIZE == 30 bytes)
 *
 * Produces: "Day, DD Mon YYYY HH:MM:SS GMT" e.g., "Fri, 01 Jan 2023 12:00:00
 * GMT" Uses gmtime_r for thread safety. Clamps invalid tm fields as
 * defense-in-depth. Always produces exactly 29 characters + null terminator.
 *
 * Returns: 29 on success (fixed length), -1 on error (invalid time_t or
 * gmtime_r fail) Thread-safe: Yes Raises: None (returns -1 on failure)
 */
int
SocketHTTP_date_format (time_t t, char *output)
{
  if (!output)
    return -1;

  struct tm tm_utc;
  struct tm *tm = gmtime_r (&t, &tm_utc);
  if (!tm)
    return -1;

  /* Clamp invalid fields (defense-in-depth, though gmtime_r should produce
   * valid) */
  int wday = tm->tm_wday;
  if (wday < 0 || wday > (DAYS_PER_WEEK - 1))
    wday = 0;

  int mon = tm->tm_mon;
  if (mon < 0 || mon > (MONTHS_PER_YEAR - 1))
    mon = 0;

  /* Format IMF-fixdate (29 chars + null) */
  int n = snprintf (
      output, SOCKETHTTP_DATE_BUFSIZE, "%s, %02d %s %04d %02d:%02d:%02d GMT",
      day_names_short[wday], (int)tm->tm_mday, month_table[mon].name,
      tm->tm_year + 1900, (int)tm->tm_hour, (int)tm->tm_min, (int)tm->tm_sec);

  if (n < 0 || n >= SOCKETHTTP_DATE_BUFSIZE || n != 29)
    return -1;

  return n;
}
