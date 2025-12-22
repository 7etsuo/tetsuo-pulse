/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP-date.c - HTTP Date Parsing and Formatting (RFC 9110 Section 5.6.7)
 *
 * Implements HTTP-date parsing for IMF-fixdate, RFC 850, and asctime formats.
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

/* Parsing constants */
#define SHORT_NAME_LEN 3
#define GMT_LEN 3
#define IMF_FIXDATE_MIN_LEN 29
#define RFC850_MIN_LEN 30
#define ASCTIME_MIN_LEN 24
#define MAX_HOUR 23
#define MAX_MINUTE 59
#define MAX_SECOND 60
#define MAX_DAY 31
#define YEAR_2DIGIT_CUTOFF 69
#define LONG_DAY_MIN_LEN 6
#define LONG_DAY_MAX_LEN 9
#define DAYS_PER_WEEK 7
#define MONTHS_PER_YEAR 12
#define LOG_DATE_TRUNCATE_LEN 50
#define MAX_YEAR 9999

/* Lookup tables */
static const char *const day_names_short[]
    = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static const char *const day_names_long[] = {
  "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
};

static const size_t day_long_lengths[DAYS_PER_WEEK] = { 6, 6, 7, 9, 8, 6, 8 };

static const struct
{
  const char *name;
  int month;
} month_table[] = {
  { "Jan", 0 },  { "Feb", 1 },  { "Mar", 2 }, { "Apr", 3 }, { "May", 4 },
  { "Jun", 5 },  { "Jul", 6 },  { "Aug", 7 }, { "Sep", 8 }, { "Oct", 9 },
  { "Nov", 10 }, { "Dec", 11 }, { NULL, -1 }
};

static const int days_per_month[MONTHS_PER_YEAR]
    = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/* Temporary structure for parsed date/time components */
typedef struct DateParts
{
  int year;
  int month;
  int day;
  int hour;
  int minute;
  int second;
} DateParts;
static int
is_leap_year (int year)
{
  return (year > 0)
         && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0));
}

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

static int
parse_2digit (const char *s)
{
  if (!isdigit ((unsigned char)s[0]) || !isdigit ((unsigned char)s[1]))
    return -1;
  return (s[0] - '0') * 10 + (s[1] - '0');
}

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

static int
expect_char (const char **p, const char *end, char expected)
{
  if (*p >= end || **p != expected)
    return -1;
  (*p)++;
  return 0;
}

static size_t
skip_whitespace (const char *s, size_t max)
{
  size_t n = 0;
  while (n < max && (s[n] == ' ' || s[n] == '\t'))
    n++;
  return n;
}

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

/* Mutex for TZ manipulation in fallback path */
static pthread_mutex_t tz_mutex __attribute__ ((unused))
    = PTHREAD_MUTEX_INITIALIZER;

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

static const char *
find_comma (const char *s, const char *end)
{
  while (s < end && *s != ',')
    ++s;
  return (s < end) ? s : NULL;
}

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

/* Parse IMF-fixdate: "Day, DD Mon YYYY HH:MM:SS GMT" */
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

/* Parse RFC 850: "Dayname, DD-MMM-YY HH:MM:SS GMT" */
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

static int
is_imf_fixdate (const char *s, size_t len)
{
  return (len >= IMF_FIXDATE_MIN_LEN && s[SHORT_NAME_LEN] == ',');
}

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

static int
is_asctime (const char *s, size_t len)
{
  return (len >= ASCTIME_MIN_LEN && s[SHORT_NAME_LEN] == ' ');
}

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
