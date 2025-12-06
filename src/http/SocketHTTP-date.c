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
#include "core/SocketUtil.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Lookup Tables
 * ============================================================================ */

/**
 * Day names for IMF-fixdate format
 */
static const char *day_names_short[] = { "Sun", "Mon", "Tue", "Wed",
                                         "Thu", "Fri", "Sat" };

/**
 * Day names for RFC 850 format
 */
static const char *day_names_long[] = { "Sunday",    "Monday",   "Tuesday",
                                        "Wednesday", "Thursday", "Friday",
                                        "Saturday" };

/**
 * Month names (case-insensitive lookup)
 */
static const struct
{
  const char *name;
  int month; /* 0-11 */
} month_names[] = {
  { "Jan", 0 },  { "Feb", 1 },  { "Mar", 2 }, { "Apr", 3 },
  { "May", 4 },  { "Jun", 5 },  { "Jul", 6 }, { "Aug", 7 },
  { "Sep", 8 },  { "Oct", 9 },  { "Nov", 10 }, { "Dec", 11 },
  { NULL, -1 }
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * Parse month name (case-insensitive, 3 chars)
 * Returns 0-11 or -1 if invalid
 */
static int
parse_month (const char *s)
{
  for (int i = 0; month_names[i].name != NULL; i++)
    {
      if (strncasecmp (s, month_names[i].name, 3) == 0)
        return month_names[i].month;
    }
  return -1;
}

/**
 * Parse 2-digit number
 */
static int
parse_2digit (const char *s)
{
  if (!isdigit ((unsigned char)s[0]) || !isdigit ((unsigned char)s[1]))
    return -1;
  return (s[0] - '0') * 10 + (s[1] - '0');
}

/**
 * Parse 4-digit number
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
 * Parse 1-2 digit number (for ANSI C day)
 * @s: String to parse
 * @max: Maximum characters available (bounds safety)
 * @consumed: Output - number of characters consumed
 */
static int
parse_day (const char *s, size_t max, int *consumed)
{
  if (max < 1)
    return -1;
  if (isdigit ((unsigned char)s[0]))
    {
      if (max >= 2 && isdigit ((unsigned char)s[1]))
        {
          *consumed = 2;
          return (s[0] - '0') * 10 + (s[1] - '0');
        }
      *consumed = 1;
      return s[0] - '0';
    }
  return -1;
}

/**
 * Skip whitespace, return number of characters skipped
 * @s: Start of string
 * @max: Maximum characters to skip (bounds safety)
 */
static int
skip_ws (const char *s, size_t max)
{
  int n = 0;
  while ((size_t)n < max && (s[n] == ' ' || s[n] == '\t'))
    n++;
  return n;
}

/**
 * Convert struct tm (UTC) to time_t
 * Note: We use timegm on POSIX systems
 */
static time_t
tm_to_time_t (struct tm *tm)
{
#if defined(_GNU_SOURCE) || defined(__linux__) || defined(__APPLE__)        \
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

/* ============================================================================
 * IMF-fixdate Parser
 * Format: Sun, 06 Nov 1994 08:49:37 GMT
 * ============================================================================ */

static int
parse_imf_fixdate (const char *s, size_t len, time_t *out)
{
  /* Minimum length check: "Sun, 06 Nov 1994 08:49:37 GMT" = 29 chars */
  if (len < 29)
    return -1;

  const char *end = s + len;

  /* Skip day name (3 chars) + comma + space */
  const char *p = s;

  /* Find comma */
  while (p < end && *p != ',')
    p++;
  if (p >= end || *p != ',')
    return -1;
  p++; /* Skip comma */

  /* Skip space */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  /* Parse day (2 digits) */
  if (p + 2 > end)
    return -1;
  int day = parse_2digit (p);
  if (day < 1 || day > 31)
    return -1;
  p += 2;

  /* Space */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  /* Parse month (3 chars) */
  if (p + 3 > end)
    return -1;
  int month = parse_month (p);
  if (month < 0)
    return -1;
  p += 3;

  /* Space */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  /* Parse year (4 digits) */
  if (p + 4 > end)
    return -1;
  int year = parse_4digit (p);
  if (year < 0)
    return -1;
  p += 4;

  /* Space */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  /* Parse time HH:MM:SS */
  if (p + 2 > end)
    return -1;
  int hour = parse_2digit (p);
  if (hour < 0 || hour > 23)
    return -1;
  p += 2;

  if (p >= end || *p != ':')
    return -1;
  p++;

  if (p + 2 > end)
    return -1;
  int minute = parse_2digit (p);
  if (minute < 0 || minute > 59)
    return -1;
  p += 2;

  if (p >= end || *p != ':')
    return -1;
  p++;

  if (p + 2 > end)
    return -1;
  int second = parse_2digit (p);
  if (second < 0 || second > 60) /* 60 for leap second */
    return -1;
  p += 2;

  /* Space + GMT */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  if (p + 3 > end || strncmp (p, "GMT", 3) != 0)
    return -1;

  /* Build struct tm */
  struct tm tm = { 0 };
  tm.tm_year = year - 1900;
  tm.tm_mon = month;
  tm.tm_mday = day;
  tm.tm_hour = hour;
  tm.tm_min = minute;
  tm.tm_sec = second;

  *out = tm_to_time_t (&tm);
  return 0;
}

/* ============================================================================
 * RFC 850 Parser
 * Format: Sunday, 06-Nov-94 08:49:37 GMT
 * ============================================================================ */

static int
parse_rfc850 (const char *s, size_t len, time_t *out)
{
  /* RFC 850 minimum: "X, DD-Mon-YY HH:MM:SS GMT" = 26 chars */
  if (len < 26)
    return -1;

  const char *end = s + len;

  /* Find comma */
  const char *p = s;
  while (p < end && *p != ',')
    p++;
  if (p >= end || *p != ',')
    return -1;
  p++; /* Skip comma */

  /* Skip space - check bounds first */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  /* Parse day (2 digits) */
  if (p + 2 > end)
    return -1;
  int day = parse_2digit (p);
  if (day < 1 || day > 31)
    return -1;
  p += 2;

  /* Dash */
  if (p >= end || *p != '-')
    return -1;
  p++;

  /* Parse month (3 chars) */
  if (p + 3 > end)
    return -1;
  int month = parse_month (p);
  if (month < 0)
    return -1;
  p += 3;

  /* Dash */
  if (p >= end || *p != '-')
    return -1;
  p++;

  /* Parse 2-digit year */
  if (p + 2 > end)
    return -1;
  int year2 = parse_2digit (p);
  if (year2 < 0)
    return -1;
  p += 2;

  /* Convert 2-digit year: 00-68 -> 2000-2068, 69-99 -> 1969-1999 */
  int year = (year2 >= 69) ? (1900 + year2) : (2000 + year2);

  /* Space */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  /* Parse time HH:MM:SS */
  if (p + 2 > end)
    return -1;
  int hour = parse_2digit (p);
  if (hour < 0 || hour > 23)
    return -1;
  p += 2;

  if (p >= end || *p != ':')
    return -1;
  p++;

  if (p + 2 > end)
    return -1;
  int minute = parse_2digit (p);
  if (minute < 0 || minute > 59)
    return -1;
  p += 2;

  if (p >= end || *p != ':')
    return -1;
  p++;

  if (p + 2 > end)
    return -1;
  int second = parse_2digit (p);
  if (second < 0 || second > 60)
    return -1;
  p += 2;

  /* Space + GMT */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  if (p + 3 > end || strncmp (p, "GMT", 3) != 0)
    return -1;

  /* Build struct tm */
  struct tm tm = { 0 };
  tm.tm_year = year - 1900;
  tm.tm_mon = month;
  tm.tm_mday = day;
  tm.tm_hour = hour;
  tm.tm_min = minute;
  tm.tm_sec = second;

  *out = tm_to_time_t (&tm);
  return 0;
}

/* ============================================================================
 * ANSI C asctime() Parser
 * Format: Sun Nov  6 08:49:37 1994
 * ============================================================================ */

static int
parse_asctime (const char *s, size_t len, time_t *out)
{
  /* Minimum: "Sun Nov  6 08:49:37 1994" = 24 chars */
  if (len < 24)
    return -1;

  const char *end = s + len;
  const char *p = s;

  /* Skip day name (3 chars) + space */
  if (p + 4 > end)
    return -1;
  p += 3;
  if (*p != ' ')
    return -1;
  p++;

  /* Parse month (3 chars) */
  if (p + 3 > end)
    return -1;
  int month = parse_month (p);
  if (month < 0)
    return -1;
  p += 3;

  /* Space(s) */
  if (p >= end || *p != ' ')
    return -1;
  p++;
  int ws = skip_ws (p, (size_t)(end - p));
  p += ws;

  /* Parse day (1 or 2 digits) */
  if (p >= end)
    return -1;
  int consumed;
  int day = parse_day (p, (size_t)(end - p), &consumed);
  if (day < 1 || day > 31)
    return -1;
  p += consumed;

  /* Space */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  /* Parse time HH:MM:SS */
  if (p + 2 > end)
    return -1;
  int hour = parse_2digit (p);
  if (hour < 0 || hour > 23)
    return -1;
  p += 2;

  if (p >= end || *p != ':')
    return -1;
  p++;

  if (p + 2 > end)
    return -1;
  int minute = parse_2digit (p);
  if (minute < 0 || minute > 59)
    return -1;
  p += 2;

  if (p >= end || *p != ':')
    return -1;
  p++;

  if (p + 2 > end)
    return -1;
  int second = parse_2digit (p);
  if (second < 0 || second > 60)
    return -1;
  p += 2;

  /* Space */
  if (p >= end || *p != ' ')
    return -1;
  p++;

  /* Parse year (4 digits) */
  if (p + 4 > end)
    return -1;
  int year = parse_4digit (p);
  if (year < 0)
    return -1;

  /* Build struct tm */
  struct tm tm = { 0 };
  tm.tm_year = year - 1900;
  tm.tm_mon = month;
  tm.tm_mday = day;
  tm.tm_hour = hour;
  tm.tm_min = minute;
  tm.tm_sec = second;

  *out = tm_to_time_t (&tm);
  return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

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

  /* Try each format in order */

  /* IMF-fixdate: starts with 3-char day, comma */
  /* e.g., "Sun, 06 Nov 1994 08:49:37 GMT" */
  if (len >= 5 && date_str[3] == ',')
    {
      if (parse_imf_fixdate (date_str, len, time_out) == 0)
        return 0;
    }

  /* RFC 850: starts with full day name, comma */
  /* e.g., "Sunday, 06-Nov-94 08:49:37 GMT" */
  if (len >= 10)
    {
      /* Find comma to detect RFC 850 format */
      for (size_t i = 3; i < 10 && i < len; i++)
        {
          if (date_str[i] == ',')
            {
              if (parse_rfc850 (date_str, len, time_out) == 0)
                return 0;
              break;
            }
        }
    }

  /* ANSI C: starts with 3-char day, space */
  /* e.g., "Sun Nov  6 08:49:37 1994" */
  if (len >= 24 && date_str[3] == ' ')
    {
      if (parse_asctime (date_str, len, time_out) == 0)
        return 0;
    }

  return -1;
}

int
SocketHTTP_date_format (time_t t, char *output)
{
  if (!output)
    return -1;

  struct tm *tm = gmtime (&t);
  if (!tm)
    return -1;

  /* Validate day of week */
  int wday = tm->tm_wday;
  if (wday < 0 || wday > 6)
    wday = 0;

  /* Validate month */
  int mon = tm->tm_mon;
  if (mon < 0 || mon > 11)
    mon = 0;

  /* Format: "Sun, 06 Nov 1994 08:49:37 GMT" */
  int n = snprintf (output, SOCKETHTTP_DATE_BUFSIZE,
                    "%s, %02d %s %04d %02d:%02d:%02d GMT",
                    day_names_short[wday], tm->tm_mday,
                    month_names[mon].name, tm->tm_year + 1900, tm->tm_hour,
                    tm->tm_min, tm->tm_sec);

  if (n < 0 || n >= SOCKETHTTP_DATE_BUFSIZE)
    return -1;

  return n;
}

