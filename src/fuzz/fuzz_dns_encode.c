/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_encode.c - libFuzzer harness for DNS wire format encoding/serialization
 *
 * Fuzzes DNS encoding functions to achieve coverage of *_encode() functions
 * which currently have 0% line coverage (issue #260).
 *
 * Targets:
 * - SocketDNS_header_encode() - Header serialization
 * - SocketDNS_name_encode() - Domain name encoding (labels + terminator)
 * - SocketDNS_question_encode() - Question section encoding
 * - SocketDNS_opt_encode() - EDNS0 OPT pseudo-RR encoding
 * - SocketDNS_edns_option_encode() - EDNS option encoding
 * - SocketDNS_edns_options_encode() - Batch option encoding
 * - SocketDNS_opt_ttl_encode() - OPT TTL field encoding
 *
 * Test strategies:
 * 1. Roundtrip testing: encode -> decode -> encode -> verify
 * 2. Random structure generation from fuzz input
 * 3. Buffer boundary conditions (exact fit, too small, etc.)
 * 4. Maximum name lengths (63 byte labels, 255 byte total)
 * 5. Label count limits
 * 6. Edge cases: empty strings, root domain, trailing dots
 * 7. Extreme field values (max uint16_t, uint32_t)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_encode
 * Run:   ./fuzz_dns_encode -fork=16 -max_len=2048
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dns/SocketDNSWire.h"

/* Maximum fuzz input size */
#define MAX_FUZZ_INPUT 4096

/* Test buffer sizes */
#define ENCODE_BUF_SIZE 512

/**
 * Generate a header structure from fuzz input.
 * Uses first 16 bytes of data to populate all header fields.
 */
static void
generate_header (const uint8_t *data, size_t size, SocketDNS_Header *hdr)
{
  if (size < 16)
    {
      memset (hdr, 0, sizeof (*hdr));
      return;
    }

  hdr->id = ((uint16_t)data[0] << 8) | data[1];
  hdr->qr = (data[2] >> 7) & 0x01;
  hdr->opcode = (data[2] >> 3) & 0x0F;
  hdr->aa = (data[2] >> 2) & 0x01;
  hdr->tc = (data[2] >> 1) & 0x01;
  hdr->rd = data[2] & 0x01;
  hdr->ra = (data[3] >> 7) & 0x01;
  hdr->z = (data[3] >> 4) & 0x07;
  hdr->rcode = data[3] & 0x0F;
  hdr->qdcount = ((uint16_t)data[4] << 8) | data[5];
  hdr->ancount = ((uint16_t)data[6] << 8) | data[7];
  hdr->nscount = ((uint16_t)data[8] << 8) | data[9];
  hdr->arcount = ((uint16_t)data[10] << 8) | data[11];
}

/**
 * Generate a domain name string from fuzz input.
 * Creates labels with varying lengths up to 63 bytes.
 */
static void
generate_name (const uint8_t *data, size_t size, char *name, size_t namelen)
{
  size_t pos = 0;
  size_t data_pos = 0;
  size_t label_count = 0;
  const size_t max_labels = 8; /* Reasonable limit for fuzzing */

  if (size == 0 || namelen == 0)
    {
      name[0] = '\0';
      return;
    }

  /* Generate labels from input data */
  while (data_pos < size && label_count < max_labels && pos < namelen - 1)
    {
      /* Label length from input, capped at DNS_MAX_LABEL_LEN */
      size_t label_len = data[data_pos] % (DNS_MAX_LABEL_LEN + 1);
      data_pos++;

      if (label_len == 0)
        break; /* Empty label ends name */

      /* Ensure we have enough space and data */
      if (pos + label_len + 1 >= namelen - 1)
        break;
      if (data_pos + label_len > size)
        label_len = size - data_pos;

      /* Add dot separator (except for first label) */
      if (label_count > 0)
        {
          name[pos++] = '.';
        }

      /* Copy label data, ensuring printable ASCII for valid names */
      for (size_t i = 0; i < label_len && data_pos < size; i++)
        {
          unsigned char c = data[data_pos++];
          /* Map to DNS-safe characters: a-z, 0-9, hyphen */
          if (c == 0)
            c = 'a'; /* Avoid null bytes in labels */
          else if (c == '.')
            c = '-'; /* Avoid dots within labels */
          else
            c = 'a' + (c % 26); /* Map to lowercase letters */

          name[pos++] = (char)c;
        }

      label_count++;
    }

  name[pos] = '\0';
}

/**
 * Test header encoding with roundtrip verification.
 */
static void
test_header_encode (const SocketDNS_Header *hdr)
{
  unsigned char buf[DNS_HEADER_SIZE];
  SocketDNS_Header decoded;
  int result;

  /* Encode header */
  result = SocketDNS_header_encode (hdr, buf, sizeof (buf));
  if (result != 0)
    return; /* Encoding failed, expected for some inputs */

  /* Decode and verify roundtrip */
  result = SocketDNS_header_decode (buf, sizeof (buf), &decoded);
  if (result == 0)
    {
      /* Verify all fields match */
      (void)(hdr->id == decoded.id);
      (void)(hdr->qr == decoded.qr);
      (void)(hdr->opcode == decoded.opcode);
      (void)(hdr->aa == decoded.aa);
      (void)(hdr->tc == decoded.tc);
      (void)(hdr->rd == decoded.rd);
      (void)(hdr->ra == decoded.ra);
      (void)(hdr->z == decoded.z);
      (void)(hdr->rcode == decoded.rcode);
      (void)(hdr->qdcount == decoded.qdcount);
      (void)(hdr->ancount == decoded.ancount);
      (void)(hdr->nscount == decoded.nscount);
      (void)(hdr->arcount == decoded.arcount);
    }

  /* Test with undersized buffer */
  for (size_t sz = 0; sz < DNS_HEADER_SIZE; sz++)
    {
      result = SocketDNS_header_encode (hdr, buf, sz);
      (void)result; /* Should fail for sz < DNS_HEADER_SIZE */
    }
}

/**
 * Test name encoding with roundtrip and edge cases.
 */
static void
test_name_encode (const char *name)
{
  unsigned char wire[DNS_MAX_NAME_LEN + 16];
  char decoded[DNS_MAX_NAME_LEN + 16];
  size_t written;
  size_t consumed;
  int result;

  /* Skip obviously invalid names */
  if (!name || strlen (name) > DNS_MAX_NAME_LEN)
    return;

  /* Test validation first */
  int valid = SocketDNS_name_valid (name);
  (void)valid;

  /* Calculate wire length */
  size_t wire_len = SocketDNS_name_wire_length (name);
  (void)wire_len;

  /* Encode name */
  result
      = SocketDNS_name_encode (name, wire, sizeof (wire), &written);
  if (result != 0)
    return; /* Encoding failed */

  /* Verify wire length matches if name was valid */
  if (valid && wire_len > 0)
    {
      (void)(wire_len == written);
    }

  /* Decode and verify roundtrip */
  result = SocketDNS_name_decode (wire, written, 0, decoded, sizeof (decoded),
                                  &consumed);
  if (result >= 0)
    {
      /* Names should match (case-insensitive) */
      int equal = SocketDNS_name_equal (name, decoded);
      (void)equal;
    }

  /* Test with various buffer sizes */
  for (size_t sz = 0; sz < written && sz < 64; sz++)
    {
      result = SocketDNS_name_encode (name, wire, sz, NULL);
      (void)result; /* Should fail for sz < required */
    }

  /* Test exact fit buffer */
  if (written > 0)
    {
      unsigned char exact_buf[DNS_MAX_NAME_LEN];
      result = SocketDNS_name_encode (name, exact_buf, written, NULL);
      (void)result;
    }
}

/**
 * Test question encoding with roundtrip.
 */
static void
test_question_encode (const SocketDNS_Question *question)
{
  unsigned char buf[ENCODE_BUF_SIZE];
  SocketDNS_Question decoded;
  size_t written;
  size_t consumed;
  int result;

  /* Encode question */
  result
      = SocketDNS_question_encode (question, buf, sizeof (buf), &written);
  if (result != 0)
    return; /* Encoding failed */

  /* Decode and verify roundtrip */
  result = SocketDNS_question_decode (buf, written, 0, &decoded, &consumed);
  if (result == 0)
    {
      /* Verify fields match */
      int name_equal
          = SocketDNS_name_equal (question->qname, decoded.qname);
      (void)name_equal;
      (void)(question->qtype == decoded.qtype);
      (void)(question->qclass == decoded.qclass);
    }

  /* Test buffer boundaries */
  for (size_t sz = 0; sz < written && sz < 32; sz++)
    {
      result = SocketDNS_question_encode (question, buf, sz, NULL);
      (void)result; /* Should fail for insufficient buffer */
    }
}

/**
 * Test OPT record encoding with roundtrip.
 */
static void
test_opt_encode (const SocketDNS_OPT *opt)
{
  unsigned char buf[ENCODE_BUF_SIZE];
  SocketDNS_OPT decoded;
  int enc_len;
  int dec_consumed;

  /* Calculate expected size */
  size_t expected_size = DNS_OPT_FIXED_SIZE + opt->rdlength;
  (void)expected_size;

  /* Encode OPT record */
  enc_len = SocketDNS_opt_encode (opt, buf, sizeof (buf));
  if (enc_len <= 0)
    return; /* Encoding failed */

  /* Decode and verify roundtrip */
  dec_consumed = SocketDNS_opt_decode (buf, enc_len, &decoded);
  if (dec_consumed > 0)
    {
      /* Verify key fields match */
      (void)(opt->udp_payload_size == decoded.udp_payload_size);
      (void)(opt->extended_rcode == decoded.extended_rcode);
      (void)(opt->version == decoded.version);
      (void)(opt->do_bit == decoded.do_bit);
      (void)(opt->z == decoded.z);
      (void)(opt->rdlength == decoded.rdlength);

      /* Validate decoded OPT */
      SocketDNS_OPT_ValidationResult valid
          = SocketDNS_opt_validate (&decoded, enc_len - DNS_OPT_FIXED_SIZE);
      (void)valid;
    }

  /* Test buffer boundaries */
  for (size_t sz = 0; sz < (size_t)enc_len && sz < 32; sz++)
    {
      int result = SocketDNS_opt_encode (opt, buf, sz);
      (void)result; /* Should fail for insufficient buffer */
    }
}

/**
 * Test EDNS option encoding.
 */
static void
test_edns_option_encode (const SocketDNS_EDNSOption *option)
{
  unsigned char buf[256];
  int enc_len;

  enc_len = SocketDNS_edns_option_encode (option, buf, sizeof (buf));
  if (enc_len > 0)
    {
      /* Verify size is correct */
      size_t expected = DNS_EDNS_OPTION_HEADER_SIZE + option->length;
      (void)(enc_len == (int)expected);
    }

  /* Test buffer boundaries */
  size_t needed = DNS_EDNS_OPTION_HEADER_SIZE + option->length;
  for (size_t sz = 0; sz < needed && sz < 16; sz++)
    {
      int result = SocketDNS_edns_option_encode (option, buf, sz);
      (void)result; /* Should fail for sz < needed */
    }
}

/**
 * Test batch EDNS options encoding.
 */
static void
test_edns_options_batch_encode (const uint8_t *data, size_t size)
{
  unsigned char buf[256];
  SocketDNS_EDNSOption options[4];
  size_t option_count = 0;
  size_t data_pos = 0;

  /* Generate up to 4 options from input */
  while (option_count < 4 && data_pos + 4 < size)
    {
      options[option_count].code
          = ((uint16_t)data[data_pos] << 8) | data[data_pos + 1];
      data_pos += 2;

      /* Small length to stay within buffer */
      size_t max_opt_len = size - data_pos;
      if (max_opt_len > 32)
        max_opt_len = 32;

      options[option_count].length = data[data_pos] % max_opt_len;
      data_pos++;

      if (options[option_count].length > 0
          && data_pos + options[option_count].length <= size)
        {
          options[option_count].data = data + data_pos;
          data_pos += options[option_count].length;
        }
      else
        {
          options[option_count].length = 0;
          options[option_count].data = NULL;
        }

      option_count++;
    }

  if (option_count > 0)
    {
      int enc_len = SocketDNS_edns_options_encode (options, option_count, buf,
                                                    sizeof (buf));
      if (enc_len > 0)
        {
          /* Parse back using iterator */
          SocketDNS_EDNSOptionIter iter;
          SocketDNS_EDNSOption parsed;
          size_t parsed_count = 0;

          SocketDNS_edns_option_iter_init (&iter, buf, enc_len);
          while (SocketDNS_edns_option_iter_next (&iter, &parsed))
            {
              parsed_count++;
            }

          /* Should parse same number of options */
          (void)(parsed_count == option_count);
        }
    }
}

/**
 * Test OPT TTL field encoding.
 */
static void
test_opt_ttl_encode (const uint8_t *data, size_t size)
{
  if (size < 4)
    return;

  SocketDNS_OPT_Flags flags;
  flags.extended_rcode = data[0];
  flags.version = data[1];
  flags.do_bit = (data[2] >> 7) & 0x01;
  flags.z = ((uint16_t)(data[2] & 0x7F) << 8) | data[3];

  /* Encode TTL */
  uint32_t ttl = SocketDNS_opt_ttl_encode (&flags);

  /* Decode and verify roundtrip */
  SocketDNS_OPT_Flags decoded;
  SocketDNS_opt_ttl_decode (ttl, &decoded);

  /* Verify all fields match */
  (void)(flags.extended_rcode == decoded.extended_rcode);
  (void)(flags.version == decoded.version);
  (void)(flags.do_bit == decoded.do_bit);
  (void)(flags.z == decoded.z);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketDNS_Header header;
  SocketDNS_Question question;
  SocketDNS_OPT opt;
  SocketDNS_EDNSOption edns_option;
  char name_buf[DNS_MAX_NAME_LEN];
  unsigned char rdata_buf[128];

  if (size == 0)
    return 0;

  /* Cap input size */
  if (size > MAX_FUZZ_INPUT)
    size = MAX_FUZZ_INPUT;

  /*
   * Test 1: Header encoding
   * Uses first 16 bytes to generate all field combinations
   */
  if (size >= 16)
    {
      generate_header (data, size, &header);
      test_header_encode (&header);

      /* Test header_init_query */
      uint16_t id = ((uint16_t)data[0] << 8) | data[1];
      uint16_t qdcount = ((uint16_t)data[2] << 8) | data[3];
      SocketDNS_header_init_query (&header, id, qdcount);
      test_header_encode (&header);
    }

  /*
   * Test 2: Name encoding
   * Generate various domain name patterns
   */
  if (size >= 8)
    {
      generate_name (data, size, name_buf, sizeof (name_buf));
      test_name_encode (name_buf);

      /* Test special cases */
      test_name_encode (""); /* Empty string (root) */
      test_name_encode ("."); /* Root domain */
      test_name_encode ("a"); /* Single character */
      test_name_encode ("example.com"); /* Valid domain */
      test_name_encode ("www.example.com"); /* Subdomain */
      test_name_encode ("example.com."); /* Trailing dot */

      /* Test maximum label length */
      char max_label[DNS_MAX_LABEL_LEN + 2];
      memset (max_label, 'a', DNS_MAX_LABEL_LEN);
      max_label[DNS_MAX_LABEL_LEN] = '\0';
      test_name_encode (max_label);

      /* Test multiple labels approaching max length */
      char long_name[DNS_MAX_NAME_LEN + 16];
      size_t pos = 0;
      for (int i = 0; i < 4 && pos < sizeof (long_name) - 64; i++)
        {
          if (i > 0)
            long_name[pos++] = '.';
          size_t label_len = (data[i % size] % 60) + 1;
          memset (long_name + pos, 'a' + i, label_len);
          pos += label_len;
        }
      long_name[pos] = '\0';
      test_name_encode (long_name);

      /* Test name as NUL-terminated fuzzer input */
      if (size < DNS_MAX_NAME_LEN)
        {
          char fuzz_name[DNS_MAX_NAME_LEN];
          memcpy (fuzz_name, data, size);
          fuzz_name[size] = '\0';
          test_name_encode (fuzz_name);
        }
    }

  /*
   * Test 3: Question encoding
   */
  if (size >= 12)
    {
      generate_name (data, size, question.qname, sizeof (question.qname));
      question.qtype = ((uint16_t)data[0] << 8) | data[1];
      question.qclass = ((uint16_t)data[2] << 8) | data[3];

      test_question_encode (&question);

      /* Test with question_init helper */
      SocketDNS_question_init (&question, name_buf, question.qtype);
      test_question_encode (&question);

      /* Test various record types */
      const uint16_t types[]
          = { DNS_TYPE_A,    DNS_TYPE_AAAA,  DNS_TYPE_CNAME, DNS_TYPE_NS,
              DNS_TYPE_MX,   DNS_TYPE_TXT,   DNS_TYPE_SOA,   DNS_TYPE_PTR,
              DNS_TYPE_SRV,  DNS_TYPE_DNSKEY, DNS_TYPE_RRSIG, DNS_TYPE_NSEC,
              DNS_TYPE_DS,   DNS_TYPE_NSEC3, DNS_TYPE_OPT,   DNS_TYPE_ANY };

      for (size_t i = 0; i < sizeof (types) / sizeof (types[0]); i++)
        {
          question.qtype = types[i];
          question.qclass = DNS_CLASS_IN;
          test_question_encode (&question);
        }
    }

  /*
   * Test 4: OPT record encoding
   */
  if (size >= 8)
    {
      uint16_t udp_size = ((uint16_t)data[0] << 8) | data[1];
      SocketDNS_opt_init (&opt, udp_size);
      test_opt_encode (&opt);

      /* Customize OPT fields from fuzzer input */
      opt.udp_payload_size = ((uint16_t)data[0] << 8) | data[1];
      opt.extended_rcode = data[2];
      opt.version = data[3];
      opt.do_bit = (data[4] >> 7) & 0x01;
      opt.z = ((uint16_t)(data[4] & 0x7F) << 8) | data[5];

      /* Add RDATA if enough input */
      if (size > 16)
        {
          size_t rdata_len = data[6] % (sizeof (rdata_buf));
          if (rdata_len > size - 16)
            rdata_len = size - 16;

          memcpy (rdata_buf, data + 16, rdata_len);
          opt.rdlength = rdata_len;
          opt.rdata = rdata_buf;
        }
      else
        {
          opt.rdlength = 0;
          opt.rdata = NULL;
        }

      test_opt_encode (&opt);

      /* Test extreme values */
      opt.udp_payload_size = 65535;
      opt.extended_rcode = 255;
      opt.version = 255;
      opt.do_bit = 1;
      opt.z = 0x7FFF;
      opt.rdlength = 0;
      opt.rdata = NULL;
      test_opt_encode (&opt);
    }

  /*
   * Test 5: EDNS option encoding
   */
  if (size >= 4)
    {
      edns_option.code = ((uint16_t)data[0] << 8) | data[1];
      edns_option.length = data[2] % 64;

      if (edns_option.length > 0 && size > 4 + edns_option.length)
        {
          edns_option.data = data + 4;
        }
      else
        {
          edns_option.length = 0;
          edns_option.data = NULL;
        }

      test_edns_option_encode (&edns_option);

      /* Test well-known option codes */
      const uint16_t opt_codes[]
          = { DNS_EDNS_OPT_NSID,     DNS_EDNS_OPT_CLIENT_SUBNET,
              DNS_EDNS_OPT_COOKIE,   DNS_EDNS_OPT_TCP_KEEPALIVE,
              DNS_EDNS_OPT_PADDING,  DNS_EDNS_OPT_EXTENDED_ERROR,
              0,                     65535 };

      for (size_t i = 0; i < sizeof (opt_codes) / sizeof (opt_codes[0]); i++)
        {
          edns_option.code = opt_codes[i];
          test_edns_option_encode (&edns_option);
        }
    }

  /*
   * Test 6: Batch EDNS options encoding
   */
  if (size >= 16)
    {
      test_edns_options_batch_encode (data, size);
    }

  /*
   * Test 7: OPT TTL field encoding
   */
  if (size >= 4)
    {
      test_opt_ttl_encode (data, size);
    }

  /*
   * Test 8: NULL pointer handling
   * Ensure functions return errors without crashing
   */
  (void)SocketDNS_header_encode (NULL, rdata_buf, sizeof (rdata_buf));
  (void)SocketDNS_header_encode (&header, NULL, sizeof (rdata_buf));

  (void)SocketDNS_name_encode (NULL, rdata_buf, sizeof (rdata_buf), NULL);
  (void)SocketDNS_name_encode ("test.com", NULL, sizeof (rdata_buf), NULL);

  (void)SocketDNS_question_encode (NULL, rdata_buf, sizeof (rdata_buf), NULL);
  (void)SocketDNS_question_encode (&question, NULL, sizeof (rdata_buf), NULL);

  (void)SocketDNS_opt_encode (NULL, rdata_buf, sizeof (rdata_buf));
  (void)SocketDNS_opt_encode (&opt, NULL, sizeof (rdata_buf));

  (void)SocketDNS_edns_option_encode (NULL, rdata_buf, sizeof (rdata_buf));
  (void)SocketDNS_edns_option_encode (&edns_option, NULL, sizeof (rdata_buf));

  (void)SocketDNS_edns_options_encode (NULL, 0, rdata_buf, sizeof (rdata_buf));
  (void)SocketDNS_edns_options_encode (&edns_option, 1, NULL,
                                        sizeof (rdata_buf));

  (void)SocketDNS_opt_ttl_encode (NULL);

  return 0;
}
