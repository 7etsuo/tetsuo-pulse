/**
 * fuzz_test_certs.h - Embedded test certificates for fuzzing
 *
 * Contains a self-signed EC certificate and private key for use in fuzz
 * harnesses. These are NOT secure and should NEVER be used in production.
 *
 * Benefits of embedded certs for fuzzing:
 * - Zero I/O overhead (no filesystem access)
 * - Deterministic (same certs every run for reproducibility)
 * - Works in sandboxed environments
 * - No cleanup required
 *
 * Certificate details:
 * - Algorithm: ECDSA with prime256v1 (P-256)
 * - Subject: CN=fuzz-test
 * - Validity: 10 years (irrelevant for fuzzing)
 * - Self-signed (no chain validation needed)
 */

#ifndef FUZZ_TEST_CERTS_H
#define FUZZ_TEST_CERTS_H

/* EC Private Key (PKCS#8 format) */
static const char FUZZ_TEST_KEY[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqkgE0iD0EUWZWzYQ\n"
    "XPgPfWGp4MGrE4FPN/MDwYGORquhRANCAASwKN6KryxfWQbBfknOxly7VFOrXn6Z\n"
    "Lx80K2pR/AIXpwibHHzr5vKf00UR6zNEscqQLhWJSJJcuG8hBbynYCvm\n"
    "-----END PRIVATE KEY-----\n";

/* Self-signed EC Certificate */
static const char FUZZ_TEST_CERT[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBfDCCASOgAwIBAgIUKYoMAZV9MVBUq0Hi8Chy7C6UxBYwCgYIKoZIzj0EAwIw\n"
    "FDESMBAGA1UEAwwJZnV6ei10ZXN0MB4XDTI1MTEzMDEwMDIxNVoXDTM1MTEyODEw\n"
    "MDIxNVowFDESMBAGA1UEAwwJZnV6ei10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
    "AQcDQgAEsCjeiq8sX1kGwX5JzsZcu1RTq15+mS8fNCtqUfwCF6cImxx86+byn9NF\n"
    "EeszRLHKkC4ViUiSXLhvIQW8hBbynYCvm6NTMFEwHQYDVR0OBBYEFBk3lmJFZing\n"
    "lIKAu9KZQSeUqfcDMB8GA1UdIwQYMBaAFBk3lmJFZinglIKAu9KZQSeUqfcDMA8G\n"
    "A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgDkw1tp53edwA4IPoI8rU\n"
    "0wbkWAGfRnGNsGUViJrP8XMCIDuhYZqAaESAYlEcz5af64sL2gGRp4v8dcr9tr42\n"
    "L6vR\n"
    "-----END CERTIFICATE-----\n";

#endif /* FUZZ_TEST_CERTS_H */

