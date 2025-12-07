/**
 * benchmark_synprotect.c - Performance Benchmarks for SocketSYNProtect
 *
 * Measures:
 * - Check latency under load (various IP counts, whitelist/CIDR sizes)
 * - Memory usage (malloc vs arena, eviction)
 * - Hash performance (collision cases)
 *
 * Usage: ./benchmark_synprotect [iterations [num_ips [num_cidrs]]]
 * Integrate to run_benchmarks.sh
 */

#include "test/Test.h"  // For timing utils if available
#include "core/Arena.h"
#include "core/SocketSYNProtect.h"
#include "core/SocketUtil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_ITER 1000000
#define DEFAULT_NUM_IPS 10000
#define DEFAULT_NUM_CIDRS 100

static int64_t get_time_ms(void) {
  return Socket_get_monotonic_ms();
}

static void benchmark_check(T protect, int iterations, const char *ip) {
  int64_t start = get_time_ms();
  for (int i = 0; i < iterations; i++) {
    SocketSYNProtect_check(protect, ip, NULL);
  }
  int64_t end = get_time_ms();
  printf("Check %s: %ld ms for %d calls (%.2f us/call)\n", ip, end - start, iterations, (double)(end - start) * 1000 / iterations);
}

static void populate_whitelist(T protect, int num_cidrs) {
  char cidr[64];
  for (int i = 0; i < num_cidrs; i++) {
    snprintf(cidr, sizeof(cidr), "10.%d.0.0/16", i % 256);
    SocketSYNProtect_whitelist_add_cidr(protect, cidr);
  }
}

static void benchmark_whitelist_overhead(T protect, int iterations, int num_cidrs) {
  populate_whitelist(protect, num_cidrs);
  int64_t start = get_time_ms();
  for (int i = 0; i < iterations; i++) {
    char test_ip[32];
    snprintf(test_ip, sizeof(test_ip), "192.168.%d.%d", rand() % 256, rand() % 256);
    SocketSYNProtect_whitelist_contains(protect, test_ip);
  }
  int64_t end = get_time_ms();
  printf("Whitelist scan (%d CIDRs): %ld ms for %d checks (%.2f us/check)\n", num_cidrs, end - start, iterations, (double)(end - start) * 1000 / iterations);
}

int main(int argc, char **argv) {
  int iterations = argc > 1 ? atoi(argv[1]) : DEFAULT_ITER;
  int num_ips = argc > 2 ? atoi(argv[2]) : DEFAULT_NUM_IPS;
  int num_cidrs = argc > 3 ? atoi(argv[3]) : DEFAULT_NUM_CIDRS;

  printf("Benchmarking SocketSYNProtect: %d iterations, %d IPs, %d CIDRs\n", iterations, num_ips, num_cidrs);

  Arena_T arena = Arena_new();
  SocketSYNProtect_Config config;
  SocketSYNProtect_config_defaults(&config);
  config.max_tracked_ips = num_ips;

  SocketSYNProtect_T protect = SocketSYNProtect_new(arena, &config);

  // Basic check benchmark
  benchmark_check(protect, iterations, "1.2.3.4");

  // Whitelist overhead
  benchmark_whitelist_overhead(protect, iterations / 10, num_cidrs);

  // IP rotation (simulate flood)
  int64_t start = get_time_ms();
  for (int i = 0; i < iterations / 100; i++) {  // Smaller for many IPs
    char ip[32];
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d", rand()%256, rand()%256, rand()%256, rand()%256);
    SocketSYNProtect_check(protect, ip, NULL);
  }
  int64_t end = get_time_ms();
  printf("IP rotation flood: %ld ms for %d unique-ish checks\n", end - start, iterations / 100);

  // Arena vs malloc? Run twice, one with arena NULL

  SocketSYNProtect_free(&protect);
  Arena_dispose(&arena);

  // Malloc mode
  protect = SocketSYNProtect_new(NULL, &config);
  benchmark_check(protect, iterations / 10, "1.2.3.4");  // Quick compare
  SocketSYNProtect_free(&protect);

  printf("Benchmark complete.\n");
  return 0;
}