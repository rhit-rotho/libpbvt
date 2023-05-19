// cc examples/benchmark_malloc.c -O3 -DMINE -ggdb3 -lpbvt -o benchmark_malloc_mine
// cc examples/benchmark_malloc.c -O3        -ggdb3 -lpbvt -o benchmark_malloc_glibc

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pbvt.h"

#define NUM_ITERATIONS 1000000
#define MAX_ALLOC_SIZE 256

#ifdef MINE
#define my_malloc pbvt_malloc
#define my_free pbvt_free
#define my_realloc pbvt_realloc
#else
#define my_malloc malloc
#define my_free free
#define my_realloc realloc
#endif

int main(int argc, char **argv) {
  // HACK: This will not initialize the persistent allocator, we want to
  // benchmark the raw implementation.
  // pbvt_init();
  // pbvt_commit();
  // pbvt_branch_commit("main");

  srand(time(NULL));
  uint8_t **ptrs = malloc(sizeof(uint8_t *) * NUM_ITERATIONS);
  uint8_t **ptrs2 = malloc(sizeof(uint8_t *) * NUM_ITERATIONS);
  size_t *sizes = malloc(sizeof(size_t) * NUM_ITERATIONS);

  clock_t start = clock();
  clock_t end;
  float duration_ms;

  int rfd = open("/dev/random", O_RDONLY);

  // Benchmark malloc
  for (int i = 0; i < NUM_ITERATIONS; i++) {
    //    size_t size = rand() % MAX_ALLOC_SIZE + 1;
    size_t size = 8;
    sizes[i] = size;
    ptrs[i] = my_malloc(size);
    // ptrs2[i] = malloc(size);

    read(rfd, ptrs[i], size);
    // memcpy(ptrs2[i], ptrs[i], sizes[i]);
    // if (memcmp(ptrs[i], ptrs2[i], sizes[i]) != 0)
    //   printf("%d: Fail.\n", __LINE__);
  }
  end = clock();
  duration_ms = 1000.0 * (end - start) / CLOCKS_PER_SEC;
  printf("malloc completed in %.2f ms\n", duration_ms);

#if 0
  for (int i = 0; i < NUM_ITERATIONS; i++) {
    if (memcmp(ptrs[i], ptrs2[i], sizes[i]) != 0) {
      printf("Mismatch! %.16lx != %.16lx\n", ptrs[i], ptrs2[i]);
      for (int j = 0; j < sizes[i]; ++j)
        printf("%.2x ", ptrs[i][j]);
      printf("\n");
      for (int j = 0; j < sizes[i]; ++j)
        printf("%.2x ", ptrs2[i][j]);
      printf("\n");
    }
  }
#endif

  // Benchmark realloc
  start = clock();
  for (int i = 0; i < NUM_ITERATIONS; i++) {
    size_t new_size = rand() % MAX_ALLOC_SIZE + 1;
    ptrs[i] = my_realloc(ptrs[i], new_size);
    // ptrs2[i] = realloc(ptrs2[i], new_size);
    if (new_size > sizes[i]) {
      memset(ptrs[i] + sizes[i], 0x00, new_size - sizes[i]);
      // memset(ptrs2[i] + sizes[i], 0x00, new_size - sizes[i]);
    }
    sizes[i] = new_size;
  }
  end = clock();
  duration_ms = 1000.0 * (end - start) / CLOCKS_PER_SEC;
  printf("realloc completed in %.2f ms\n", duration_ms);

#if 0
  for (int i = 0; i < NUM_ITERATIONS; i++) {
    if (memcmp(ptrs[i], ptrs2[i], sizes[i]) != 0) {
      printf("Mismatch! %.16lx != %.16lx\n", ptrs[i], ptrs2[i]);
      for (int j = 0; j < sizes[i]; ++j)
        printf("%.2x ", ptrs[i][j]);
      printf("\n");
      for (int j = 0; j < sizes[i]; ++j)
        printf("%.2x ", ptrs2[i][j]);
      printf("\n");
    }
  }
#endif

  // Benchmark free
  start = clock();
  for (int i = 0; i < NUM_ITERATIONS; i++) {
    my_free(ptrs[i]);
    // free(ptrs2[i]);
  }
  end = clock();
  duration_ms = 1000.0 * (end - start) / CLOCKS_PER_SEC;
  printf("free completed in %.2f ms\n", duration_ms);
  start = clock();

  free(ptrs);

  return 0;
}
