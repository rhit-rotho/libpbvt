#include <coz.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "cassert.h"
#include "pbvt.h"

#define MIN(a, b) ((a) > (b) ? (b) : (a))

int main(int argc, char **argv) {
  if (argc < 3) {
    printf("./driver [TRIALS] [GC_THRESHOLD]\n");
    return 1;
  }
  printf("Size of additional copy: %d\n",
         NUM_BOTTOM + sizeof(PVectorLeaf) + sizeof(PVector) * (MAX_DEPTH - 1));

  int64_t trials = atoll(argv[1]);
  int64_t gc_threshold = atoll(argv[2]);
  if (gc_threshold == -1)
    gc_threshold = INT64_MAX;

  pbvt_init();

  size_t test_sz = 0x1000;
  uint8_t *test = mmap((void *)0x10000UL, test_sz, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (test == MAP_FAILED) {
    perror("mmap");
    return 1;
  }

  uint8_t *test_arr = mmap(NULL, test_sz, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  for (int i = 0; i < test_sz; ++i)
    test[i] = i;
  memcpy(test_arr, test, test_sz);

  // track changes
  printf("Adding range %p-%p...", test, test + test_sz);
  pbvt_track_range(test, test_sz, PROT_READ | PROT_WRITE);
  printf("done\n");

  Commit *c = pbvt_commit();
  pbvt_branch_commit("main");

  for (int64_t i = 1; i < trials; ++i) {
    for (int i = 0; i < 0x100; ++i) {
      uint8_t key = rand() & (0x10000 - 1);
      uint8_t val = rand() & 0xff;
      test[key] = val;
    }
    COZ_PROGRESS;
    pbvt_commit();
    COZ_PROGRESS;
    if (pbvt_size() > gc_threshold) {
      pbvt_gc_n(gc_threshold / 2);
      COZ_PROGRESS;
    }
    if (i % 0x100 == 0) {
      pbvt_stats();
      pbvt_checkout(c);
      printf("Checking: %.16lx\n", c->hash);
      assert(memcmp(test_arr, test, test_sz) == 0);
      pbvt_branch_checkout("main");
      c = pbvt_head();
      printf("Checking: %.16lx\n", c->hash);
      assert(memcmp(test_arr, test, test_sz) != 0);
      memcpy(test_arr, test, test_sz);
    }
    COZ_PROGRESS;
  }

  pbvt_print("out.dot");

  goto cleanup;

driver:
  int auto_update = 1;
  for (;;) {
    char buf[0x100];
    uint64_t idx, val;
    printf("> ");
    fgets(buf, sizeof(buf) - 1, stdin);
    char *pbuf = buf;
    pbuf += 2;
    switch (buf[0]) {
    case 'q':
      printf("Goodbye!\n");
      exit(0);
      break;
    case 'p':
      pbvt_print("out.dot");
      printf("printed to out.dot!\n");
      break;
    case 'f':
      pbuf += sscanf(pbuf, "%p", &idx);
      printf("Value at %.16lx: %.2x\n", idx, *(uint8_t *)idx);
      break;
    case 'c':
      printf("Committing...\n");
      pbvt_commit();
      break;
    case 't':
      pbuf += sscanf(pbuf, "%p %d", &idx, &val);
      printf("Modify %d at 0x%0.16x\n", val, idx);
      *(uint8_t *)idx = val;
      break;
    case 'u':
      pbuf += sscanf(pbuf, "%p", &idx);
      printf("Value at 0x%0.16x: %.2x\n", idx, *(uint8_t *)idx);
      break;
    case 'b':
      printf("Checkout one from head\n");
      pbvt_checkout(pbvt_commit_parent(pbvt_head()));
      break;
    default:
      printf("Unrecognized %c\n", buf[0]);
      break;
    }
    pbvt_print("out.dot");
  }

cleanup:
  pbvt_print("out.dot");
  // pbvt_stats();
  pbvt_cleanup();
  // munmap(test, test_sz);
  return 0;
}
