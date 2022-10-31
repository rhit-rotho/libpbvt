#include <assert.h>
#include <coz.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

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

  PVectorState *pvs = pbvt_init();
  uint64_t max_index = pbvt_capacity();
  pbvt_debug();

  uint8_t *test =
      mmap((void *)0x10000UL, 0x10000, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_FIXED, -1, 0);

  // track changes
  printf("Adding range %p-%p...", test, test + 0x10000);
  pbvt_track_range(pvs, test, 0x10000);
  printf("done\n");

  test[0] = 1;
  pbvt_commit(pvs, NULL);
  test[0] = 2;
  test[0] = 3;
  pbvt_commit(pvs, NULL);
  assert(test[0] == 3);
  test[0] = 4;
  // We didn't commit the previous change, so it gets discarded
  pbvt_checkout_n(pvs, 1);
  assert(test[0] == 1);

  for (int i = 0; i < 0x100; ++i)
    test[i] = 0;
  pbvt_commit(pvs, NULL);

  pbvt_print(pvs, "out.dot");

  for (int64_t i = 1; i < trials; ++i) {
    for (int i = 0; i < 0x100; ++i) {
      uint8_t key = rand() & (0x10000 - 1);
      uint8_t val = rand() & 0xff;
      test[key] = val;
    }
    COZ_PROGRESS;
    pbvt_commit(pvs, NULL);
    COZ_PROGRESS;
    if (pbvt_size(pvs) > gc_threshold) {
      pbvt_gc_n(pvs, gc_threshold / 2);
      COZ_PROGRESS;
    }
    if (i % 0x400 == 0)
      pbvt_stats(pvs);
    COZ_PROGRESS;
  }

  pbvt_print(pvs, "out.dot");

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
      pbvt_print(pvs, "out.dot");
      printf("printed to out.dot!\n");
      break;
    case 'f':
      pbuf += sscanf(pbuf, "%p", &idx);
      printf("Value at %.16lx: %.2x\n", idx, *(uint8_t *)idx);
      break;
    case 'c':
      printf("Committing...\n");
      pbvt_commit(pvs, NULL);
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
      pbvt_checkout(pvs, 0);
      break;
    default:
      printf("Unrecognized %c\n", buf[0]);
      break;
    }
    pbvt_print(pvs, "out.dot");
  }

cleanup:
  pbvt_print(pvs, "out.dot");
  pbvt_stats(pvs);
  pbvt_cleanup(pvs);

  return 0;
}
