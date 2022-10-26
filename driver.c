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

  int64_t trials = atoll(argv[1]);
  int64_t gc_threshold = atoll(argv[2]);
  if (gc_threshold == -1)
    gc_threshold = INT64_MAX;

  PVectorState *pvs = pbvt_init();
  uint64_t max_index = pbvt_capacity();
  pbvt_debug();

  uint8_t *test =
      mmap((void *)0x10000UL, 0x4000, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_FIXED, -1, 0);

  // track changes to range
  pbvt_add_range(pvs, test, 0x4000);

  test[0] = 1;
  pbvt_commit_head(pvs);
  assert(test[0] == 1);
  test[0] = 2;
  test[0] = 3;
  pbvt_commit_head(pvs);
  assert(test[0] == 3);
  pbvt_checkout(pvs);
  assert(test[0] == 1);

  pbvt_print(pvs, "out.dot");

  goto driver;

random_insert:
  uint8_t *tarr = calloc(max_index + 1, sizeof(uint8_t));
  uint8_t t0 = 0;
  uint8_t t1 = 0;

  srand(0);
  for (int64_t i = 1; i < trials; ++i) {
    uint64_t key = rand() & max_index;
    uint8_t val = rand() & max_index;
    pbvt_update_head(pvs, key, pbvt_get_head(pvs, key) ^ val);
    tarr[key] ^= val;
    COZ_PROGRESS;
    if (pbvt_size(pvs) > gc_threshold) {
      pbvt_gc_n(pvs, gc_threshold / 2);
      COZ_PROGRESS;
    }
    for (int i = 0; i < 100; ++i) {
      uint64_t gkey = rand() & max_index;
      t0 ^= pbvt_get_head(pvs, gkey);
      t1 ^= tarr[gkey];
      if (tarr[gkey] != pbvt_get_head(pvs, gkey))
        printf("%d: %d %d\n", gkey, tarr[gkey], pbvt_get_head(pvs, gkey));
      assert(tarr[gkey] == pbvt_get_head(pvs, gkey));
      COZ_PROGRESS;
    }
  }
  printf("%.2x == %.2x? %s\n", t0, t1, t0 == t1 ? "true" : "false");
  assert(t0 == t1);
  free(tarr);
  goto cleanup;

insert_sample:
  // insert characters from sample.txt
  int fd = open("sample.txt", O_RDONLY);
  size_t pos = 0;
  char c;
  for (;;) {
    int nbytes = read(fd, &c, 1);
    if (nbytes < 0)
      perror("read");
    if (nbytes == 0)
      break;
    // printf("%c", c);
    pbvt_update_head(pvs, pos, c);
    if (pbvt_size(pvs) > gc_threshold) {
      pbvt_gc_n(pvs, gc_threshold / 2);
      COZ_PROGRESS;
    }
    pos++;
  }
  close(fd);
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
    case 'a':
      pbuf += sscanf(pbuf, "%p %d", &idx, &val);
      printf("Adding %d at 0x%0.16x\n", val, idx);
      pbvt_update_head(pvs, idx, val);
      break;
    case 'g':
      pbuf += sscanf(pbuf, "%lu", &idx);
      printf("old idx: %lu %lu\n", idx, pbvt_size(pvs) - 1);
      idx = MIN(idx, pbvt_size(pvs));
      printf("new idx: %lu\n", idx);
      printf("Garbage collecting oldest %lu items\n", idx);
      pbvt_gc_n(pvs, idx);
      break;
    case 'q':
      printf("Goodbye!\n");
      exit(0);
      break;
    case 'p':
      pbvt_print(pvs, "out.dot");
      printf("printed to out.dot!\n");
      break;
    // case 'u':
    //   auto_update = !auto_update;
    //   printf("Set auto-update to %s\n", auto_update ? "true" : "false");
    //   break;
    case 'f':
      pbuf += sscanf(pbuf, "%p", &idx);
      val = pbvt_get_head(pvs, idx);
      printf("Value at %.16lx: %.2x\n", idx, val);
      break;
    case 'c':
      printf("Committing...\n");
      pbvt_commit_head(pvs);
      break;
    case 't':
      pbuf += sscanf(pbuf, "%p %d", &idx, &val);
      printf("Modify (transient) %d at 0x%0.16x\n", val, idx);
      *(uint8_t *)idx = val;
      break;
    case 'u':
      pbuf += sscanf(pbuf, "%p", &idx);
      printf("Value (transient) at 0x%0.16x: %.2x\n", idx, *(uint8_t *)idx);
      break;
    case 'b':
      printf("Checkout one from head\n");
      pbvt_checkout(pvs);
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
