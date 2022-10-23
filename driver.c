#include "pbvt.h"

#include <coz.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define MIN(a, b) ((a) > (b) ? (b) : (a))
#define GC_THRESHOLD (24)

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("./driver [TRIALS]\n");
    return 1;
  }

  int64_t trials = atoll(argv[1]);

  PVectorState *pvs = pbvt_init();

  uint8_t t = 0;
random_insert:
  srand(0);
  for (int64_t i = 1; i < trials; ++i) {
    uint64_t key = rand() & 0xff;
    uint8_t val = rand() & 0xff;
    pbvt_update_latest(pvs, key, val);
    COZ_PROGRESS;
    if (i % GC_THRESHOLD == 0) {
      pbvt_gc_n(pvs, GC_THRESHOLD / 2);
      COZ_PROGRESS;
    }
    for (int i = 0; i < 100; ++i) {
      t ^= pbvt_get_latest(pvs, rand() & 0xff);
      COZ_PROGRESS;
    }
  }
  printf("%.2x\n", t);
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
    printf("%c", c);
    pbvt_update_latest(pvs, pos, c);
    // if (queue_size(pvs) > GC_THRESHOLD) {
    //   while (queue_size(pvs) > GC_THRESHOLD / 2)
    //     pbvt_gc(queue_popleft(pvs), MAX_DEPTH - 1);
    // }
    // if (pos % 0x8000 == 0)
    //   pbvt_print("out.dot", (PVector **)pvs->arr, pvs->pos);
    pos++;
  }
  // pbvt_print("out.dot", (PVector **)pvs->arr, queue_size(pvs));
  close(fd);
  goto cleanup;

  // driver:
  //   int auto_update = 1;
  //   for (;;) {
  //     char buf[0x100];
  //     uint64_t idx, val;
  //     printf("> ");
  //     fgets(buf, sizeof(buf) - 1, stdin);
  //     char *pbuf = buf;
  //     pbuf += 2;
  //     switch (buf[0]) {
  //     case 'a':
  //       pbuf += sscanf(pbuf, "%p %d", &idx, &val);
  //       printf("Adding %d at 0x%0.16x\n", val, idx);
  //       queue_push(pvs, pbvt_update(queue_front(pvs), idx, val));
  //       break;
  //     case 'g':
  //       pbuf += sscanf(pbuf, "%lu", &idx);
  //       printf("old idx: %lu %lu\n", idx, pbvt_states(pvs) - 1);
  //       idx = MIN(idx, pbvt_states(pvs));
  //       printf("new idx: %lu\n", idx);
  //       printf("Garbage collecting oldest %lu items\n", idx);
  //       pbvt_gc_n(pvs, MAX_DEPTH - 1);
  //       break;
  //     case 'q':
  //       printf("Goodbye!\n");
  //       exit(0);
  //       break;
  //     case 'p':
  //       // pbvt_print("out.dot", (PVector **)pvs->arr, queue_size(pvs));
  //       printf("printed to out.dot!\n");
  //       break;
  //     case 'u':
  //       auto_update = !auto_update;
  //       printf("Set auto-update to %s\n", auto_update ? "true" : "false");
  //       break;
  //     case 'f':
  //       pbuf += sscanf(pbuf, "%p", &idx);
  //       val = pbvt_get_latest(idx);
  //       printf("Value at %.16lx: %.2x\n", idx, val);
  //       break;
  //     default:
  //       printf("Unrecognized %c\n", buf[0]);
  //       break;
  //     }
  //     // pbvt_print("out.dot", (PVector **)pvs->arr, pvs->pos);
  //   }

cleanup:
  pbvt_cleanup(pvs);

  return 0;
}
