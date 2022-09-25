#include "pbvt.h"
#include "queue.h"
#include <stdio.h>

#define MIN(a, b) ((a) > (b) ? (b) : (a))

int main(int argc, char **argv) {
  queue_t *pvs = queue_create();
  queue_push(pvs, pbvt_create());

  for (int i = 0; i < 16; ++i)
    queue_push(pvs, pbvt_update(queue_front(pvs), i, i));
  for (int i = 0; i < 15; ++i)
    pbvt_gc(queue_popleft(pvs), MAX_DEPTH - 1);
  pbvt_print("out.dot", (pvector_t **)pvs->arr, pvs->pos);

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
      printf("Adding %d at %p\n", val, idx);
      queue_push(pvs, pbvt_update(queue_front(pvs), idx, val));
      break;
    case 'g':
      pbuf += sscanf(pbuf, "%d", &idx);
      printf("Garbage collecting oldest %d items\n", idx);
      for (uint64_t i = 0; i < MIN(idx, pvs->pos); ++i)
        pbvt_gc(queue_popleft(pvs), MAX_DEPTH - 1);
      break;
    case 'q':
      printf("Goodbye!\n");
      exit(0);
      break;
    default:
      printf("Unrecognized %c\n", buf[0]);
      break;
    }
    pbvt_print("out.dot", (pvector_t **)pvs->arr, pvs->pos);
  }

  return 0;
}