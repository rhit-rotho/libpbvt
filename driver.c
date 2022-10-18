#include "pbvt.h"
#include "queue.h"
#include <stdio.h>

#define MIN(a, b) ((a) > (b) ? (b) : (a))

int main(int argc, char **argv) {
  Queue *pvs = queue_create();
  queue_push(pvs, pbvt_create());

  for (int i = 0; i < 16; ++i) 
    queue_push(pvs, pbvt_update(queue_front(pvs), i, i));
  for (int i = 0; i < 16; ++i)
    pbvt_gc(queue_popleft(pvs), MAX_DEPTH - 1);
  pbvt_print("out.dot", (PVector **)pvs->arr, pvs->pos);

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
      queue_push(pvs, pbvt_update(queue_front(pvs), idx, val));
      break;
    case 'g':
      pbuf += sscanf(pbuf, "%lu", &idx);
      printf("old idx: %lu %lu\n", idx, pvs->pos - 1);
      idx = MIN(idx, pvs->pos - 1);
      printf("new idx: %lu\n", idx);
      printf("Garbage collecting oldest %lu items\n", idx);
      for (uint64_t i = 0; i < idx; ++i)
        pbvt_gc(queue_popleft(pvs), MAX_DEPTH - 1);
      break;
    case 'q':
      printf("Goodbye!\n");
      exit(0);
      break;
    case 'p':
      pbvt_print("out.dot", (PVector **)pvs->arr, pvs->pos);
      printf("printed to out.dot!\n");
      break;
    case 'u':
      auto_update = !auto_update;
      printf("Set auto-update to %s\n", auto_update ? "true" : "false");
      break;
    case 'f':
      pbuf += sscanf(pbuf, "%p", &idx);
      val = pbvt_get(queue_front(pvs), idx);
      printf("Value at %p: %ld\n", idx, val);
      break;
    default:
      printf("Unrecognized %c\n", buf[0]);
      break;
    }
    pbvt_print("out.dot", (PVector **)pvs->arr, pvs->pos);
  }

  return 0;
}