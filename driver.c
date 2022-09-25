#include "pbvt.h"
#include <stdio.h>

int main(int argc, char **argv) {
  // TODO: split out into timeline object
  size_t idx = 0;
  pvector_t *pvs[0x120] = {0};
  pvs[idx++] = pbvt_create();
  for (int i = 0; i < 0x10; ++i)
    pvs[idx++] = pbvt_update(pvs[idx - 1], i, i);

  for (int i = 0; i <= 8; ++i)
    pbvt_gc(pvs[i], MAX_DEPTH - 1);
  pbvt_print("out.dot", pvs, idx);

  return 0;
}