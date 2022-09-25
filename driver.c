#include "pbvt.h"
#include <stdio.h>

int main(int argc, char **argv) {

  // TODO: split out into timeline object

  uint64_t key = 0x1338;
  pvector_t *pv = pbvt_create();
  //   size_t idx = 0;
  //   pvector_t *pvs[10] = {0};
  //   pvs[idx++] = pbvt_create();
  //   pvs[idx++] = pbvt_update(pvs[idx - 1], 0x0a0a0a0beef, 0x1337);
  //   pvs[idx++] = pbvt_update(pvs[idx - 1], 0x7fff0ffdead, 0x1338);
  for (int i = 0; i < 64; ++i)
    pv = pbvt_update(pv, i, i);
  pv = pbvt_update(pv, 0x000000a0a0a0beef, 0x000000a0a0a0beef);
  pv = pbvt_update(pv, 0x000007fff0ffdead, 0x000007fff0ffdead);
  pv = pbvt_update(pv, 0xffffffffff600000, 0xffffffffff600000);

  pbvt_print("out.dot", &pv, 1);
  return 0;
}