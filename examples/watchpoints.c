// cc examples/watchpoints.c -O2 -Iinclude -lpbvt -o watchpoints

#include <assert.h>
#include <sys/mman.h>

#include "pbvt.h"

void log_changed(void *addr) {
  Commit *c = pbvt_last_changed(addr, 8);
  if (c)
    printf("Changed 0x%.16lx (val: %.16lx) after %.16lx\n", (uint64_t *)addr,
           *(uint64_t *)addr, c->hash);
  else
    printf("Unchanged %.16lx!\n", addr);
}

int main(int argc, char **argv) {

  pbvt_init();

  uint64_t counter_sz = 0x1000;
  uint64_t *counter = pbvt_calloc(sizeof(uint64_t), counter_sz);

  printf("Addr: %.16lx\n", counter);

  pbvt_commit();
  pbvt_branch_commit("main");

  printf("Initial: %.16lx\n", pbvt_head()->hash);
  for (int i = 0; i < counter_sz; i++) {
    counter[i] = i;
    pbvt_commit();
    printf("Current: %.16lx (modified idx 0x%.2x)\n", pbvt_head()->hash, i);
  }

  printf("Finished!\n");

  log_changed(&counter[21]);

  return 0;
}
