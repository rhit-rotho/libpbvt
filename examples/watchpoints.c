// cc examples/watchpoints.c -O2 -Iinclude -lpbvt -o watchpoints

#include <sys/mman.h>

#include "pbvt.h"

void log_changed(void *addr) {
  Commit *c = pbvt_last_changed(addr, 1);
  if (c)
    printf("Changed 0x%.16lx (val: %.16lx) after %.16lx\n", (uint64_t *)addr,
           *(uint64_t *)addr, c->hash);
  else
    printf("Unchanged %.16lx!\n", addr);
}

int main(int argc, char **argv) {

  pbvt_init();

  // uint64_t *counter = pbvt_calloc(sizeof(uint64_t), 0x1000);
  uint64_t *counter =
      mmap(0x10000, 0x1000 * sizeof(uint64_t), PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANON, -1, 0);
  pbvt_track_range(counter, 0x1000 * sizeof(uint64_t), PROT_READ | PROT_WRITE);

  printf("Addr: %.16lx\n", counter);

  pbvt_commit();
  pbvt_branch_commit("main");

  printf("Initial: %.16lx\n", pbvt_head()->hash);
  for (int i = 0; i < 0x1000; i += 0x100) {
    counter[i] = -1;
    pbvt_commit();
    printf("Current: %.16lx (modified idx %d)\n", pbvt_head()->hash, i);
  }

  log_changed(&counter[0]);
  log_changed(&counter[256]);
  log_changed(&counter[3072]);
  log_changed(&counter[3840 - 1]);
  return 0;
}