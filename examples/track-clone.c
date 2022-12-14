#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pbvt.h"

#define UNUSED(x) (void)(x)
#define STACK_SIZE (8 * 0x1000)

int child(void *arg) {
  printf("Hello, world!\n");
  uint64_t counter = 0;
  for (;;)
    counter = ~counter;

  UNUSED(arg);
}

int pid;

void sighand(int signo) {
  kill(pid, SIGINT);
  exit(0);
}

int main(int argc, char **argv) {
  pbvt_init();
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  signal(SIGINT, sighand);

  void *child_stk = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (child_stk == MAP_FAILED)
    perror("mmap");
  printf("Tracking range...");
  pbvt_track_range(child_stk, STACK_SIZE);
  pbvt_commit();
  printf("done.\n");
  pid = clone(child, child_stk + STACK_SIZE, CLONE_VM, NULL);

  for (;;) {
    pbvt_stats();
    pbvt_commit();
    usleep(1000);
  }

  pbvt_cleanup();
  return 0;
}