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
  uint64_t *counter = arg;
  *counter = 0;
  for (uint64_t i = 0; i < 0x100000000; ++i)
    *counter = i;
  write(1, "Goodbye!\n", 9);
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
  void *counter = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (counter == MAP_FAILED)
    perror("mmap");
  printf("%d: Tracking range... %p ", getpid(), counter);
  pbvt_track_range(counter, 0x1000, PROT_READ | PROT_WRITE);
  printf("done.\n");
  pbvt_commit();
  pid = clone(child, child_stk + STACK_SIZE, CLONE_VM, counter);

  for (int i = 0; i < 0x10; ++i) {
    sleep(1);
    pbvt_stats();
    // printf("Commit!\n");
    pbvt_commit();
  }

  pbvt_cleanup();
  return 0;
}