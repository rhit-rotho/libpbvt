#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <malloc.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <threads.h>
#include <unistd.h>

#include "cassert.h"
#include "fasthash.h"
#include "memory.h"
#include "pbvt.h"

uint64_t get_child(PVector *n, int index);
void set_bit(uint64_t *bitmap, int index);

#define MIN(x, y) ((x) > (y) ? (y) : (x))
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define CLAMP(x, a, b) MIN(MAX(x, a), b)

#define STACK_SIZE (8 * 0x1000 * 0x1000)
#define HEAP_SIZE (0x1000)
#define UNUSED(x) (void)(x)

enum MSG_TYPE {
  MSG_NONE = 0,
  MSG_HANDSHAKE,
  MSG_REGISTER_RANGE,
  MSG_WRITE_PROTECT,
  MSG_SHUTDOWN,
  MSG_SUCCESS,
  MSG_COMMIT,
  MSG_HANDLE_FAULT,
  MSG_FAILURE,
  NUM_MSGS
};

#define xperror(x)                                                             \
  do {                                                                         \
    perror(x);                                                                 \
    exit(-1);                                                                  \
  } while (0);

typedef struct uffd_args {
  PVectorState *pvs;
  int infd;
} uffd_args;

typedef struct MessageRange {
  void *range;
  uint64_t n;
} MessageRange;

typedef struct MessageWP {
  Range *r;
  uint8_t dirty;
} MessageWP;

typedef struct MonitorMessage {
  char type;
  char status;
  union {
    void *addr;
    MessageRange range;
    MessageWP wp;
  } data;
  union {
    Commit *commit;
  } reply;
  pthread_cond_t reply_cond;
  pthread_mutex_t reply_mutex;
} MonitorMessage;

void *clone_stk;
int efd;
MallocState *persistent_heap;
PVectorState *pvs;

void *alt_stk;

#define MAX_QUEUE_SIZE (32)

struct MonitorMessage *queue[MAX_QUEUE_SIZE];
pthread_mutex_t queue_mutex;
int head = 0;
int tail = 0;

int mon_enqueue(MonitorMessage *msg) {
  pthread_mutex_lock(&queue_mutex);

  queue[tail] = msg;
  tail = (tail + 1) % MAX_QUEUE_SIZE;
  assert(head != tail);
  pthread_mutex_unlock(&queue_mutex);
  return 0;
}

MonitorMessage *mon_dequeue(void) {
  pthread_mutex_lock(&queue_mutex);
  assert(head != tail);

  MonitorMessage *msg = queue[head];
  head = (head + 1) % MAX_QUEUE_SIZE;
  pthread_mutex_unlock(&queue_mutex);
  return msg;
}

void msg_wait(MonitorMessage *msg) {
  msg->status = MSG_NONE;
  pthread_mutex_init(&msg->reply_mutex, NULL);
  pthread_cond_init(&msg->reply_cond, NULL);

  mon_enqueue(msg);

  pthread_mutex_lock(&msg->reply_mutex);

  // Wake up monitor thread
  uint64_t c = 1;
  write(efd, &c, sizeof(c));

  while (msg->status == MSG_NONE) {
    pthread_cond_wait(&msg->reply_cond, &msg->reply_mutex);
  }
  pthread_mutex_unlock(&msg->reply_mutex);

  pthread_mutex_destroy(&msg->reply_mutex);
  pthread_cond_destroy(&msg->reply_cond);
}

void msg_reply(MonitorMessage *msg, int status) {
  pthread_mutex_lock(&msg->reply_mutex);
  msg->status = status;
  pthread_mutex_unlock(&msg->reply_mutex);
  pthread_cond_signal(&msg->reply_cond);
}

void segv_monitor(int signo, siginfo_t *si, void *ctx) {
  UNUSED(ctx);
  UNUSED(signo);

  assert(signo == SIGSEGV);

  MonitorMessage msg = {0};
  msg.type = MSG_HANDLE_FAULT;
  msg.data.addr = si->si_addr;
  msg_wait(&msg);

  assert(msg.status == MSG_SUCCESS);

  return;
}

// Move any bytes into active range if possible (i.e., stop shadowing memory)
void pbvt_relocate_into_internal(Range *r, PVector *v) {
  for (size_t i = 0; i < r->len; i += NUM_BOTTOM) {
    PVectorLeaf *l = pvector_get_leaf(v, (uint64_t)r->address + i);
    if (!l)
      continue;

    if (fasthash64((uint8_t *)r->address + i, NUM_BOTTOM, 0) != l->hash)
      memcpy((uint8_t *)r->address + i, UNTAG(l->bytes), NUM_BOTTOM);
    if (!TAGGED(l->bytes))
      continue;
    memory_free(NULL, UNTAG(l->bytes));
    l->bytes = (uint8_t *)r->address + i;
  }
}

// Similar to write-protect, move any bytes out of active range
void pbvt_relocate_away_internal(Range *r) {
  for (size_t i = 0; i < r->len; i += NUM_BOTTOM) {
    uint64_t hash = fasthash64(r->address + i, NUM_BOTTOM, 0);
    PVectorLeaf *l = ht_get(ht, hash);
    // Move any relevant nodes out of the way so they don't get
    // clobbered by writes to this page
    void *arrp = UNTAG(l->bytes);
    if (r->address <= arrp && arrp < r->address + r->len) {
      uint8_t *back = memory_calloc(NULL, NUM_BOTTOM, sizeof(uint8_t));
      memcpy(back, arrp, NUM_BOTTOM);
      l->bytes = TAG(back);
    }
  }
}

void uffd_segv(int signo) {
  UNUSED(signo);
  printf("WARNING: got segfault in uffd_montior\n");
  abort();
}

int uffd_monitor(void *args) {
  UNUSED(args);
  printf("uffd_monitor: %d\n", getpid());

  signal(SIGSEGV, uffd_segv);

  struct pollfd pollfds[2];
  struct uffd_msg msg = {0};

  // Copy, since the stack frame containing the arguments to clone gets freed
  // after our handshake
  PVectorState *pvs = ((uffd_args *)args)->pvs;
  int infd = ((uffd_args *)args)->infd;

#ifdef UFFD_USER_MODE_ONLY
  int uffd =
      syscall(SYS_userfaultfd, O_NONBLOCK | O_CLOEXEC | UFFD_USER_MODE_ONLY);
#else
  int uffd = -1;
#endif
  if (uffd < 0) {
    uffd = open("/dev/zero", O_RDONLY);
    goto skip_uffd;
  }

  struct uffdio_api uffd_api = {};
  uffd_api.api = UFFD_API;
  uffd_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
  if (ioctl(uffd, UFFDIO_API, &uffd_api))
    xperror("ioctl");

skip_uffd:
  pollfds[0].fd = uffd;
  pollfds[0].events = POLLIN | POLLERR;
  pollfds[1].fd = infd;
  pollfds[1].events = POLLIN | POLLERR;

  uint64_t c;
  read(efd, &c, sizeof(c));

  MonitorMessage *tmsg = mon_dequeue();
  assert(tmsg->type == MSG_HANDSHAKE);
  msg_reply(tmsg, MSG_SUCCESS);

  for (;;) {
    if (poll(pollfds, 2, 1000) < 0)
      xperror("poll(uffd)");

    // TODO: Right now we technically only need the read, since it's blocking,
    // but according to userfaultfd(2) we should also be doing POLLERR to
    // resolve any potential issues with our ioctl() calls.
    if (pollfds[0].revents & POLLERR)
      xperror("POLLERR in userfaultfd");

    if (pollfds[0].revents & POLLIN) {
      if (read(pollfds[0].fd, &msg, sizeof(msg)) < 0)
        continue;

      switch (msg.event) {
      case MSG_NONE: // HACK: Fallback when using /dev/zero for events
        break;
      case UFFD_EVENT_PAGEFAULT:
        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
          Range *r = NULL;
          for (size_t i = 0; i < queue_size(pvs->ranges); ++i) {
            r = queue_peekleft(pvs->ranges, i);
            if (r->address == (void *)msg.arg.pagefault.address)
              break;
            r = NULL;
          }

          assert(r);

          pbvt_relocate_away_internal(r);
          pbvt_write_protect_internal(uffd, r, 1);
        }
        break;
      default:
        printf("unrecognized event %d\n", msg.event);
        break;
      }
    }

    if (pollfds[1].revents & POLLIN) {
      if (read(pollfds[1].fd, &c, sizeof(c)) < 0)
        xperror("monitor read");

      MonitorMessage *msg = mon_dequeue();

      switch (msg->type) {
      case MSG_REGISTER_RANGE: {
#ifdef UFFDIO_REGISTER_MODE_WP
        uint64_t range = (uint64_t)msg->data.range.range;
        uint64_t n = msg->data.range.n;

        struct uffdio_register uffd_register = {};
        uffd_register.range.start = (__u64)range;
        uffd_register.range.len = n;
        uffd_register.mode = UFFDIO_REGISTER_MODE_WP;
        ioctl(uffd, UFFDIO_REGISTER, &uffd_register);
        // xperror("ioctl(uffd, UFFDIO_REGISTER)");
#endif

        msg_reply(msg, MSG_SUCCESS);
        break;
      }
      case MSG_HANDLE_FAULT: {
        void *addr = msg->data.addr;

        Range *r = NULL;
        for (size_t i = 0; i < queue_size(pvs->ranges); ++i) {
          r = queue_peekleft(pvs->ranges, i);
          if (r->address <= addr && addr < r->address + r->len)
            break;
          r = NULL;
        }

        // TODO: This could be a segfault
        if (!r) {
          printf("Couldn't find range for address %.16lx!\n", (uint64_t)addr);
          msg_reply(msg, MSG_FAILURE);
          break;
        }

        pbvt_relocate_away_internal(r);
        pbvt_write_protect_internal(uffd, r, 1);

        if (pvs->on_fault)
          pvs->on_fault(pvs->on_fault_ctx, addr);
        msg_reply(msg, MSG_SUCCESS);
        break;
      }
      case MSG_WRITE_PROTECT: {
        Range *r = msg->data.wp.r;
        uint8_t dirty = msg->data.wp.dirty;

        pbvt_write_protect_internal(uffd, r, dirty);
        msg_reply(msg, MSG_SUCCESS);
        break;
      }
      case MSG_COMMIT: {
        msg->reply.commit = pbvt_commit_internal(uffd);
        msg_reply(msg, MSG_SUCCESS);
        break;
      }
      case MSG_SHUTDOWN:
        msg_reply(msg, MSG_SUCCESS);
        goto cleanup;
      default:
        xperror("userfaultfd_monitor: unrecognized char");
        break;
      }

      continue;
    }
  }

cleanup:
  exit(EXIT_SUCCESS);
}

void persistent_heap_hook(BinHdr *bin) {
  return pbvt_track_range(bin, bin->memsz, PROT_READ | PROT_WRITE);
}

void pbvt_init(void) {
  pvs = memory_calloc(NULL, 1, sizeof(PVectorState));
  pvs->states = ht_create();
  // TODO: Replace with appropriate datastructure (hash table?)
  pvs->ranges = queue_create();
  pvs->branches = ht_create();
  clone_stk = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (clone_stk == MAP_FAILED)
    xperror("mmap");

  efd = eventfd(0, EFD_SEMAPHORE);
  if (efd < 0)
    xperror("eventfd");

  pthread_mutex_init(&queue_mutex, NULL);

  uffd_args args;
  args.pvs = pvs;
  args.infd = efd;
  if (clone(uffd_monitor, clone_stk + STACK_SIZE, CLONE_VM, &args) == -1)
    xperror("clone");

  alt_stk = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (alt_stk == MAP_FAILED)
    xperror("mmap");

  stack_t ss = {0};
  ss.ss_size = STACK_SIZE;
  ss.ss_sp = alt_stk;
  if (sigaltstack(&ss, NULL) < 0)
    xperror("sigaltstack");

  struct sigaction act = {0};
  act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  act.sa_sigaction = segv_monitor;
  sigemptyset(&act.sa_mask);
  if (sigaction(SIGSEGV, &act, NULL) < 0)
    xperror("sigaction(SIGSEGV)");

  MonitorMessage msg = {.type = MSG_HANDSHAKE};
  msg_wait(&msg);
  assert(msg.status == MSG_SUCCESS);

  // Create our null node ("null object" pattern if you like OOP)
  PVector *v = memory_calloc(NULL, 1, sizeof(PVector));
  v->hash = 0UL;
  v->refcount = 1;
  set_bit(v->bitmap, 0);
  v->children = memory_calloc(NULL, 1, sizeof(uint64_t));
  Commit *h = pbvt_commit_create(v, NULL);
  pvs->head = h;
  ht_insert(pvs->states, h->hash, h);

  // Create table for hashconsing ("flyweight pattern" if you like OOP)
  ht = ht_create();
  ht_insert(ht, 0UL, v);

  // Create a persistent heap (for use in pbvt_malloc, pbvt_free, ...)
  assert(sizeof(MallocState) < HEAP_SIZE);
  persistent_heap = mmap(NULL, HEAP_SIZE, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (persistent_heap == MAP_FAILED)
    xperror("mmap");
  pbvt_track_range(persistent_heap, HEAP_SIZE, PROT_READ | PROT_WRITE);
  persistent_heap->on_mmap = persistent_heap_hook;
  return;
}

// TODO: Add support for installing multiple hooks
int pbvt_install_hook(PBVT_HOOK_TYPE type, pbvt_hook hook, void *ctx) {
  switch (type) {
  case PBVT_ON_FAULT:
    if (pvs->on_fault)
      return -1;
    pvs->on_fault = hook;
    pvs->on_fault_ctx = ctx;
    return 0;
  default:
    return -1;
  }
}

Commit *pbvt_commit_create(PVector *v, Commit *p) {
  Commit *c = memory_calloc(NULL, 1, sizeof(Commit));
  assert(c != NULL);

  uint64_t content[2] = {v->hash, p ? p->hash : 0UL};
  c->hash = fasthash64(content, sizeof(content), 0);
  // No need to increment v's reference count, since our caller already has a
  // reference to v.
  c->current = v;
  c->parent = p;
  return c;
}

void pbvt_commit_free(Commit *c) {
  pvector_gc(c->current, MAX_DEPTH - 1);
  memory_free(NULL, c);
}

void pbvt_branch_free(Branch *b) {
  memory_free(NULL, b->name);
  memory_free(NULL, b);
}

void pbvt_cleanup() {
  MonitorMessage msg = {.type = MSG_SHUTDOWN};
  msg_wait(&msg);
  assert(msg.status == MSG_SUCCESS);

  // Free commits
  for (size_t i = 0; i < pvs->states->cap; ++i) {
    HashBucket *bucket = &pvs->states->buckets[i];
    for (size_t j = 0; j < bucket->size; ++j) {
      Commit *c = (Commit *)bucket->values[j];
      pbvt_commit_free(c);
    }
  }
  ht_free(pvs->states);

  // Free branches
  for (size_t i = 0; i < pvs->branches->cap; ++i) {
    HashBucket *bucket = &pvs->branches->buckets[i];
    for (size_t j = 0; j < bucket->size; ++j) {
      Branch *b = (Branch *)bucket->values[j];
      pbvt_branch_free(b);
    }
  }
  ht_free(pvs->branches);

  // Free ranges
  while (queue_size(pvs->ranges) > 0)
    memory_free(NULL, queue_popleft(pvs->ranges));
  queue_free(pvs->ranges);

  // Free null node
  memory_free(NULL, UNTAG(((PVectorLeaf *)ht_get(ht, 0UL))->bytes));
  memory_free(NULL, ht_get(ht, 0UL));
  ht_remove(ht, 0UL);

  // Free hashtable
  ht_free(ht);

  close(efd);

  // TODO: Make these client stubs for message passing to another thread
  munmap(clone_stk, STACK_SIZE);
  printf("--- Persistent heap ---\n");
  print_malloc_stats(persistent_heap);
  printf("-----------------------\n");
  munmap(persistent_heap, HEAP_SIZE);
  memory_free(NULL, pvs);
  print_malloc_stats(NULL);
}

void pbvt_gc_n(size_t n) {
  size_t len = 0;
  Commit *h = pvs->head;
  while (h) {
    h = h->parent;
    len++;
  }

  assert(n < len);
  h = pvs->head;
  for (size_t i = 0; i < -1 + len - n; ++i)
    h = h->parent;
  Commit *tail = h;
  h = h->parent;

  size_t t = 0;
  while (h) {
    t++;
    ht_remove(pvs->states, h->hash);
    Commit *p = h->parent;
    pbvt_commit_free(h);
    h = p;
  }
  tail->parent = NULL;
  assert(t == n);
}

size_t pbvt_size(void) { return ht_size(pvs->states); }

void pbvt_print(char *path) {
  HashTable *pr = ht_create();
  FILE *f = fopen(path, "w");
  if (f == NULL)
    return;
  fprintf(f, "digraph {\n");
  fprintf(f, "\tnode[shape=record];\n");

  HashTable *heads = ht_create();
  for (size_t i = 0; i < pvs->branches->cap; ++i) {
    HashBucket *bucket = &pvs->branches->buckets[i];
    for (size_t j = 0; j < bucket->size; ++j) {
      Branch *b = (Branch *)bucket->values[j];
      fprintf(f, "\tv%.16lx [\n", b->head->hash);
      if (b->head == pvs->head)
        fprintf(f, "\t\tcolor=\"green\"\n");
      else
        fprintf(f, "\t\tcolor=\"red\"\n");
      fprintf(f, "\t\tlabel=\"%.16lx (%s)\"\n", b->head->hash, b->name);
      fprintf(f, "\t];\n");
      ht_insert(heads, b->head->hash, b->head);
    }
  }

  for (size_t i = 0; i < pvs->states->cap; ++i) {
    HashBucket *bucket = &pvs->states->buckets[i];
    for (size_t j = 0; j < bucket->size; ++j) {
      Commit *c = (Commit *)bucket->values[j];
      if (c->parent)
        fprintf(f, "\tv%.16lx -> v%.16lx;\n", c->hash, c->parent->hash);
      if (ht_get(heads, c->hash))
        continue;
      fprintf(f, "\tv%.16lx [\n", c->hash);
      fprintf(f, "\t\tlabel=\"%.16lx\"\n", c->hash);
      fprintf(f, "\t];\n");
    }
  }

  ht_free(heads);

  // TODO: Add support for printing both branch information and program timeline
  goto cleanup;

  fprintf(f, "\ttimeline [\n");
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<timeline>timeline|{");
  Commit *h = pvs->head;
  Queue *q = queue_create();
  while (h) {
    queue_push(q, h);
    h = h->parent;
  }

  for (size_t j = 1; j < queue_size(q); ++j) {
    h = queue_peekright(q, j);
    fprintf(f, "<%ld>%.16lx", j, h->hash);
    if (j != queue_size(q) - 1)
      fprintf(f, "|");
  }

  fprintf(f, "}}");
  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  for (size_t j = 1; j < queue_size(q); ++j) {
    h = queue_peekright(q, j);
    fprintf(f, "\ttimeline:%ld -> v%.16lx:n;\n", j, h->current->hash);
    h = h->parent;
  }

  for (size_t j = 1; j < queue_size(q); ++j) {
    h = queue_peekright(q, j);
    pbvt_print_node(f, pr, h->current, MAX_DEPTH - 1);
    h = h->parent;
  }

  queue_free(q);

  // for (size_t i = 0, n = queue_size(pvs->states); i < n; ++i)
  //   pbvt_print_node(f, pr, (PVector *)queue_peekleft(pvs->states, i),
  //                   MAX_DEPTH - 1);

cleanup:
  fprintf(f, "}\n");
  fclose(f);
  ht_free(pr);
}

void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level) {
  if (ht_get(pr, v->hash))
    return;
  ht_insert(pr, v->hash, v);

  size_t tlen = ftell(f);
  fprintf(f, "\tv%.16lx [\n", v->hash);
  fprintf(f, "\t\tcolorscheme = \"blues5\";\n");
  fprintf(f, "\t\tstyle = filled\n");
  fprintf(f, "\t\tfillcolor = %ld;\n", CLAMP(v->refcount, 1, 5));

  fprintf(f, "\t\tlabel = \"");
  if (level > 0) {
    // fprintf(f, "{<head>%.2lx (%ld refs)|{", v->hash & 0xff, v->refcount);
    fprintf(f, "{{");
    for (size_t i = 0; i < NUM_CHILDREN; ++i) {
      if (get_child(v, i))
        fprintf(f, "<%ld>", i);
      else
        fprintf(f, "<%ld>x", i);
      if (i != NUM_CHILDREN - 1)
        fprintf(f, "|");
      if (ftell(f) - tlen > 8192) {
        fprintf(f, "\\\n");
        tlen = ftell(f);
      }
    }
  } else {
    PVectorLeaf *l = (PVectorLeaf *)v;
    // fprintf(f, "{<head>%.2lx (%ld refs) %p[%ld]|{", v->hash & 0xff,
    // v->refcount,
    //         UNTAG(l->bytes), NUM_BOTTOM);
    fprintf(f, "{{");
    for (size_t i = 0; i < NUM_BOTTOM; ++i) {
      fprintf(f, "<%ld>%.2x", i, UNTAG((l->bytes))[i]);
      if (i != NUM_BOTTOM - 1)
        fprintf(f, "|");
      if (ftell(f) - tlen > 8192) {
        fprintf(f, "\\\n");
        tlen = ftell(f);
      }
    }
  }
  fprintf(f, "}}");

  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  if (level == 0)
    return;

  for (size_t i = 0; i < NUM_CHILDREN; ++i) {
    if (get_child(v, i)) {
      fprintf(f, "\tv%.16lx:%ld -> v%.16lx:n;\n", v->hash, i, get_child(v, i));
      pbvt_print_node(f, pr, ht_get(ht, get_child(v, i)), level - 1);
    }
  }
}

void pbvt_debug(void) {
  printf("---------PBVT STATS---------\n");
  printf("NUM_BITS       = %d\n", NUM_BITS);
  // printf("MAX_INDEX      = 0x%lx\n", MAX_INDEX);
  printf("NUM_CHILDREN   = %ld\n", NUM_CHILDREN);
  // printf("BOTTOM_BITS    = %d\n", BOTTOM_BITS);
  // printf("MAX_DEPTH      = %d\n", MAX_DEPTH);
  printf("NUM_BOTTOM     = %ld\n", NUM_BOTTOM);
  // printf("BITS_PER_LEVEL = %d\n", BITS_PER_LEVEL);
  // printf("BOTTOM_MASK    = %ld\n", BOTTOM_MASK);
  // printf("CHILD_MASK     = %ld\n", CHILD_MASK);
}

extern MallocState global_heap;
void pbvt_stats() {
  pbvt_debug();
  printf("Tracked states: %ld\n", ht_size(pvs->states));
  printf("Number of nodes: %ld\n", ht_size(ht));
  printf("Theoretical max: 0x%lx\n", MAX_INDEX);

  Range *r;
  size_t live = 0;
  for (size_t i = 0; i < queue_size(pvs->ranges); ++i) {
    r = queue_peekleft(pvs->ranges, i);
    live += r->len;
  }

  // printf("Size of shadowed (copied) memory: %ld bytes\n", overhead);
  printf("Size of all tracked (live) memory: %ld bytes\n", live);

  // printf("Estimated overhead: %f%%\n", 100.0 * overhead / live);

  size_t full_copy_sz = live * ht_size(pvs->states);
  printf("Assuming full-copy for each state: %ld bytes\n", full_copy_sz);
  //   printf("Estimated reduction in overhead (overestimate): %f%%\n",
  //          100.0 * ((float)overhead - full_copy_sz) / full_copy_sz);

  print_malloc_stats(NULL);
}

uint64_t pbvt_capacity(void) { return MAX_INDEX; }

// TODO: Suboptimal, complexity is O(kmlog_d(n)), k number of bytes, n size of
// trie, m number of commits
Commit *pbvt_last_changed(uint64_t idx, size_t n) {
  size_t tmpd = -1;
  size_t mindepth = -1;
  Commit *tmpc, *c = NULL;
  for (size_t i = 0; i < n; ++i) {
    tmpc = pbvt_last_changed_internal(idx + i, &tmpd);
    if (tmpd < mindepth) {
      mindepth = tmpd;
      c = tmpc;
    }
  }

  return c;
}

// O(mlog_d(n))
Commit *pbvt_last_changed_internal(uint64_t idx, size_t *depth) {
  Commit *head = pbvt_head();

  *depth = 0;
  Commit *p = head->parent;
  while (p) { // O(m) - m number of commits
    PVector *cv = head->current;
    PVector *pv = p->current;
    uint64_t idxn = idx >> BOTTOM_BITS;
    uint64_t key;

    // Traverse both tries down to the leaf, if we get to a point where the
    // hashes are the same, then this node couldn't have changed, so break.
    // O(log_d(n)) - n is the size of the trie
    for (int i = MAX_DEPTH - 1; i >= 1; --i) {
      key = (idxn >> (i - 1) * BITS_PER_LEVEL) & CHILD_MASK;
      if (get_child(pv, key) == get_child(cv, key))
        goto skip;
      if (get_child(cv, key) == 0UL) {
        *depth = -1;
        return NULL;
      }
      if (get_child(pv, key) == 0UL) {
        *depth = -1;
        return NULL;
      }

      pv = ht_get(ht, get_child(pv, key)); // O(1)
      cv = ht_get(ht, get_child(cv, key));
    }
    PVectorLeaf *pvl = (PVectorLeaf *)pv;
    PVectorLeaf *cvl = (PVectorLeaf *)cv;

    // TODO: Verify bottom bits at the desired positions (n bytes) have actually
    // changed.
    if (pvl->bytes[idx & BOTTOM_MASK] != cvl->bytes[idx & BOTTOM_MASK])
      return p;

  skip:
    p = p->parent;
    *depth = 0;
  }
  *depth = 0;
  return NULL;
}

void pbvt_track_range(void *range, size_t n, int perms) {
  // TODO: Zero-pad, handle this correctly
  assert((uint64_t)range % sysconf(_SC_PAGESIZE) == 0);
  assert(n % NUM_BOTTOM == 0);
  assert(n % sysconf(_SC_PAGESIZE) == 0);

  PVector *v = pvector_update_n(pvs->head->current, (uint64_t)range, range, n);
  Commit *h = pbvt_commit_create(v, pvs->head);
  ht_insert(pvs->states, h->hash, h);
  pvs->head = h;

  // See pbvt_relocate_into_internal
  PVectorLeaf *l;
  for (size_t i = 0; i < n; i += NUM_BOTTOM) {
    l = ht_get(ht, fasthash64(range + i, NUM_BOTTOM, 0));
    assert(l && "Hashed contents don't match any existing node");
    // Is this region in our malloc'd region, or backed by the memory it
    // represents? If not, we can make it so and save some space
    if (!TAGGED(l->bytes))
      continue;
    memory_free(NULL, UNTAG(l->bytes));
    l->bytes = range + i;
  }

  MonitorMessage msg = {.type = MSG_REGISTER_RANGE};
  msg.data.range.range = range;
  msg.data.range.n = n;
  msg_wait(&msg);
  assert(msg.status == MSG_SUCCESS);

  for (size_t i = 0; i < n; i += 0x1000) {
    Range *r = memory_calloc(NULL, 1, sizeof(Range));
    r->address = range + i;
    r->len = 0x1000;
    r->perms = perms;
    pbvt_write_protect(r, 0);
    queue_push(pvs->ranges, r);
  }
}

Commit *pbvt_commit() {
  MonitorMessage msg = {.type = MSG_COMMIT};
  msg_wait(&msg);
  assert(msg.status == MSG_SUCCESS);
  return msg.reply.commit;
}

Commit *pbvt_commit_internal(int uffd) {
  Range *r;

  Branch *cb = pvs->branch;
  Commit *h = pvs->head;
  PVector *u;
  PVector *v = h->current;
  v->refcount++;

  for (size_t i = 0; i < queue_size(pvs->ranges); ++i) {
    r = queue_peekleft(pvs->ranges, i);
    if (!r->dirty)
      continue;

    pbvt_write_protect_internal(uffd, r, 0);
    u = pvector_update_n(v, (uint64_t)r->address, (uint8_t *)r->address,
                         r->len);

    PVectorLeaf *l;
    for (size_t i = 0; i < r->len; i += NUM_BOTTOM) {
      l = ht_get(ht, fasthash64((uint8_t *)r->address + i, NUM_BOTTOM, 0));
      // Is this region in our malloc'd region, or backed by the memory it
      // represents? If not, we can make it so and save some space
      if (!TAGGED(l->bytes))
        continue;
      memory_free(NULL, UNTAG(l->bytes));
      l->bytes = (uint8_t *)r->address + i;
    }

    pvector_gc(v, MAX_DEPTH - 1);
    v = u;
  }
  Commit *nh = pbvt_commit_create(v, h);
  if (!ht_get(pvs->states, nh->hash)) {
    ht_insert(pvs->states, nh->hash, nh);
  } else {
    uint64_t hash = nh->hash;
    pbvt_commit_free(nh);
    nh = ht_get(pvs->states, hash);
    return nh;
  }

  // If we're already on a branch && we modified the current head of a branch,
  // update the current head to our new commit, otherwise we're in a "detached"
  // state, with no current branch
  if (cb && h == cb->head)
    cb->head = nh;
  else
    pvs->branch = NULL;
  pvs->head = nh;
  return nh;
}

Commit *pbvt_branch_head(char *name) {
  uint64_t key = fasthash64(name, strlen(name), 0);
  Branch *b = ht_get(pvs->branches, key);
  assert(b && "Branch does not exist!");
  return b->head;
}

void pbvt_branch_checkout(char *name) {
  uint64_t key = fasthash64(name, strlen(name), 0);
  Branch *b = ht_get(pvs->branches, key);
  assert(b && "Branch does not exist!");
  pbvt_checkout(b->head);
  pvs->branch = b;
}

// Commit the current commit as "name"
void pbvt_branch_commit(char *name) {
  uint64_t key = fasthash64(name, strlen(name), 0);
  Branch *b = memory_calloc(NULL, 1, sizeof(Branch));
  b->head = pvs->head;

  size_t nlen = strlen(name);
  b->name = memory_malloc(NULL, nlen + 1);
  strncpy(b->name, name, nlen + 1);
  pvs->branch = b;
  ht_insert(pvs->branches, key, b);
}

void pbvt_write_protect_internal(int uffd, Range *r, uint8_t dirty) {
#ifdef UFFDIO_WRITEPROTECT_MODE_WP
  struct uffdio_writeprotect wp = {0};
  wp.range.start = (uint64_t)r->address;
  wp.range.len = r->len;
#endif
  int prot;

  if (dirty) {
    r->dirty = 1;
#ifdef UFFDIO_WRITEPROTECT_MODE_WP
    wp.mode = 0;
#endif
    prot = r->perms;
  } else {
    r->dirty = 0;
#ifdef UFFDIO_WRITEPROTECT_MODE_WP
    wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
#endif
    prot = r->perms & ~PROT_WRITE;
  }

#ifdef UFFDIO_WRITEPROTECT
  if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == 0)
    return;
#endif

  if (mprotect(r->address, r->len, prot) < 0)
    xperror("mprotect");
  // TODO: This may not be necessary
  if (msync(r->address, r->len, MS_SYNC) < 0)
    xperror("msync");
}

void pbvt_write_protect(Range *r, uint8_t dirty) {
  MonitorMessage msg = {.type = MSG_WRITE_PROTECT};
  msg.data.wp.r = r;
  msg.data.wp.dirty = dirty;
  msg_wait(&msg);
  assert(msg.status == MSG_SUCCESS);
}

Commit *pbvt_commit_parent(Commit *commit) { return commit->parent; }

Commit *pbvt_head() { return pvs->head; }

void pbvt_checkout(Commit *commit) {
  PVector *v = commit->current;

  // This puts us in a transient state
  for (size_t n = 0; n < queue_size(pvs->ranges); ++n) {
    Range *r = queue_peekleft(pvs->ranges, n);

    pbvt_relocate_into_internal(r, v);
    // Get back out of transient state, we assume any page faults from the
    // memcpy are resolved by uffd_monitor.
    pbvt_write_protect(r, 0);
  }
  pvs->head = commit;

  // TODO: Check to see if this commit was the head of any branch(?)
}

void *pbvt_calloc(size_t nmemb, size_t size) {
  return memory_calloc(persistent_heap, nmemb, size);
}
void *pbvt_realloc(void *ptr, size_t size) {
  return memory_realloc(persistent_heap, ptr, size);
}
void *pbvt_malloc(size_t size) { return memory_malloc(persistent_heap, size); }
void pbvt_free(void *ptr) { return memory_free(persistent_heap, ptr); }