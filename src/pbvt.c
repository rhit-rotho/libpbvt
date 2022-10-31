#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <malloc.h>
#include <poll.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "fasthash.h"
#include "pbvt.h"

#define STACK_SIZE (8 * 1024 * 1024)
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define TAG(x) ((uint8_t *)((uint64_t)(x) | 1))
#define UNTAG(x) ((uint8_t *)((uint64_t)(x) & ~1))
#define TAGGED(x) (((uint64_t)(x)&1) == 1)

#define xperror(x)                                                             \
  do {                                                                         \
    perror(x);                                                                 \
    exit(-1);                                                                  \
  } while (0);

int uffd;
int uffd_monitor(void *args) {
  // TODO: Watch out for concurrent access of pvs, since this can be modified by
  // both the pagefault handler and any tasks that might have monitored ranges
  // TODO: Actually, it makes more sense to communicate with "pbvt" over a
  // socket that sends commands to this thread. That way we avoid races, and it
  // becomes possible to call "pbvt_track_range" in the main thread
  PVectorState *pvs = args;
  struct pollfd pollfds[1];
  struct uffd_msg msg = {};

  printf("Monitoring uffd %d for page faults...\n", uffd);

  pollfds[0].fd = uffd;
  pollfds[0].events = POLLIN;
  for (;;) {
    // TODO: Right now we technically only need the read, since it's blocking,
    // but according to userfaultfd(2) we should also be doing POLLERR to
    // resolve any potential issues with our ioctl() calls.
    if (poll(pollfds, 1, -1) <= 0)
      xperror("poll(uffd)");
    if (read(uffd, &msg, sizeof(msg)) < 0)
      xperror("read(uffd)");

    switch (msg.event) {
    case UFFD_EVENT_PAGEFAULT:
      if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
        // printf("Handle uffd-wp: %p\n", (void *)msg.arg.pagefault.address);

        Range *r = NULL;
        for (size_t i = 0; i < queue_size(pvs->ranges); ++i) {
          r = queue_peekleft(pvs->ranges, i);
          if (r->address == (void *)msg.arg.pagefault.address)
            break;
          r = NULL;
        }

        assert(r);

        for (size_t i = 0; i < r->len; i += NUM_BOTTOM) {
          uint64_t hash = fasthash64(r->address + i, NUM_BOTTOM, 0);
          PVectorLeaf *l = ht_get(ht, hash);
          // Move any relevant nodes out of the way so they don't get clobbered
          // by writes to this page
          void *arrp = UNTAG(l->bytes);
          if (r->address <= arrp && arrp < r->address + r->len) {
            uint8_t *back = calloc(NUM_BOTTOM, sizeof(uint8_t));
            memcpy(back, arrp, NUM_BOTTOM);
            l->bytes = TAG(back);
          }
        }

        pbvt_write_protect(r, 1);
      }
      break;
    default:
      printf("unrecognized event %d\n", msg.event);
      break;
    }
  }
  return 0;
}

PVectorState *pbvt_init(void) {
  uffd = syscall(SYS_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
  if (uffd < 0)
    xperror("userfaultfd");

  struct uffdio_api uffd_api = {};
  uffd_api.api = UFFD_API;
  uffd_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;

  if (ioctl(uffd, UFFDIO_API, &uffd_api))
    xperror("ioctl");

  PVectorState *pvs = calloc(1, sizeof(PVectorState));
  pvs->states = queue_create();
  // TODO: Replace with appropriate datastructure (hash table?)
  pvs->ranges = queue_create();
  if (clone(uffd_monitor, malloc(STACK_SIZE) + STACK_SIZE, CLONE_VM, pvs) == -1)
    xperror("clone");

  // Create our null node ("null object" pattern if you like OOP)
  PVector *v = calloc(1, MAX(sizeof(PVector), sizeof(PVectorLeaf)));
  v->hash = 0UL;
  pvs->head = pbvt_commit_create(v, NULL, NULL);
  queue_push(pvs->states, v);

  // Create table for hashconsing ("flyweight pattern" if you like OOP)
  ht = ht_create();
  ht_insert(ht, 0UL, v);
  return pvs;
}

Commit *pbvt_commit_create(PVector *v, Commit *p, char *name) {
  Commit *c = calloc(1, sizeof(Commit));

  if (name) {
    size_t len = strlen(name);
    c->name = malloc(len + 1);
    strncpy(c->name, name, len + 1);
  }

  uint64_t content[2] = {v->hash, p ? p->hash : 0UL};
  c->hash = fasthash64(content, sizeof(content), 0);
  c->current = v;
  c->parent = p;
  v->refcount++;
  return c;
}

void pbvt_commit_free(Commit *c) {
  pvector_gc(c->current, MAX_DEPTH - 1);
  free(c->name);
  free(c);
}

void pbvt_cleanup(PVectorState *pvs) {
  while (queue_size(pvs->states) > 0)
    pbvt_commit_free(queue_popleft(pvs->states));
  queue_free(pvs->states);
  while (queue_size(pvs->ranges) > 0)
    free(queue_popleft(pvs->ranges));
  queue_free(pvs->ranges);
  free(UNTAG(((PVectorLeaf *)ht_get(ht, 0UL))->bytes));
  free(ht_get(ht, 0UL));
  ht_free(ht);
  free(pvs);
}

void pbvt_gc_n(PVectorState *pvs, size_t n) {
  // TODO: What is a good abstraction here? The obvious thing to do would be to
  // trim the n oldest states, but we currently don't have enough information to
  // calculate that.
  printf("%s:%d(%p, %ld) Not implemented\n", __FUNCTION__, __LINE__, pvs, n);
}

size_t pbvt_size(PVectorState *pvs) { return queue_size(pvs->states); }

void pbvt_print(PVectorState *pvs, char *path) {
  HashTable *pr = ht_create();
  FILE *f = fopen(path, "w");
  if (f == NULL)
    return;
  fprintf(f, "digraph {\n");
  fprintf(f, "\tnode[shape=record];\n");

  // TODO: This is now a DAG
  fprintf(f, "\ttimeline [\n");
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<timeline>timeline|{");
  for (size_t i = 0, n = queue_size(pvs->states); i < n; ++i) {
    fprintf(f, "<%ld>%.16lx", i,
            ((PVector *)queue_peekleft(pvs->states, i))->hash);
    if (i != n - 1)
      fprintf(f, "|");
  }
  fprintf(f, "}}");
  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  for (size_t i = 0, n = queue_size(pvs->states); i < n; ++i) {
    fprintf(f, "\ttimeline:%ld -> v%.16lx;\n", i,
            ((PVector *)queue_peekleft(pvs->states, i))->hash);
  }

  for (size_t i = 0, n = queue_size(pvs->states); i < n; ++i)
    pbvt_print_node(f, pr, (PVector *)queue_peekleft(pvs->states, i),
                    MAX_DEPTH - 1);

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
  fprintf(f, "\t\tlabel = \"");
  if (level > 0) {
    fprintf(f, "{<head>%.16lx (%ld refs)|{", v->hash, v->refcount);
    for (size_t i = 0; i < NUM_CHILDREN; ++i) {
      if (v->children[i])
        fprintf(f, "<%ld>%.16lx", i, v->children[i]);
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
    fprintf(f, "{<head>%.16lx (%ld refs) %p[%ld]|{", v->hash, v->refcount,
            UNTAG(l->bytes), NUM_BOTTOM);
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
    if (v->children[i]) {
      fprintf(f, "\tv%.16lx:%ld -> v%.16lx;\n", v->hash, i, v->children[i]);
      pbvt_print_node(f, pr, ht_get(ht, v->children[i]), level - 1);
    }
  }
}

void pbvt_debug(void) {
  printf("---------PBVT STATS---------\n");
  printf("NUM_BITS       = %d\n", NUM_BITS);
  printf("MAX_INDEX      = %ld\n", MAX_INDEX);
  printf("NUM_CHILDREN   = %ld\n", NUM_CHILDREN);
  printf("BOTTOM_BITS    = %d\n", BOTTOM_BITS);
  printf("MAX_DEPTH      = %d\n", MAX_DEPTH);
  printf("NUM_BOTTOM     = %ld\n", NUM_BOTTOM);
  printf("BITS_PER_LEVEL = %d\n", BITS_PER_LEVEL);
  printf("BOTTOM_MASK    = %ld\n", BOTTOM_MASK);
  printf("CHILD_MASK     = %ld\n", CHILD_MASK);
}

void pbvt_stats(PVectorState *pvs) {
  printf("Tracked states: %ld\n", queue_size(pvs->states));
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

  size_t full_copy_sz = live * queue_size(pvs->states);
  printf("Assuming full-copy for each state: %ld bytes\n", full_copy_sz);
  //   printf("Estimated reduction in overhead (overestimate): %f%%\n",
  //          100.0 * ((float)overhead - full_copy_sz) / full_copy_sz);
}

uint64_t pbvt_capacity(void) { return MAX_INDEX; }

void pbvt_track_range(PVectorState *pvs, void *range, size_t n) {
  // TODO: Zero-pad, handle this correctly
  assert((uint64_t)range % sysconf(_SC_PAGESIZE) == 0);
  assert(n % NUM_BOTTOM == 0);
  assert(n % sysconf(_SC_PAGESIZE) == 0);

  PVector *c = pvector_update_n(pvs->head->current, (uint64_t)range, range, n);
  Commit *h = pbvt_commit_create(c, pvs->head, NULL);
  queue_push(pvs->states, h);
  pvs->head = h;

  PVectorLeaf *v;
  for (size_t i = 0; i < n; i += NUM_BOTTOM) {
    v = ht_get(ht, fasthash64(range + i, NUM_BOTTOM, 0));
    // Is this region in our malloc'd region, or backed by the memory it
    // represents? If not, we can make it so and save some space
    if (!TAGGED(v->bytes))
      continue;
    // printf("Changing backing memory for %.16lx to %p (was %p)\n", v->hash,
    //        range + i, UNTAG(v->bytes));
    free(UNTAG(v->bytes));
    v->bytes = range + i;
  }

  struct uffdio_register uffd_register = {};
  uffd_register.range.start = (__u64)range;
  uffd_register.range.len = n;
  uffd_register.mode = UFFDIO_REGISTER_MODE_WP;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffd_register))
    xperror("ioctl(uffd, UFFDIO_REGISTER)");

  for (size_t i = 0; i < n; i += 0x1000) {
    Range *r = calloc(1, sizeof(Range));
    r->address = range + i;
    r->len = 0x1000;
    pbvt_write_protect(r, 0);
    queue_push(pvs->ranges, r);
  }
}

// Similar logic to pvector_update_n
void pbvt_commit(PVectorState *pvs, char *name) {
  Range *r;

  Commit *h = pvs->head;
  PVector *t;
  PVector *c = h->current;
  c->refcount++;

  for (size_t i = 0; i < queue_size(pvs->ranges); ++i) {
    r = queue_peekleft(pvs->ranges, i);
    if (!r->dirty)
      continue;

    // printf("Saving state for %p...\n", (void *)r->address);
    t = pvector_update_n(c, (uint64_t)r->address, (uint8_t *)r->address,
                         r->len);
    pvector_gc(c, MAX_DEPTH - 1);
    c = t;

    PVectorLeaf *v;
    for (size_t i = 0; i < r->len; i += NUM_BOTTOM) {
      v = ht_get(ht, fasthash64((uint8_t *)r->address + i, NUM_BOTTOM, 0));
      // Is this region in our malloc'd region, or backed by the memory it
      // represents? If not, we can make it so and save some space
      if (!TAGGED(v->bytes))
        continue;
      // printf(
      //     "Changing backing memory for %.16lx to %p (was %p) (mem:
      //     %.16lx)\n", v->hash, (uint8_t *)r->address + i, UNTAG(v->bytes),
      //     fasthash64((uint8_t *)r->address + i, NUM_BOTTOM, 0));
      free(UNTAG(v->bytes));
      v->bytes = (uint8_t *)r->address + i;
    }

    pbvt_write_protect(r, 0);
  }

  h = pbvt_commit_create(c, h, name);
  queue_push(pvs->states, h);
  pvs->head = h;
}

void pbvt_write_protect(Range *r, uint8_t dirty) {
  struct uffdio_writeprotect wp;
  wp.range.start = (uint64_t)r->address;
  wp.range.len = r->len;

  if (dirty) {
    r->dirty = 1;
    wp.mode = 0;
  } else {
    r->dirty = 0;
    wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
  }

  if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp))
    xperror("ioctl(uffd, UFFDIO_WRITEPROTECT)");
}

void pbvt_checkout(PVectorState *pvs, uint64_t back) {
  // Commit *h = NULL;
  // for (size_t i = 0; i < queue_size(pvs->states); ++i)
  //   if (((Commit *)queue_peekleft(pvs->states, i))->hash == hash)
  //     h = queue_peekleft(pvs->states, i);
  Commit *h = pvs->head;
  for (uint64_t i = 0; i < back && h; ++i)
    h = h->parent;
  assert(h);
  PVector *v = h->current;

  // This puts us in a transient state
  for (size_t n = 0; n < queue_size(pvs->ranges); ++n) {
    Range *r = queue_peekleft(pvs->ranges, n);
    for (size_t i = 0; i < r->len; i += NUM_BOTTOM) {
      PVectorLeaf *l = pvector_get_leaf(v, (uint64_t)r->address + i);
      if (fasthash64((uint8_t *)r->address + i, NUM_BOTTOM, 0) != l->hash)
        memcpy((uint8_t *)r->address + i, UNTAG(l->bytes), NUM_BOTTOM);
    }
  }

  // Put us back in non-transient state, commit adds another state, so just drop
  // it
  pbvt_commit(pvs, NULL);
}