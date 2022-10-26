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
  PVectorState *pvs = args;
  struct pollfd pollfds[1];
  struct uffd_msg msg = {};
  struct uffdio_writeprotect wp;

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
        printf("Handle uffd-wp: %p\n", (void *)msg.arg.pagefault.address);

        wp.range.start = msg.arg.pagefault.address;
        wp.range.len = 0x1000; // TODO: Replace with _SC_PAGE_SIZE
        wp.mode = 0;

        Range *r = NULL;
        for (size_t i = 0; i < queue_size(pvs->ranges); ++i) {
          r = queue_peek(pvs->ranges, i);
          if (r->address == msg.arg.pagefault.address)
            break;
          r = NULL;
        }

        if (!r) {
          printf("Couldn't find valid range!\n");
          abort();
        }

        for (size_t i = 0; i < 0x1000; i += NUM_BOTTOM) {
          uint64_t hash =
              fasthash64((uint8_t *)(r->address + i), NUM_BOTTOM, 0);
          PVectorLeaf *v = ht_get(ht, hash);
          // Move any leaves out of the way so they don't get clobbered by
          // writes to this page
          if ((r->address <= (uint64_t)UNTAG(v->bytes)) &&
              ((uint64_t)UNTAG(v->bytes) < r->address + 0x1000)) {
            uint8_t *back = calloc(NUM_BOTTOM, sizeof(uint8_t));
            printf("Moving backing memory for %.16lx from %p to %p\n", v->hash,
                   UNTAG(v->bytes), back);
            memcpy(back, UNTAG(v->bytes), NUM_BOTTOM);
            v->bytes = TAG(back);
          }
        }

        printf("Marked %p as dirty\n", (void *)r->address);
        r->dirty = 1;

        if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp))
          xperror("ioctl(uffd, UFFDIO_WRITEPROTECT)");
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
  assert((NUM_BITS - BOTTOM_BITS) % BITS_PER_LEVEL == 0);

  uffd = syscall(SYS_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
  if (uffd < 0)
    xperror("userfaultfd");

  struct uffdio_api uffd_api = {};
  uffd_api.api = UFFD_API;
  uffd_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;

  if (ioctl(uffd, UFFDIO_API, &uffd_api))
    xperror("ioctl");

  PVectorState *pvs = calloc(1, sizeof(PVectorState));
  pvs->q = queue_create();
  // TODO: Replace with appropriate datastructure (hash table?)
  pvs->ranges = queue_create();
  if (clone(uffd_monitor, malloc(STACK_SIZE) + STACK_SIZE, CLONE_VM, pvs) == -1)
    xperror("clone");

  // create null node
  PVector *v = calloc(1, MAX(sizeof(PVector), sizeof(PVectorLeaf)));
  v->hash = 0UL;

  queue_push(pvs->q, v);

  ht = ht_create();
  ht_insert(ht, 0UL, v);
  return pvs;
}

uint8_t pbvt_get_head(PVectorState *pvs, uint64_t key) {
  return pvector_get(queue_front(pvs->q), key);
}

void pbvt_update_head(PVectorState *pvs, uint64_t key, uint8_t val) {
  queue_push(pvs->q, pvector_update(queue_front(pvs->q), key, val));
}

void pbvt_cleanup(PVectorState *pvs) {
  while (queue_size(pvs->q) > 0)
    pvector_gc(queue_popleft(pvs->q), MAX_DEPTH - 1);
  queue_free(pvs->q);
  while (queue_size(pvs->ranges) > 0)
    free(queue_popleft(pvs->ranges));
  queue_free(pvs->ranges);
  free(UNTAG(((PVectorLeaf *)ht_get(ht, 0UL))->bytes));
  free(ht_get(ht, 0UL));
  ht_free(ht);
  free(pvs);
}

void pbvt_gc_n(PVectorState *pvs, size_t n) {
  for (size_t i = 0; i < n; ++i)
    pvector_gc(queue_popleft(pvs->q), MAX_DEPTH - 1);
}

size_t pbvt_size(PVectorState *pvs) { return queue_size(pvs->q); }

void pbvt_print(PVectorState *pvs, char *path) {
  HashTable *pr = ht_create();
  FILE *f = fopen(path, "w");
  if (f == NULL)
    return;
  fprintf(f, "digraph {\n");
  fprintf(f, "\tnode[shape=record];\n");

  fprintf(f, "\ttimeline [\n");
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<timeline>timeline|{");
  for (size_t i = 0, n = queue_size(pvs->q); i < n; ++i) {
    fprintf(f, "<%ld>%.16lx", i, ((PVector *)queue_peek(pvs->q, i))->hash);
    if (i != n - 1)
      fprintf(f, "|");
  }
  fprintf(f, "}}");
  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  for (size_t i = 0, n = queue_size(pvs->q); i < n; ++i) {
    fprintf(f, "\ttimeline:%ld -> v%.16lx;\n", i,
            ((PVector *)queue_peek(pvs->q, i))->hash);
  }

  for (size_t i = 0, n = queue_size(pvs->q); i < n; ++i)
    pbvt_print_node(f, pr, (PVector *)queue_peek(pvs->q, i), MAX_DEPTH - 1);

  fprintf(f, "}\n");
  fclose(f);
  ht_free(pr);
}

void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level) {
  if (ht_get(pr, v->hash))
    return;
  ht_insert(pr, v->hash, v);

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
    }
  } else {
    PVectorLeaf *l = (PVectorLeaf *)v;
    fprintf(f, "{<head>%.16lx (%ld refs) %p|{", v->hash, v->refcount, l->bytes);
    for (size_t i = 0; i < NUM_BOTTOM; ++i) {
      fprintf(f, "<%ld>%.2x", i, UNTAG((l->bytes))[i]);
      if (i != NUM_BOTTOM - 1)
        fprintf(f, "|");
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
  printf("Tracked states: %ld\n", queue_size(pvs->q));
  printf("Number of nodes: %ld\n", ht_size(ht));
  printf("Theoretical max: 0x%lx\n", MAX_INDEX);
  printf("Sparsity: %f%%\n",
         100.0 * (float)ht_size(ht) / (float)(queue_size(pvs->q) * MAX_INDEX));
  // malloc_stats();

  // check hash
  for (size_t i = 0; i < ht->cap; ++i) {
    HashBucket *hb = &ht->buckets[i];
    for (size_t j = 0; j < hb->size; ++j) {
      HashEntry *he = &hb->entries[j];
      PVector *v = he->value;

      // incorrect hash for our null node
      if (v->hash == 0UL)
        continue;

      // assert(fasthash64(v->bytes, sizeof(v->bytes), 0) == v->hash);
    }
  }

  PVectorLeaf *pv = NULL;
  uint64_t refs = 0;

  for (size_t i = 0; i < ht->cap; ++i) {
    HashBucket *hb = &ht->buckets[i];
    for (size_t j = 0; j < hb->size; ++j) {
      HashEntry *he = &hb->entries[j];
      PVector *v = he->value;
      if (v->hash == 0UL)
        continue;
      if (v->level == 0 && v->refcount > refs) {
        pv = (PVectorLeaf *)v;
        refs = pv->refcount;
      }
    }
  }

  char chars[0x100][0x3];
  for (uint32_t i = 0; i < sizeof(chars) / sizeof(chars[0]); ++i) {
    chars[i][0] = i;
    chars[i][1] = '\0';
  }

  chars['\n'][0] = '\\';
  chars['\n'][1] = 'n';
  chars['\n'][2] = '\0';

  chars['\0'][0] = '\\';
  chars['\0'][1] = '0';
  chars['\0'][2] = '\0';

  printf("node %.16lx (level: %ld) with %ld refs:\n", pv->hash, pv->level,
         pv->refcount);

  for (int i = 0, n = NUM_BOTTOM; i < n; ++i)
    printf("%.2x ", UNTAG(pv->bytes)[i]);
  printf("\n");

  //   printf("\"");
  //   for (int i = 0, n = NUM_BOTTOM; i < n; ++i)
  //     printf("%s", chars[pv->bytes[i]]);
  //   printf("\"\n");
}

uint64_t pbvt_capacity(void) { return MAX_INDEX; }

void pbvt_add_range(PVectorState *pvs, void *range, size_t n) {
  // TODO: Zero-pad, handle this correctly
  assert((uint64_t)range % sysconf(_SC_PAGESIZE) == 0);
  assert(n % NUM_BOTTOM == 0);
  assert(n % sysconf(_SC_PAGESIZE) == 0);

  queue_push(pvs->q,
             pvector_update_n(queue_front(pvs->q), (uint64_t)range, range, n));

  PVectorLeaf *v;
  for (size_t i = 0; i < n; i += NUM_BOTTOM) {
    v = ht_get(ht, fasthash64(range + i, NUM_BOTTOM, 0));
    // Is this region in our malloc'd region, or backed by the memory it
    // represents? If not, we can make it so and save some space
    if (!TAGGED(v->bytes))
      continue;
    printf("Changing backing memory for %.16lx to %p (was %p)\n", v->hash,
           range + i, UNTAG(v->bytes));
    free(UNTAG(v->bytes));
    v->bytes = range + i;
  }

  printf("Adding range %p-%p\n", range, range + n);

  struct uffdio_register uffd_register = {};
  uffd_register.range.start = (__u64)range;
  uffd_register.range.len = n;
  uffd_register.mode = UFFDIO_REGISTER_MODE_WP;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffd_register))
    xperror("ioctl(uffd, UFFDIO_REGISTER)");

  struct uffdio_writeprotect wp = {};
  wp.range.start = (__u64)range;
  wp.range.len = n;
  wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
  if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp))
    xperror("ioctl(uffd, UFFDIO_WRITEPROTECT)");

  for (size_t i = 0; i < n; i += 0x1000) {
    Range *r = calloc(1, sizeof(Range));
    r->address = (uint64_t)range + i;
    r->len = 0x1000;
    r->dirty = 0;
    queue_push(pvs->ranges, r);
  }
}

// Similar logic to pvector_update_n
void pbvt_snapshot(PVectorState *pvs) {
  struct uffdio_writeprotect wp;
  Range *r;

  PVector *c = queue_front(pvs->q);
  PVector *t;
  c->refcount++;

  for (size_t i = 0; i < queue_size(pvs->ranges); ++i) {
    r = queue_peek(pvs->ranges, i);
    if (!r->dirty)
      continue;

    printf("Saving state for %p...\n", (void *)r->address);
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
      printf(
          "Changing backing memory for %.16lx to %p (was %p) (mem: %.16lx)\n",
          v->hash, (uint8_t *)r->address + i, UNTAG(v->bytes),
          fasthash64((uint8_t *)r->address + i, NUM_BOTTOM, 0));
      free(UNTAG(v->bytes));
      v->bytes = (uint8_t *)r->address + i;
    }

    wp.range.start = r->address;
    wp.range.len = r->len;
    wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
    if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp))
      xperror("ioctl(uffd, UFFDIO_WRITEPROTECT)");
    r->dirty = 0;
  }

  queue_push(pvs->q, c);
}
