#include <stdio.h>

#include "hashtable.h"
#include "pvector.h"
#include "queue.h"

HashTable *ht;

typedef struct Range {
  void *address;
  size_t len;
  uint8_t perms;
  uint8_t dirty;
} Range;

typedef struct Commit Commit;
typedef struct Commit {
  uint64_t hash;
  PVector *current;
  Commit *parent;
} Commit;

typedef struct Branch {
  char *name;
  Commit *head;
} Branch;

typedef struct PVectorState {
  Commit *head;
  Branch *branch;
  HashTable *branches;
  HashTable *states;
  Queue *ranges;
} PVectorState;

// public operations
void pbvt_init(void);
void pbvt_cleanup();
void pbvt_gc_n(size_t n);
size_t pbvt_size();

void pbvt_print(char *path);
void pbvt_track_range(void *range, size_t n);

Commit *pbvt_commit();
void pbvt_checkout(Commit *commit);

Commit *pbvt_commit_parent(Commit *commit);
Commit *pbvt_head();

void pbvt_branch_commit(char *name);
void pbvt_branch_checkout(char *name);

uint64_t pbvt_capacity(void);

void *pbvt_calloc(size_t nmemb, size_t size);
void *pbvt_realloc(void *ptr, size_t size);
void *pbvt_malloc(size_t size);
void pbvt_free(void *ptr);

// private operations
void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level);
void pbvt_stats();
void pbvt_debug(void);

Commit *pbvt_commit_create(PVector *v, Commit *p);
void pbvt_commit_free(Commit *c);

void pbvt_write_protect(Range *r, uint8_t);
void pbvt_write_protect_internal(int uffd, Range *r, uint8_t dirty);