#include <stdio.h>

#include "hashtable.h"
#include "pvector.h"
#include "queue.h"

extern HashTable *ht;

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

#define PUBLIC __attribute__((visibility("default")))

// public operations
PUBLIC void pbvt_init(void);
PUBLIC void pbvt_cleanup();
PUBLIC void pbvt_gc_n(size_t n);
PUBLIC size_t pbvt_size();

PUBLIC void pbvt_print(char *path);
PUBLIC void pbvt_track_range(void *range, size_t n);

PUBLIC void pbvt_update_n(uint64_t key, void *buf, size_t len);

PUBLIC Commit *pbvt_commit();
PUBLIC void pbvt_checkout(Commit *commit);

PUBLIC Commit *pbvt_commit_parent(Commit *commit);
PUBLIC Commit *pbvt_head();

PUBLIC void pbvt_branch_commit(char *name);
PUBLIC void pbvt_branch_checkout(char *name);

PUBLIC uint64_t pbvt_capacity(void);

// Persistent heap operations
PUBLIC void *pbvt_calloc(size_t nmemb, size_t size);
PUBLIC void *pbvt_realloc(void *ptr, size_t size);
PUBLIC void *pbvt_malloc(size_t size);
PUBLIC void pbvt_free(void *ptr);

PUBLIC void pbvt_stats();

// private operations
void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level);
void pbvt_debug(void);

Commit *pbvt_commit_create(PVector *v, Commit *p);
void pbvt_commit_free(Commit *c);
void pbvt_branch_free(Branch *b);

void pbvt_write_protect(Range *r, uint8_t);
void pbvt_write_protect_internal(int uffd, Range *r, uint8_t dirty);
Commit *pbvt_commit_internal(int uffd);
