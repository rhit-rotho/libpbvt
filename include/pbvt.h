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
  char *name;
  PVector *current;
  Commit *parent;
} Commit;

typedef struct PVectorState {
  Commit *head;
  // Queue *heads;
  HashTable *states;
  Queue *ranges;
} PVectorState;

// public operations
PVectorState *pbvt_init(void);
void pbvt_cleanup(PVectorState *pvs);
void pbvt_gc_n(PVectorState *pvs, size_t n);
size_t pbvt_size(PVectorState *pvs);

void pbvt_print(PVectorState *pvs, char *path);
void pbvt_track_range(PVectorState *pvs, void *range, size_t n);

void pbvt_checkout_n(PVectorState *pvs, size_t depth);
Commit *pbvt_commit(PVectorState *pvs, char *name);
void pbvt_checkout(PVectorState *pvs, Commit *commit);
Commit *pbvt_commit_by_name(PVectorState *pvs, char *name);
Commit *pbvt_commit_parent(PVectorState *pvs, char *name);

// private operations
void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level);
void pbvt_stats(PVectorState *pvs);
void pbvt_debug(void);
uint64_t pbvt_capacity(void);

Commit *pbvt_commit_create(PVector *v, Commit *p, char *name);
void pbvt_commit_free(Commit *c);

void pbvt_write_protect(Range *r, uint8_t);
void pbvt_write_protect_internal(int uffd, Range *r, uint8_t dirty) ;