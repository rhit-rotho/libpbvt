#include <stdio.h>

#include "hashtable.h"
#include "pvector.h"
#include "queue.h"

// Commits are abstractly represented as linked list to tuples of program states
// memory = StaticArray<uint8_t, 0, 2**48>;
// pbvt = Array<LinkedList<Memory>>, cur_idx = Integer, 0 <= cur_idx < |pbvt|

extern HashTable *ht;

typedef enum PBVT_HOOK_TYPE {
  PBVT_ON_FAULT,
} PBVT_HOOK_TYPE;

typedef void (*pbvt_hook)(void *, void *);

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

  pbvt_hook on_fault;
  void *on_fault_ctx;
} PVectorState;

#define PUBLIC __attribute__((visibility("default")))

// public operations
PUBLIC void pbvt_init(void);
PUBLIC void pbvt_cleanup();
PUBLIC void pbvt_gc_n(size_t n);
PUBLIC size_t pbvt_size();

PUBLIC void pbvt_print(char *path);
PUBLIC void pbvt_track_range(void *range, size_t n, int perms);

//@ requires buf != null
//@ requires buf + len < |memory|
PUBLIC void pbvt_update_n(uint64_t key, void *buf, size_t len);

//@ requires pbvt != []
//@ ensures dirty_ranges = []
//@ ensures clean_ranges = #clean_ranges || #dirty_ranges
//@ ensures pbvt[cur_idx] = [memory, #pbvt[cur_idx]]
PUBLIC Commit *pbvt_commit();

//@ requires commit != null
//@ requires
PUBLIC void pbvt_checkout(Commit *commit);

PUBLIC Commit *pbvt_commit_parent(Commit *commit);

//@ requires pbvt != []
//@ ensures \result = pbvt[cur_idx][0]->hash
PUBLIC Commit *pbvt_head();

//@ ensures pbvt[|pbvt|] = {#memory}
PUBLIC void pbvt_branch_commit(char *name);
PUBLIC void pbvt_branch_checkout(char *name);

PUBLIC uint64_t pbvt_capacity(void);
PUBLIC int pbvt_install_hook(PBVT_HOOK_TYPE type, pbvt_hook hook, void *ctx);

// Persistent heap operations
PUBLIC void *pbvt_calloc(size_t nmemb, size_t size);
PUBLIC void *pbvt_realloc(void *ptr, size_t size);
PUBLIC void *pbvt_malloc(size_t size);
PUBLIC void pbvt_free(void *ptr);

PUBLIC void pbvt_stats();

// Private operations
void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level);
void pbvt_debug(void);

Commit *pbvt_commit_create(PVector *v, Commit *p);
void pbvt_commit_free(Commit *c);
void pbvt_branch_free(Branch *b);

void pbvt_write_protect(Range *r, uint8_t);
void pbvt_write_protect_internal(int uffd, Range *r, uint8_t dirty);
Commit *pbvt_commit_internal(int uffd);

void pbvt_relocate_away_internal(Range *r);
void pbvt_relocate_into_internal(Range *r, PVector *v);