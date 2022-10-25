#include <stdio.h>

#include "hashtable.h"
#include "pvector.h"
#include "queue.h"

HashTable *ht;

typedef struct Range {
  uint64_t address;
  size_t len;
  uint8_t perms;
  uint8_t dirty;
} Range;

typedef struct PVectorState {
  Queue *q;
  Queue *ranges;
} PVectorState;

// public operations
PVectorState *pbvt_init(void);
uint8_t pbvt_get_head(PVectorState *pvs, uint64_t key);
void pbvt_update_head(PVectorState *pvs, uint64_t key, uint8_t val);
void pbvt_cleanup(PVectorState *pvs);
void pbvt_gc_n(PVectorState *pvs, size_t n);
size_t pbvt_size(PVectorState *pvs);
void pbvt_print(PVectorState *pvs, char *path);
void pbvt_add_range(PVectorState *pvs, void *range, size_t n);
void pbvt_snapshot(PVectorState *pvs);

// private operations
void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level);
void pbvt_stats(PVectorState *pvs);
void pbvt_debug(void);
uint64_t pbvt_capacity(void);