#include <stdio.h>

#include "hashtable.h"
#include "pvector.h"
#include "queue.h"

HashTable *ht;

typedef struct PVectorState {
  Queue *q;
} PVectorState;

// public operations
PVectorState *pbvt_init(void);
uint8_t pbvt_get_latest(PVectorState *pvs, uint64_t key);
void pbvt_update_latest(PVectorState *pvs, uint64_t key, uint8_t val);
void pbvt_cleanup(PVectorState *pvs);
void pbvt_gc_n(PVectorState *pvs, size_t n);
size_t pbvt_size(PVectorState *pvs);
void pbvt_print(PVectorState *pvs, char *path);

// private operations
void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level);
void pbvt_stats(PVectorState *pvs);