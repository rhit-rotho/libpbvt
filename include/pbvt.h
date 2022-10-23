#include "queue.h"
#include "hashtable.h"

HashTable *ht;

typedef struct PVectorState {
  Queue *q;
} PVectorState;

PVectorState *pbvt_init(void);
uint8_t pbvt_get_latest(PVectorState *pvs, uint64_t key);
void pbvt_update_latest(PVectorState *pvs, uint64_t key, uint8_t val);
void pbvt_cleanup(PVectorState *pvs);
void pbvt_gc_n(PVectorState *pvs, size_t n);