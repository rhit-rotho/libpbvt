#include "pbvt.h"
#include "pvector.h"

PVectorState *pbvt_init(void) {
  ht = ht_create();

  PVectorState *pvs = calloc(sizeof(PVectorState), 1);
  pvs->q = queue_create();

  // create null node
  PVector *v = pvector_create();
  v->hash = 0UL;

  queue_push(pvs->q, v);
  ht_insert(ht, 0UL, v);
  return pvs;
}

uint8_t pbvt_get_latest(PVectorState *pvs, uint64_t key) {
  return pvector_get(queue_front(pvs->q), key);
}

void pbvt_update_latest(PVectorState *pvs, uint64_t key, uint8_t val) {
  queue_push(pvs->q, pvector_update(queue_front(pvs->q), key, val));
}

void pbvt_cleanup(PVectorState *pvs) {
  while (queue_size(pvs->q) > 0)
    pvector_gc(queue_popleft(pvs->q), MAX_DEPTH - 1);
  queue_free(pvs->q);
  ht_free(ht);
  free(pvs);
}

void pbvt_gc_n(PVectorState *pvs, size_t n) {
  for (size_t i = 0; i < n; ++i)
    pvector_gc(queue_popleft(pvs->q), MAX_DEPTH - 1);
}