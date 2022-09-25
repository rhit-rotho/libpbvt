#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// TODO: We don't need all of malloc's functionality, a bump allocator would
// probably work just fine (this may or may not be necessary for performance).
// Additionally, pointers would no longer need to be 64-bit, since

#define BITS_PER_LEVEL (2)
#define NUM_CHILDREN (1 << BITS_PER_LEVEL)
#define CHILD_MASK ((1 << BITS_PER_LEVEL) - 1)
#define MAX_DEPTH (8 * sizeof(uintptr_t) / BITS_PER_LEVEL)

typedef struct pvector pvector_t;

typedef struct pvector {
  uint64_t idx;
  pvector_t *children[NUM_CHILDREN];
  // TODO: Replace this with bitmap (8x space decrease)
  uint8_t populated[NUM_CHILDREN];
  uint8_t exclusive; // is there only one reference to this node?
} pvector_t;

pvector_t *pbvt_create(void);
uint64_t pbvt_get(pvector_t *v, uint64_t idx);
pvector_t *pbvt_update(pvector_t *v, uint64_t idx, uint64_t val);

pvector_t *pbvt_clone(pvector_t *v);
pvector_t *pbvt_set_child(pvector_t *v, uint64_t key, pvector_t *u);

void pbvt_print(char *name, pvector_t **vs, size_t n);
void pbvt_print_node(FILE *f, pvector_t *v, int idx, int level);