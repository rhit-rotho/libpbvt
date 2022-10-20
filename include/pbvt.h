#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TODO: We don't need all of malloc's functionality, a bump allocator would
// probably work just fine (this may or may not be necessary for performance).
// Additionally, pointers would no longer need to be 64-bit, since we could just
// use indices into buckets/arenas or a hash of the nodes contents

// These are precalculated, we need an extra 3 bits for the lowest level so we
// don't waste space when storing individual bytes
#define BITS_PER_LEVEL (1)
#define NUM_CHILDREN (1 << BITS_PER_LEVEL)
#define CHILD_MASK ((1 << BITS_PER_LEVEL) - 1)
// For 4-level paging (see "Paging" in Volume 3 of the Intel 64 and IA-32
// Architectures Software Developer's manual)
// #define MAX_DEPTH ((49 - (BITS_PER_LEVEL + 3)) / BITS_PER_LEVEL)
#define MAX_DEPTH ((9 - (BITS_PER_LEVEL + 3)) / BITS_PER_LEVEL)
// #define MAX_DEPTH ((24 - (BITS_PER_LEVEL + 3)) / BITS_PER_LEVEL)
#define BOTTOM_BITS (BITS_PER_LEVEL + 3)
#define BOTTOM_MASK ((1 << BOTTOM_BITS) - 1)

typedef struct PVector PVector;

typedef struct PVector {
  uint64_t refcount;
  uint64_t hash;
  union {
    uint64_t children[NUM_CHILDREN];
    uint8_t bytes[NUM_CHILDREN * sizeof(PVector *)];
  };
} PVector;

// public methods
PVector *pbvt_create(void);
uint8_t pbvt_get(PVector *v, uint64_t idx);
PVector *pbvt_update(PVector *v, uint64_t idx, uint8_t val);
void pbvt_print(char *name, PVector **vs, size_t n);

// private methods
PVector *pbvt_clone(PVector *v, uint64_t level);
void pbvt_gc(PVector *v, uint64_t level);
void pbvt_print_node(FILE *f, PVector *v, int level);
