#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// TODO: We don't need all of malloc's functionality, a bump allocator would
// probably work just fine (this may or may not be necessary for performance).

// For 4-level paging (see "Paging" in Volume 3 of the Intel 64 and IA-32
// Architectures Software Developer's manual)
#define NUM_BITS (49)
#define BITS_PER_LEVEL (2)
#define BOTTOM_BITS (5)

// Calculated defines, make sure (NUM_BITS - BOTTOM_BITS) % BITS_PER_LEVEL == 0
#if (NUM_BITS - BOTTOM_BITS) % BITS_PER_LEVEL != 0
#error "Internal nodes require an integer number of bits for partitioning."
#endif

#define NUM_CHILDREN (1UL << BITS_PER_LEVEL)
#define CHILD_MASK ((1UL << BITS_PER_LEVEL) - 1)
#define MAX_INDEX ((1UL << NUM_BITS) - 1)
#define NUM_BOTTOM (1UL << BOTTOM_BITS)
#define BOTTOM_MASK ((1UL << BOTTOM_BITS) - 1)
#define MAX_DEPTH (1 + (NUM_BITS - BOTTOM_BITS) / BITS_PER_LEVEL)

typedef struct PVector PVector;

typedef struct PVector {
  uint64_t refcount;
  uint64_t hash;
#ifndef NDEBUG
  uint64_t level;
#endif
  uint64_t children[NUM_CHILDREN];
} PVector;

typedef struct PVectorLeaf {
  uint64_t refcount;
  uint64_t hash;
#ifndef NDEBUG
  uint64_t level;
#endif
  // uint8_t bytes[1 << BOTTOM_BITS];
  uint8_t *bytes;
} PVectorLeaf;

// public methods
uint8_t pvector_get(PVector *v, uint64_t idx);
PVector *pvector_update(PVector *v, uint64_t idx, uint8_t val);
void pvector_print(char *name, PVector **vs, size_t n);

// private methods
PVector *pvector_clone(PVector *v, uint64_t level);
void pvector_gc(PVector *v, uint64_t level);
