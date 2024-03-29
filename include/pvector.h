#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// For 4-level paging we need at least 48 bits of key (see "Paging" in Volume 3
// of the Intel 64 and IA-32 Architectures Software Developer's manual)
#define NUM_BITS (45+5)
#define BITS_PER_LEVEL (3)
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

// Make tagged pointers obviously invalid (crash on deref)
#define TAG(x) ((uint8_t *)((uint64_t)(x) | (0xbadUL << 52)))
#define UNTAG(x) ((uint8_t *)((uint64_t)(x) & ~(0xbadUL << 52)))
#define TAGGED(x) ((uint64_t)(x) & (0xbadUL << 52))

typedef struct PVector PVector;

typedef struct PVector {
  uint64_t hash;
  uint64_t refcount;
  uint16_t bitmap[(NUM_CHILDREN + (8 * sizeof(uint16_t)) - 1) /
                  (8 * sizeof(uint16_t))];
  uint64_t *children;
} PVector;

typedef struct PVectorLeaf {
  uint64_t hash;
  uint64_t refcount;
  uint8_t *bytes;
} PVectorLeaf;

// public methods
uint8_t pvector_get(PVector *v, uint64_t idx);
PVector *pvector_update(PVector *v, uint64_t idx, uint8_t val);
void pvector_print(char *name, PVector **vs, size_t n);

// private methods
PVector *pvector_clone(PVector *v);
void pvector_gc(PVector *v, uint64_t level);
PVector *pvector_update_n(PVector *v, uint64_t idx, uint8_t *buf, size_t n);
PVectorLeaf *pvector_get_leaf(PVector *v, uint64_t idx);
uint64_t pvector_hash(PVector *v);

int is_bit_set(uint16_t *bitmap, int index);
void set_bit(uint16_t *bitmap, int index);
void clear_bit(uint16_t *bitmap, int index);

uint64_t get_child(PVector *n, int index);
void set_child(PVector *v, int index, uint64_t value);