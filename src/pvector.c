#include <assert.h>
#include <string.h>

#include "fasthash.h"
#include "hashtable.h"
#include "memory.h"
#include "pvector.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

HashTable *ht;

int is_bit_set(uint64_t *bitmap, int index) {
  int array_index = index / 64;
  int bit_index = index % 64;
  return (bitmap[array_index] & (1ULL << bit_index)) != 0;
}

void set_bit(uint64_t *bitmap, int index) {
  int array_index = index / 64;
  int bit_index = index % 64;
  bitmap[array_index] |= (1ULL << bit_index);
}

void clear_bit(uint64_t *bitmap, int index) {
  int array_index = index / 64;
  int bit_index = index % 64;
  bitmap[array_index] &= ~(1ULL << bit_index);
}

size_t count_set_bits(uint64_t *bitmap, size_t index) {
  size_t count = 0;
  for (size_t i = 0; i <= index; i++)
    if (is_bit_set(bitmap, i))
      count++;
  return count;
}

// Access a child using the sparse index
uint64_t get_child(PVector *v, int index) {
  // assert(v);
  // return v->children[index];

  if (!is_bit_set(v->bitmap, index))
    return 0UL;
  int compact_index = count_set_bits(v->bitmap, index) - 1;
  return v->children[compact_index];
}

// Set a child using the sparse index
void set_child(PVector *v, int index, uint64_t value) {
  if (!is_bit_set(v->bitmap, index) && value != 0) {
    // A new child is being added, resize the children array and update the
    // bitmap
    int compact_index = count_set_bits(v->bitmap, index);
    v->children = memory_realloc(
        NULL, v->children,
        (count_set_bits(v->bitmap, NUM_CHILDREN - 1) + 1) * sizeof(uint64_t));
    memmove(&v->children[compact_index + 1], &v->children[compact_index],
            (count_set_bits(v->bitmap, NUM_CHILDREN - 1) - compact_index) *
                sizeof(uint64_t));
    v->children[compact_index] = value;
    set_bit(v->bitmap, index);
  // } else if (is_bit_set(v->bitmap, index) && value == 0) {
  //   // A child is being removed, resize the children array and update the bitmap
  //   int compact_index = count_set_bits(v->bitmap, index) - 1;
  //   memmove(&v->children[compact_index], &v->children[compact_index + 1],
  //           (count_set_bits(v->bitmap, NUM_CHILDREN - 1) - compact_index - 1) *
  //               sizeof(uint64_t));
  //   v->children = memory_realloc(
  //       NULL, v->children,
  //       (count_set_bits(v->bitmap, NUM_CHILDREN - 1) - 1) * sizeof(uint64_t));
  //   clear_bit(v->bitmap, index);
  } else if (is_bit_set(v->bitmap, index)) {
    // Update the existing child
    int compact_index = count_set_bits(v->bitmap, index) - 1;
    v->children[compact_index] = value;
  }
}

// Fully expand and hash node
uint64_t pvector_hash(PVector *v) {
  uint64_t children[NUM_CHILDREN];
  for (size_t i = 0; i < NUM_CHILDREN; ++i)
    children[i] = get_child(v, i);
  return fasthash64(children, NUM_CHILDREN * sizeof(uint64_t), 0);
}

PVector *pvector_clone(PVector *v) {
  PVector *u = memory_calloc(NULL, 1, sizeof(PVector));
  u->hash = v->hash;
  set_bit(u->bitmap, 0);
  u->children = memory_calloc(NULL, 1, sizeof(uint64_t));
  for (size_t i = 0; i < NUM_CHILDREN; ++i)
    set_child(u, i, get_child(v, i));
  printf("Set bits: %.16lx\n", count_set_bits(u->bitmap, NUM_CHILDREN-1));
  return u;
}

// This is (purposely) similar to a page-walk, except instead of 12-bit page
// tables, we have BITS_PER_LEVEL-bits
uint8_t pvector_get(PVector *t, uint64_t idx) {
  uint64_t key;

  PVector *v = t;

  uint64_t idxn = idx >> BOTTOM_BITS;
  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idxn >> (i - 1) * BITS_PER_LEVEL) & CHILD_MASK;
    if (get_child(v, key) == 0UL)
      return 0; // Assume memory is 0-initialized
    v = ht_get(ht, get_child(v, key));
  }
  return UNTAG((((PVectorLeaf *)v)->bytes))[idx & BOTTOM_MASK];
}

PVectorLeaf *pvector_get_leaf(PVector *v, uint64_t idx) {
  uint64_t key;

  uint64_t idxn = idx >> BOTTOM_BITS;
  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idxn >> (i - 1) * BITS_PER_LEVEL) & CHILD_MASK;
    if (get_child(v, key) == 0UL)
      return 0; // Assume memory is 0-initialized
    v = ht_get(ht, get_child(v, key));
  }
  return (PVectorLeaf *)v;
}

PVector *pvector_update_n_helper(PVector *v, uint64_t depth, uint64_t idx,
                                 uint8_t *buf, size_t n) {
  if (depth == 0) {
    uint64_t hash = fasthash64(buf, NUM_BOTTOM, 0);
    PVectorLeaf *l = (PVectorLeaf *)v;
    if (ht_get(ht, hash) != NULL)
      return (PVector *)ht_get(ht, hash);

    l = memory_calloc(NULL, 1, sizeof(PVectorLeaf));
    l->bytes = memory_calloc(NULL, NUM_BOTTOM, sizeof(uint8_t));
    memcpy(l->bytes, buf, n);
    l->bytes = TAG(l->bytes);
    l->hash = hash;
    ht_insert(ht, l->hash, l);
    return (PVector *)l;
  }

  uint64_t k;
  uint64_t tn;

  tn = NUM_BOTTOM;
  for (uint64_t i = 0; i < depth - 1; ++i)
    tn *= NUM_CHILDREN;
  k = (idx >> ((depth - 1) * BITS_PER_LEVEL + BOTTOM_BITS)) & CHILD_MASK;
  uint64_t mk =
      ((idx + n - 1) >> ((depth - 1) * BITS_PER_LEVEL + BOTTOM_BITS)) &
      CHILD_MASK;

  // Do we have an exclusive copy?
  int cloned = 0;

  uint64_t align = ((idx + tn) & ~(tn - 1)) - idx;
  uint64_t inc = tn;
  if (align > 0)
    inc = align;

  for (uint64_t i = 0; k < mk + 1; k += 1) {
    assert(k < NUM_CHILDREN);
    PVector *u = ht_get(ht, get_child(v, k));
    u = pvector_update_n_helper(u, depth - 1, idx + i, buf + i,
                                MIN(inc, n - i));

    if (get_child(v, k) != u->hash) {
      if (!cloned) {
        v = pvector_clone(v);
        cloned = 1;
      }
      set_child(v, k, u->hash);
    }

    i += inc;
    inc = tn;
  }

  if (cloned) {
    v->hash = pvector_hash(v);
    if (ht_get(ht, v->hash) == NULL) {
      ht_insert(ht, v->hash, v);

      for (uint64_t m = 0; m < NUM_CHILDREN; ++m)
        ((PVector *)ht_get(ht, get_child(v, m)))->refcount++;
    }
  }
  return v;
}

PVector *pvector_update_n(PVector *v, uint64_t idx, uint8_t *buf, size_t n) {
  assert(idx + n <= MAX_INDEX);

  // TODO: Can make these unnecessary
  assert(idx % NUM_BOTTOM == 0);
  assert(n % NUM_BOTTOM == 0);

  v = pvector_update_n_helper(v, MAX_DEPTH - 1, idx, buf, n);
  v->refcount++;
  return v;
}

PVector *pvector_update(PVector *v, uint64_t idx, uint8_t val) {
  assert(idx <= MAX_INDEX);

  return pvector_update_n(v, idx, &val, 1);
}

// Decrement reference count starting at root, free any nodes whose reference
// count drops to 0. With a custom memory allocator, this can be the expensive
// bit, may also consider changing the API to pvector_gc(PVector**vs, size_t
// n), since we can coalesce compaction.
void pvector_gc(PVector *v, uint64_t level) {
  if (v->hash == 0) // don't free NULL node
    return;

  v->refcount--;
  if (v->refcount == 0 && level > 0) {
    for (size_t i = 0; i < NUM_CHILDREN; ++i)
      if (get_child(v, i))
        pvector_gc(ht_get(ht, get_child(v, i)), level - 1);
  }
  if (v->refcount == 0) {
    ht_remove(ht, v->hash);
    if (level == 0 && TAGGED(((PVectorLeaf *)v)->bytes))
      memory_free(NULL, UNTAG(((PVectorLeaf *)v)->bytes));
    memory_free(NULL, v);
  }
}
