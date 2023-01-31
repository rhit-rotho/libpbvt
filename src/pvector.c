#include <assert.h>
#include <string.h>

#include "fasthash.h"
#include "hashtable.h"
#include "memory.h"
#include "pvector.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

HashTable *ht;

PVector *pvector_clone(PVector *v) {
  PVector *u = memory_calloc(NULL, 1, sizeof(PVector));
  u->hash = v->hash;
  for (size_t i = 0; i < NUM_CHILDREN; ++i)
    u->children[i] = v->children[i];
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
    if (v->children[key] == 0UL)
      return 0; // Assume memory is 0-initialized
    v = ht_get(ht, v->children[key]);
  }
  return UNTAG((((PVectorLeaf *)v)->bytes))[idx & BOTTOM_MASK];
}

PVectorLeaf *pvector_get_leaf(PVector *v, uint64_t idx) {
  uint64_t key;

  uint64_t idxn = idx >> BOTTOM_BITS;
  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idxn >> (i - 1) * BITS_PER_LEVEL) & CHILD_MASK;
    if (v->children[key] == 0UL)
      return 0; // Assume memory is 0-initialized
    v = ht_get(ht, v->children[key]);
  }
  return (PVectorLeaf *)v;
}

// TODO: Incorrect indexing for some values of BOTTOM_BITS and BITS_PER_LEVEL
PVector *pvector_update_n_helper(PVector *v, uint64_t depth, uint64_t idx,
                                 uint8_t *buf, size_t n) {
  if (depth == 0) {
    // printf("d: 0, buf: %p [ ", buf);
    // for (int i = 0; i < 0x40; ++i) {
    //   printf("%.2x ", buf[i]);
    // }
    // printf("]\n");

    uint64_t hash = fasthash64(buf, n, 0);
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

  int cloned = 0; // Do we have an exclusive copy?
  uint64_t rbytes = n;

  // printf("%.16lx: d: %lx k: %lx p: %lx tn: %lx n: %lx (next: %.16lx)\n", idx,
  //        depth, k, CHILD_MASK, tn, n, idx + tn);
  for (uint64_t i = 0; k < NUM_CHILDREN && i < n; i += tn) {
    assert(k < NUM_CHILDREN);
    PVector *u = ht_get(ht, v->children[k]);
    u = pvector_update_n_helper(u, depth - 1, idx + i, buf + i,
                                MIN(tn, rbytes));

    if (v->children[k] != u->hash) {
      if (!cloned) {
        v = pvector_clone(v);
        cloned = 1;
      }
      v->children[k] = u->hash;
    }

    k++;
    rbytes -= tn;
  }

  if (cloned) {
    v->hash = fasthash64(v->children, NUM_CHILDREN * sizeof(uint64_t), 0);
    if (ht_get(ht, v->hash) == NULL) {
      ht_insert(ht, v->hash, v);

      for (uint64_t m = 0; m < NUM_CHILDREN; ++m)
        ((PVector *)ht_get(ht, v->children[m]))->refcount++;
    }
  }
  return v;
}

// TODO: This can be much more optimized
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
      if (v->children[i])
        pvector_gc(ht_get(ht, v->children[i]), level - 1);
  }
  if (v->refcount == 0) {
    ht_remove(ht, v->hash);
    if (level == 0 && TAGGED(((PVectorLeaf *)v)->bytes))
      memory_free(NULL, UNTAG(((PVectorLeaf *)v)->bytes));
    memory_free(NULL, v);
  }
}
