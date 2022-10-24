#include <assert.h>
#include <string.h>

#include "fasthash.h"
#include "hashtable.h"
#include "pvector.h"

extern HashTable *ht;

// We can do this without cloning all the child nodes because our tree is
// persistent; all operations on the data structure will clone any children as
// necessary, so we can be lazy here.
PVectorLeaf *pvector_clone_leaf(PVectorLeaf *v) {
  PVectorLeaf *u = calloc(1, sizeof(PVectorLeaf));
  u->refcount = 0;
  u->level = 0;
  u->bytes = calloc(NUM_BOTTOM, sizeof(uint8_t));
  if (v->bytes)
    memcpy(u->bytes, v->bytes, NUM_BOTTOM);
  return u;
}

PVector *pvector_clone(PVector *v, uint64_t level) {
  PVector *u = calloc(1, sizeof(PVector));
  u->refcount = 0;
#ifndef NDEBUG
  u->level = level;
#endif
  for (size_t i = 0; i < NUM_CHILDREN; ++i) {
    u->children[i] = v->children[i];
    if (u->children[i]) {
      PVector *c = ht_get(ht, u->children[i]);
      c->refcount++;
    }
  }
  return u;
}

// This is (purposely) similar to a page-walk, except instead of 12-bit page
// tables, we have BITS_PER_LEVEL-bits
uint8_t pvector_get(PVector *v, uint64_t idx) {
  uint64_t key;

  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idx >> ((i - 1) * BITS_PER_LEVEL + BOTTOM_BITS)) & CHILD_MASK;
    if (!v->children[key])
      return 0; // Assume memory is 0-initialized
    v = ht_get(ht, v->children[key]);
  }
  return ((PVectorLeaf *)v)->bytes[idx & BOTTOM_MASK];
}

PVector *pvector_update(PVector *v, uint64_t idx, uint8_t val) {
  assert(idx <= MAX_INDEX);

  PVector *path[MAX_DEPTH] = {0};
  uint64_t key;
  uint64_t hash;

  // build path down into tree
  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    path[i] = v;
    key = (idx >> ((i - 1) * BITS_PER_LEVEL + BOTTOM_BITS)) & CHILD_MASK;
    v = ht_get(ht, v->children[key]);
  }

  uint8_t bytes[NUM_BOTTOM] = {0};
  if (((PVectorLeaf *)v)->bytes)
    memcpy(bytes, ((PVectorLeaf *)v)->bytes, sizeof(bytes));
  bytes[idx & BOTTOM_MASK] = val;
  hash = fasthash64(bytes, sizeof(bytes), 0);

  if (ht_get(ht, hash)) {
    v = ht_get(ht, hash);
  } else {
    v = (PVector *)pvector_clone_leaf((PVectorLeaf *)v);
    ((PVectorLeaf *)v)->bytes[idx & BOTTOM_MASK] = val;
    v->hash = hash;
    ht_insert(ht, hash, v);
  }
  PVector *prev = v;

  // Propogate hashes back up the tree
  uint64_t children[NUM_CHILDREN];
  for (int i = 1; i < MAX_DEPTH; ++i) {
    v = path[i];
    key = (idx >> ((i - 1) * BITS_PER_LEVEL + BOTTOM_BITS)) & CHILD_MASK;

    memcpy(children, v->children, sizeof(children));
    children[key] = prev->hash;
    hash = fasthash64(children, sizeof(children), 0);

    // We split this up from the dirty check, since the node we would've
    // created with may already exist
    if (ht_get(ht, hash)) {
      v = ht_get(ht, hash);
    } else {
      v = pvector_clone(v, i);
      ((PVector *)ht_get(ht, v->children[key]))->refcount--;
      prev->refcount++;
      v->children[key] = prev->hash;
      v->hash = hash;
      ht_insert(ht, hash, v);
    }
    prev = v;
  }

  // We always do this since our caller now has a reference to the new root
  // node
  v->refcount++;
  return v;
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
    if (level == 0)
      free(((PVectorLeaf *)v)->bytes);
    free(v);
  }
}
