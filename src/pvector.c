#include <assert.h>
#include <string.h>

#include "fasthash.h"
#include "hashtable.h"
#include "pvector.h"

extern HashTable *ht;

// We can do this without cloning all the child nodes because our tree is
// persistent; all operations on the data structure will clone any children as
// necessary, so we can be lazy here.
PVector *pvector_clone(PVector *v, uint64_t level) {
  PVector *u = calloc(1, sizeof(PVector));
  u->refcount = 0;
#ifndef NDEBUG
  u->level = level;
#endif
  for (int i = 0; i < NUM_CHILDREN; ++i) {
    u->children[i] = v->children[i];
    if (level > 0 && u->children[i]) {
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
    key = (idx >> (i * BITS_PER_LEVEL + 3)) & CHILD_MASK;
    if (!v->children[key])
      return 0; // Assume memory is 0-initialized
    v = ht_get(ht, v->children[key]);
  }
  return v->bytes[idx & BOTTOM_MASK];
}

PVector *pvector_update(PVector *v, uint64_t idx, uint8_t val) {
  assert(idx < 1UL << NUM_BITS);

  PVector *path[MAX_DEPTH] = {0};
  uint64_t key;
  uint64_t hash;

  // build path down into tree
  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    path[i] = v;
    key = (idx >> (i * BITS_PER_LEVEL + 3)) & CHILD_MASK;
    v = ht_get(ht, v->children[key]);
  }

  uint8_t content[sizeof(v->bytes)];
  memcpy(content, v->bytes, sizeof(content));
  content[idx & BOTTOM_MASK] = val;
  hash = fasthash64(content, sizeof(content), 0);
  if (ht_get(ht, hash)) {
    v = ht_get(ht, hash);
  } else {
    v = pvector_clone(v, 0);
    v->bytes[idx & BOTTOM_MASK] = val;
    v->hash = hash;
    ht_insert(ht, hash, v);
  }
  PVector *prev = v;

  // Propogate hashes back up the tree
  for (int i = 1; i < MAX_DEPTH; ++i) {
    v = path[i];
    key = (idx >> (i * BITS_PER_LEVEL + 3)) & CHILD_MASK;

    memcpy(content, v->children, sizeof(content));
    ((uint64_t *)content)[key] = prev->hash;
    hash = fasthash64(content, sizeof(content), 0);

    // We split this up from the dirty check, since the node we would've created
    // with may already exist
    if (ht_get(ht, hash)) {
      v = ht_get(ht, hash);
    } else {
      v = pvector_clone(v, i);
      PVector *c = ht_get(ht, v->children[key]);
      c->refcount--;
      v->children[key] = prev->hash;
      prev->refcount++;
      v->hash = hash;
      ht_insert(ht, hash, v);
    }
    prev = v;
  }

  // We always do this since our caller now has a reference to the new root node
  v->refcount++;
  return v;
}

// Decrement reference count starting at root, free any nodes whose reference
// count drops to 0. With a custom memory allocator, this can be the expensive
// bit, may also consider changing the API to pvector_gc(PVector**vs, size_t n),
// since we can coalesce compaction.
void pvector_gc(PVector *v, uint64_t level) {
  if (v->hash == 0) // don't free NULL node
    return;

  v->refcount--;
  if (v->refcount == 0 && level > 0) {
    for (int i = 0; i < NUM_CHILDREN; ++i)
      if (v->children[i])
        pvector_gc(ht_get(ht, v->children[i]), level - 1);
  }
  if (v->refcount == 0) {
    ht_remove(ht, v->hash);
    free(v);
  }
}
