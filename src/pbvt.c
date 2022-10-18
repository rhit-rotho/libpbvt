#include "pbvt.h"
#include "fasthash.h"
#include "hashtable.h"

#define likely(x) (__builtin_expect((x), 1))
#define unlikely(x) (__builtin_expect((x), 0))

// TODO: For a multi-threaded implementation a global counter is killer,
// consider indexing nodes by contents (e.g. xxHash) rather than by the order
// in which they were created. This also simplifies memory allocation, which can
// be O(1) with a hash table.

HashTable *ht = NULL;
uint64_t idx = 0;
PVector *pbvt_create() {
  PVector *v = calloc(sizeof(PVector), 1);
  v->idx = idx++;
  v->refcount = 0;
  if (unlikely(!ht)) {
    ht = ht_create();
    ht_insert(ht, 0UL, v);
  }
  return v;
}
// We can do this without cloning all the child nodes because our tree is
// persistent; all operations on the data structure will clone any children as
// necessary, so we can be lazy here.
PVector *pbvt_clone(PVector *v, uint64_t level) {
  PVector *u = pbvt_create();
  for (int i = 0; i < NUM_CHILDREN; ++i) {
    u->children[i] = v->children[i];
    if (level > 0 && v->children[i]) {
      PVector *c = ht_get(ht, v->children[i]);
      c->refcount++;
    }
  }
  return u;
}

// This is (purposely) similar to a page-walk, except instead of 12-bit page
// tables, we have BITS_PER_LEVEL-bits
uint8_t pbvt_get(PVector *v, uint64_t idx) {
  uint64_t key;

  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idx >> (i * BITS_PER_LEVEL + 3)) & CHILD_MASK;
    if (!v->children[key])
      return -1;
    v = ht_get(ht, v->children[key]);
  }
  key = idx & BOTTOM_MASK;
  return v->bytes[key];
}

PVector *pbvt_update(PVector *v, uint64_t idx, uint8_t val) {
  PVector *path[MAX_DEPTH] = {0};
  uint64_t key;
  uint64_t hash;

  PVector *orig = v;

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
    v = pbvt_clone(v, 0);
    v->bytes[idx & BOTTOM_MASK] = val;
    v->hash = hash;
    ht_insert(ht, hash, v);
  }
  path[0] = v;

  // Propogate hashes back up the tree
  for (int i = 1; i < MAX_DEPTH; ++i) {
    v = path[i];
    key = (idx >> (i * BITS_PER_LEVEL + 3)) & CHILD_MASK;
    memcpy(content, v->children, sizeof(content));
    ((uint64_t *)content)[key] = path[i - 1]->hash;
    hash = fasthash64(content, sizeof(content), 0);
    if (ht_get(ht, hash)) {
      v = ht_get(ht, hash);
    } else {
      v = pbvt_clone(v, i);

      ((PVector *)ht_get(ht, v->children[key]))->refcount--;
      path[i - 1]->refcount++;

      v->children[key] = path[i - 1]->hash;
      v->hash = hash;
      ht_insert(ht, hash, v);
    }
    path[i] = v;
  }

  path[MAX_DEPTH - 1]->refcount++;
  return path[MAX_DEPTH - 1];
}

// Decrement reference count starting at root, free any nodes whose reference
// count drops to 0. With a custom memory allocator, this can be the expensive
// bit, may also consider changing the API to pbvt_gc(PVector**vs, size_t n),
// since we can coalesce compaction.
void pbvt_gc(PVector *v, uint64_t level) {
  if (v->hash == 0)
    return;

  v->refcount--;
  if (v->refcount == 0 && level > 0) {
    for (int i = 0; i < NUM_CHILDREN; ++i)
      if (v->children[i])
        pbvt_gc(ht_get(ht, v->children[i]), level - 1);
  }
  if (v->refcount == 0) {
    ht_remove(ht, v->hash);
    free(v);
  }
}

// FIXME: This is a bit silly, we could do better (probabilistically) with a
// bloom filter, or by actually using bitmap operations
uint8_t *dirty;
void pbvt_print(char *name, PVector **vs, size_t n) {
  dirty = calloc(idx * sizeof(uint8_t), 1);
  FILE *f = fopen(name, "w");
  if (f == NULL)
    return;
  fprintf(f, "digraph {\n");
  fprintf(f, "\tnode[shape=record];\n");

  fprintf(f, "\ttimeline [\n");
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<timeline>timeline|{");
  for (size_t i = 0; i < n; ++i) {
    fprintf(f, "<%ld>%p", i, vs[i]);
    if (i != n - 1)
      fprintf(f, "|");
  }
  fprintf(f, "}}");
  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  for (size_t i = 0; i < n; ++i) {
    fprintf(f, "\ttimeline:%ld -> v%ld;\n", i, vs[i]->idx);
  }

  for (size_t i = 0; i < n; ++i)
    pbvt_print_node(f, vs[i], MAX_DEPTH - 1);

  fprintf(f, "}\n");
  fclose(f);
  free(dirty);
}

void pbvt_print_node(FILE *f, PVector *v, int level) {
  int is_dirty = dirty[v->idx];
  if (is_dirty)
    return;
  dirty[v->idx] = 1;

  fprintf(f, "\tv%ld [\n", v->idx);
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<head>%ld (%ld refs) h: %.16lx|{", v->idx, v->refcount, v->hash);
  if (level > 0) {
    for (int i = 0; i < NUM_CHILDREN; ++i) {
      if (v->children[i])
        fprintf(f, "<%d>%p", i, (PVector *)ht_get(ht, v->children[i]));
      else
        fprintf(f, "<%d>x", i);
      if (i != NUM_CHILDREN - 1)
        fprintf(f, "|");
    }
  } else {
    for (int i = 0; i < 8 * NUM_CHILDREN; ++i) {
      fprintf(f, "<%d>%.2x", i, v->bytes[i]);
      if (i != 8 * NUM_CHILDREN - 1)
        fprintf(f, "|");
    }
  }
  fprintf(f, "}}");

  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  if (level == 0)
    return;

  for (int i = 0; i < NUM_CHILDREN; ++i) {
    if (v->children[i]) {
      fprintf(f, "\tv%ld:%d -> v%ld;\n", v->idx, i,
              ((PVector *)ht_get(ht, v->children[i]))->idx);
      pbvt_print_node(f, ht_get(ht, v->children[i]), level - 1);
    }
  }
}