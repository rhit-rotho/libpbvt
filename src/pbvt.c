#include "pbvt.h"
#include "fasthash.h"
#include "hashtable.h"

#define likely(x) (__builtin_expect((x), 1))
#define unlikely(x) (__builtin_expect((x), 0))

HashTable *ht = NULL;
PVector *pbvt_create() {
  PVector *v = calloc(sizeof(PVector), 1);
  v->refcount = 1;
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
  u->refcount = 0;
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
  assert(idx < 1 << NUM_BITS);

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
      // Hash didn't change, so we don't need to change the refcount
      v = ht_get(ht, hash);
    } else {
      v = pbvt_clone(v, i);
      ((PVector *)ht_get(ht, v->children[key]))->refcount--;
      v->children[key] = path[i - 1]->hash;
      path[i - 1]->refcount++;
      v->hash = hash;
      ht_insert(ht, hash, v);
    }
    path[i] = v;
  }

  // We always do this since our caller now has a reference to the new root node
  path[MAX_DEPTH - 1]->refcount++;
  return path[MAX_DEPTH - 1];
}

// Decrement reference count starting at root, free any nodes whose reference
// count drops to 0. With a custom memory allocator, this can be the expensive
// bit, may also consider changing the API to pbvt_gc(PVector**vs, size_t n),
// since we can coalesce compaction.
void pbvt_gc(PVector *v, uint64_t level) {
  if (v->hash == 0) // don't free NULL node
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
uint64_t dirty_sz;
uint8_t *dirty;
void pbvt_print(char *name, PVector **vs, size_t n) {
  dirty_sz = 0x10000;
  dirty = calloc(dirty_sz, 1);
  FILE *f = fopen(name, "w");
  if (f == NULL)
    return;
  fprintf(f, "digraph {\n");
  fprintf(f, "\tnode[shape=record];\n");

  fprintf(f, "\ttimeline [\n");
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<timeline>timeline|{");
  for (size_t i = 0; i < n; ++i) {
    fprintf(f, "<%ld>%.16lx", i, vs[i]->hash);
    if (i != n - 1)
      fprintf(f, "|");
  }
  fprintf(f, "}}");
  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  for (size_t i = 0; i < n; ++i) {
    fprintf(f, "\ttimeline:%ld -> v%.16lx;\n", i, vs[i]->hash);
  }

  for (size_t i = 0; i < n; ++i)
    pbvt_print_node(f, vs[i], MAX_DEPTH - 1);

  fprintf(f, "}\n");
  fclose(f);
  free(dirty);
}

void pbvt_print_node(FILE *f, PVector *v, int level) {
  int is_dirty = dirty[v->hash % dirty_sz];
  if (is_dirty)
    return;
  dirty[v->hash % dirty_sz] = 1;

  fprintf(f, "\tv%.16lx [\n", v->hash);
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<head>%.16lx (%ld refs)|{", v->hash, v->refcount);
  if (level > 0) {
    for (int i = 0; i < NUM_CHILDREN; ++i) {
      if (v->children[i])
        fprintf(f, "<%d>%.16lx", i, v->children[i]);
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
      fprintf(f, "\tv%.16lx:%d -> v%.16lx;\n", v->hash, i, v->children[i]);
      pbvt_print_node(f, ht_get(ht, v->children[i]), level - 1);
    }
  }
}

void pbvt_cleanup(void) {
  free(ht_get(ht, 0));
  ht_free(ht);
}