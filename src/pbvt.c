#include "pbvt.h"

// TODO: For a multi-threaded implementation a global counter is killer,
// consider indexing nodes by contents (e.g. xxHash) rather than by the order
// in which they were created. This also simplifies memory allocation, which can
// be O(1) with a hash table.
uint64_t idx = 0;
PVector *pbvt_create() {
  PVector *v = calloc(sizeof(PVector), 1);
  v->idx = idx++;
  v->refcount = 1;
  v->hash = 0UL;
  return v;
}

// We can do this without cloning all the child nodes because our tree is
// persistent; all operations on the data structure will clone any children as
// necessary, so we can be lazy here.
PVector *pbvt_clone(PVector *v, uint64_t level) {
  PVector *u = pbvt_create();
  for (int i = 0; i < NUM_CHILDREN; ++i) {
    u->children[i] = v->children[i];
    if (level > 1 && u->children[i])
      u->children[i]->refcount++;
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
    v = v->children[key];
  }
  key = idx & BOTTOM_MASK;
  return v->bytes[key];
}

PVector *pbvt_update(PVector *v, uint64_t idx, uint64_t val) {
  // TODO: Test this as an optimization
  //   if (pbvt_get(v, idx) == val)
  //     return v;

  uint64_t key;
  PVector *u = pbvt_clone(v, MAX_DEPTH - 1);
  v = u;
  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idx >> (i * BITS_PER_LEVEL + 3)) & CHILD_MASK;
    if (!v->children[key])
      v->children[key] = pbvt_create();
    v->children[key]->refcount--;
    v->children[key] = pbvt_clone(v->children[key], i);
    v = v->children[key];
  }
  key = idx & BOTTOM_MASK;
  v->bytes[key] = val;
  return u;
}

// Decrement reference count starting at root, free any nodes whose reference
// count drops to 0.
void pbvt_gc(PVector *v, uint64_t level) {
  if (level > 0)
    for (int i = 0; i < NUM_CHILDREN; ++i)
      if (v->children[i])
        pbvt_gc(v->children[i], level - 1);
  v->refcount--;
  if (v->refcount == 0)
    free(v);
}

void pbvt_print(char *name, PVector **vs, size_t n) {
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
}

void pbvt_print_node(FILE *f, PVector *v, int level) {
  fprintf(f, "\tv%ld [\n", v->idx);
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<head>%ld (%ld refs)|{", v->idx, v->refcount);
  if (level > 0) {
    for (int i = 0; i < NUM_CHILDREN; ++i) {
      if (v->children[i])
        fprintf(f, "<%d>%p", i, v->children[i]);
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
      fprintf(f, "\tv%ld:%d -> v%ld;\n", v->idx, i, v->children[i]->idx);
      pbvt_print_node(f, v->children[i], level - 1);
    }
  }
}