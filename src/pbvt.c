#include "pbvt.h"

// TODO: For a multi-threaded implementation a global counter is killer,
// consider indexing nodes by contents (e.g. siphash) rather than by the order
// in which they were created. This also simplifies memory allocation, which can
// be O(1) with a hash table.
uint64_t idx = 0;
pvector_t *pbvt_create(void) {
  pvector_t *v = calloc(sizeof(pvector_t), 1);
  v->idx = idx++;
  v->refcount = 1;
  return v;
}

// The reason we can do this without cloning all the child nodes is because our
// tree is persistent; all operations on the data structure will clone any
// children as necessary, so we can be lazy here.
pvector_t *pbvt_clone(pvector_t *v, uint64_t level) {
  pvector_t *u = pbvt_create();
  for (int i = 0; i < NUM_CHILDREN; ++i) {
    u->children[i] = v->children[i];
    u->populated[i] = v->populated[i];
    if (level > 1 && u->populated[i])
      u->children[i]->refcount++;
  }
  return u;
}

// This is (purposely) similar to a page-walk, except instead of 12-bit page
// tables, we have BITS_PER_LEVEL-bits
uint64_t pbvt_get(pvector_t *v, uint64_t idx) {
  uint64_t key;

  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idx >> (i * BITS_PER_LEVEL)) & CHILD_MASK;
    if (!v->populated[key])
      return -1;
    v = v->children[key];
  }
  key = idx & CHILD_MASK;
  return (uint64_t)v->children[key];
}

pvector_t *pbvt_update(pvector_t *v, uint64_t idx, uint64_t val) {
  // TODO: Test this as an optimization
  //   if (pbvt_get(v, idx) == val)
  //     return v;

  uint64_t key;
  pvector_t *u = pbvt_clone(v, MAX_DEPTH - 1);
  v = u;
  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idx >> (i * BITS_PER_LEVEL)) & CHILD_MASK;
    if (!v->populated[key]) {
      v->children[key] = pbvt_create();
      v->populated[key] = 1;
    }
    v->children[key]->refcount--;
    v->children[key] = pbvt_clone(v->children[key], i);
    v = v->children[key];
  }
  key = idx & CHILD_MASK;
  v->children[key] = (pvector_t *)val;
  v->populated[key] = 1;
  return u;
}

// Decrement reference count starting at root, free any nodes whose reference
// count drops to 0.
void pbvt_gc(pvector_t *v, uint64_t level) {
  if (level == 0)
    return;
  for (int i = 0; i < NUM_CHILDREN; ++i) {
    if (v->populated[i])
      pbvt_gc(v->children[i], level - 1);
  }
  v->refcount--;
  if (v->refcount == 0) {
    memset(v, 0xa5, sizeof(pvector_t));
    free(v);
  }
}

void pbvt_print(char *name, pvector_t **vs, size_t n) {
  FILE *f = fopen(name, "w");
  if (f == NULL)
    return;
  fprintf(f, "digraph {\n");
  fprintf(f, "\tnode[shape=record];\n");

  for (size_t i = 0; i < n; ++i)
    pbvt_print_node(f, vs[i], MAX_DEPTH - 1);

  fprintf(f, "}\n");
  fclose(f);
}

void pbvt_print_node(FILE *f, pvector_t *v, int level) {
  fprintf(f, "\tv%ld [\n", v->idx);
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<head>%ld (%ld refs)|{", v->idx, v->refcount);
  for (int i = 0; i < NUM_CHILDREN; ++i) {
    if (v->populated[i])
      fprintf(f, "<%d>%p", i, v->children[i]);
    else
      fprintf(f, "<%d>x", i);
    if (i != NUM_CHILDREN - 1)
      fprintf(f, "|");
  }
  fprintf(f, "}}");

  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  if (level == 0)
    return;

  for (int i = 0; i < NUM_CHILDREN; ++i) {
    if (v->populated[i]) {
      fprintf(f, "\tv%ld:%d -> v%ld;\n", v->idx, i, v->children[i]->idx);
      pbvt_print_node(f, v->children[i], level - 1);
    }
  }
}