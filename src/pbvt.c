#include "pbvt.h"


uint64_t idx = 0;
pvector_t *pbvt_create(void) {
  pvector_t *v = calloc(sizeof(pvector_t), 1);
  v->idx = idx++;
  return v;
}

// The reason we can do this without cloning all the child nodes is because our
// tree is persistent; all operations on the data structure will clone any
// children as necessary, so we can be lazy here.
pvector_t *pbvt_clone(pvector_t *v) {
  pvector_t *u = malloc(sizeof(pvector_t));
  memcpy(u, v, sizeof(pvector_t));
  return u;
}

// pvector_t *pbvt_set_child(pvector_t *v, uint64_t key, pvector_t *u) {
//   if (v->exclusive) {
//     v->children[key] = u;
//     return v;
//   } else {
//     v = pbvt_clone(v);
//     v->children[key] = u;
//     return v;
//   }
// }

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
  uint64_t key;
  pvector_t *t = v;
  for (int i = MAX_DEPTH - 1; i >= 1; --i) {
    key = (idx >> (i * BITS_PER_LEVEL)) & CHILD_MASK;
    if (!v->populated[key]) {
      v->children[key] = pbvt_create();
      v->populated[key] = 1;
    }
    v = v->children[key];
  }
  key = idx & CHILD_MASK;
  v->children[key] = val;
  v->populated[key] = 1;
  return t;
}

void pbvt_print(char *name, pvector_t **vs, size_t n) {
  FILE *f = fopen(name, "w");
  if (f == NULL)
    return;
  fprintf(f, "digraph {\n");
  fprintf(f, "\tnode[shape=record];\n");

  for (size_t i = 0; i < n; ++i)
    pbvt_print_node(f, vs[i], 0, MAX_DEPTH - 1);

  fprintf(f, "}\n");
  fclose(f);
}

void pbvt_print_node(FILE *f, pvector_t *v, int idx, int level) {
  fprintf(f, "\tv%p [\n", v);
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<head>%p|{", v);
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
      fprintf(f, "\tv%p:%d -> v%p;\n", v, i, v->children[i], i);
      pbvt_print_node(f, v->children[i], i, level - 1);
    }
  }
}