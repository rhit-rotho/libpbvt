#include "pbvt.h"

PVectorState *pbvt_init(void) {
  PVectorState *pvs = calloc(1, sizeof(PVectorState));
  pvs->q = queue_create();

  // create null node
  PVector *v = calloc(1, sizeof(PVector));
  v->hash = 0UL;

  queue_push(pvs->q, v);

  ht = ht_create();
  ht_insert(ht, 0UL, v);
  return pvs;
}

uint8_t pbvt_get_latest(PVectorState *pvs, uint64_t key) {
  return pvector_get(queue_front(pvs->q), key);
}

void pbvt_update_latest(PVectorState *pvs, uint64_t key, uint8_t val) {
  queue_push(pvs->q, pvector_update(queue_front(pvs->q), key, val));
}

void pbvt_cleanup(PVectorState *pvs) {
  while (queue_size(pvs->q) > 0)
    pvector_gc(queue_popleft(pvs->q), MAX_DEPTH - 1);
  queue_free(pvs->q);
  ht_free(ht);
  free(pvs);
}

void pbvt_gc_n(PVectorState *pvs, size_t n) {
  for (size_t i = 0; i < n; ++i)
    pvector_gc(queue_popleft(pvs->q), MAX_DEPTH - 1);
}

size_t pbvt_size(PVectorState *pvs) { return queue_size(pvs->q); }

void pbvt_print(PVectorState *pvs, char *path) {
  HashTable *pr = ht_create();
  FILE *f = fopen(path, "w");
  if (f == NULL)
    return;
  fprintf(f, "digraph {\n");
  fprintf(f, "\tnode[shape=record];\n");

  fprintf(f, "\ttimeline [\n");
  fprintf(f, "\t\tlabel = \"");
  fprintf(f, "{<timeline>timeline|{");
  for (size_t i = 0, n = queue_size(pvs->q); i < n; ++i) {
    fprintf(f, "<%ld>%.16lx", i, ((PVector *)queue_peek(pvs->q, i))->hash);
    if (i != n - 1)
      fprintf(f, "|");
  }
  fprintf(f, "}}");
  fprintf(f, "\";\n");
  fprintf(f, "\t];\n");

  for (size_t i = 0, n = queue_size(pvs->q); i < n; ++i) {
    fprintf(f, "\ttimeline:%ld -> v%.16lx;\n", i,
            ((PVector *)queue_peek(pvs->q, i))->hash);
  }

  for (size_t i = 0, n = queue_size(pvs->q); i < n; ++i)
    pbvt_print_node(f, pr, (PVector *)queue_peek(pvs->q, i), MAX_DEPTH - 1);

  fprintf(f, "}\n");
  fclose(f);
  ht_free(pr);
}

void pbvt_print_node(FILE *f, HashTable *pr, PVector *v, int level) {
  if (ht_get(pr, v->hash))
    return;
  ht_insert(pr, v->hash, v);

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
      pbvt_print_node(f, pr, ht_get(ht, v->children[i]), level - 1);
    }
  }
}

#include "fasthash.h"
#include <assert.h>
#include <malloc.h>
void pbvt_stats(PVectorState *pvs) {
  printf("Tracked states: %ld\n", queue_size(pvs->q));
  printf("Number of nodes: %ld\n", ht_size(ht));
  printf("Theoretical max: 0x%lx\n", 1UL << NUM_BITS);
  printf("Sparsity: %f\n", 100.0 * (float)ht_size(ht) /
                               (float)(queue_size(pvs->q) * (1UL << NUM_BITS)));
  malloc_stats();

  // check hash
  for (size_t i = 0; i < ht->cap; ++i) {
    HashBucket *hb = &ht->buckets[i];
    for (size_t j = 0; j < hb->size; ++j) {
      HashEntry *he = &hb->entries[j];
      PVector *v = he->value;

      // incorrect hash for our null node
      if (v->hash == 0UL)
        continue;

      // for (int i = 0, n = sizeof(v->bytes); i < n; ++i)
      //   printf("%.2x ", v->bytes[i]);
      // printf("\n");
      assert(fasthash64(v->bytes, sizeof(v->bytes), 0) == v->hash);
    }
  }

  PVector *pv = NULL;
  uint64_t refs = 0;

  for (size_t i = 0; i < ht->cap; ++i) {
    HashBucket *hb = &ht->buckets[i];
    for (size_t j = 0; j < hb->size; ++j) {
      HashEntry *he = &hb->entries[j];
      PVector *v = he->value;
      if (v->hash == 0UL)
        continue;
      if (v->level == 0 && v->refcount > refs) {
        pv = v;
        refs = pv->refcount;
      }
    }
  }

  char chars[0x100][0x3];
  for (uint32_t i = 0; i < sizeof(chars) / sizeof(chars[0]); ++i) {
    chars[i][0] = i;
    chars[i][1] = '\0';
  }

  chars['\n'][0] = '\\';
  chars['\n'][1] = 'n';
  chars['\n'][2] = '\0';

  chars['\0'][0] = '\\';
  chars['\0'][1] = '0';
  chars['\0'][2] = '\0';

  printf("node %.16lx (level: %ld) with %ld refs:\n", pv->hash, pv->level,
         pv->refcount);
  printf("b\"");
  for (int i = 0, n = sizeof(pv->bytes); i < n; ++i)
    // printf("%.2x ", pv->bytes[i]);
    printf("%s", chars[pv->bytes[i]]);
  printf("\"\n");
}
