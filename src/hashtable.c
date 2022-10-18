#include "hashtable.h"

HashTable *ht_create(void) {
  HashTable *ht = malloc(sizeof(HashTable));
  ht->cap = HT_INITIAL_CAP;
  ht->size = 0;
  ht->arr = malloc(sizeof(HashEntry) * ht->cap);
  // memset(ht->arr, 0xff, sizeof(HashEntry) * ht->cap);
  for (size_t i = 0; i < ht->cap; ++i)
    ht->arr[i].key = HT_TOMBSTONE;
  return ht;
}

void *ht_get(HashTable *ht, uint64_t key) {
  HashEntry he;
  for (size_t i = 0; i < ht->cap; ++i) {
    he = ht->arr[(key + i) % ht->cap];
    if (he.key == key)
      return he.value;
  }
  return NULL;
}

// Assumes caller does not try to insert duplicates
int ht_insert(HashTable *ht, uint64_t key, void *val) {
  // assert(!ht_get(ht, key));
  if (ht_get(ht, key))
    return 0;

  // rekey and free
  if (ht->size > ht->cap * HT_LOADING_FACTOR) {
    HashTable hnt = {0};
    HashTable *hn = &hnt;
    hn->size = 0;
    hn->cap = ht->cap * 2;
    hn->arr = malloc(sizeof(HashEntry) * hn->cap);
    // memset(hn->arr, 0xff, sizeof(HashEntry) * hn->cap);
    for (size_t i = 0; i < hn->cap; ++i)
      hn->arr[i].key = HT_TOMBSTONE;

    // reinsert
    for (size_t i = 0; i < ht->cap; ++i) {
      HashEntry he = ht->arr[i];
      if (he.key != HT_TOMBSTONE)
        // WARNING: Recursive call, make sure this doesn't reshuffle
        ht_insert(hn, he.key, he.value);
    }
    free(ht->arr);
    ht->arr = hn->arr;
    ht->size = hn->size;
    ht->cap = hn->cap;
  }

  uint8_t inserted = 0;
  HashEntry he;
  HashEntry be = {key, val};
  for (size_t i = 0; i < ht->cap; ++i) {
    he = ht->arr[(key + i) % ht->cap];
    if (he.key == HT_TOMBSTONE) {
      ht->arr[(key + i) % ht->cap] = be;
      inserted = 1;
      break;
    }
  }
  assert(inserted);
  ht->size++;
  return 0;
}

void *ht_remove(HashTable *ht, uint64_t key) {
  HashEntry he;
  for (size_t i = 0; i < ht->cap; ++i) {
    he = ht->arr[(key + i) % ht->cap];
    if (he.key == key) {
      he = ht->arr[i];
      ht->arr[(key + i) % ht->cap].key = HT_TOMBSTONE;
      ht->size--;
      return he.value;
    }
  }
  return NULL;
}

void ht_free(HashTable *ht) {
  free(ht->arr);
  free(ht);
}