#include <assert.h>

#include "hashtable.h"
#include "memory.h"

HashTable *ht_create(void) {
  HashTable *ht = memory_malloc(NULL, sizeof(HashTable));
  ht->cap = HT_INITIAL_CAP;
  ht->size = 0;
  ht->buckets = memory_calloc(NULL, ht->cap, sizeof(HashBucket));
  for (size_t i = 0; i < ht->cap; ++i) {
    ht->buckets[i].size = 0;
    ht->buckets[i].cap = HT_BUCKET_CAP;
    ht->buckets[i].entries =
        memory_calloc(NULL, ht->buckets[i].cap, sizeof(HashEntry));
  }
  return ht;
}

void *ht_get(HashTable *ht, uint64_t key) {
  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  for (size_t i = 0; i < bucket->size; ++i)
    if (bucket->entries[i].key == key)
      return bucket->entries[i].value;
  return NULL;
}

// Assumes caller does not try to insert duplicates
int ht_insert(HashTable *ht, uint64_t key, void *val) {
  assert(!ht_get(ht, key));

  // rekey and free
  if (ht->size == ht->cap * HT_LOADING_FACTOR) {
    HashTable hnt = {0};
    HashTable *hn = &hnt;
    hn->size = 0;
    hn->cap = ht->cap * 2;
    hn->buckets = memory_calloc(NULL, hn->cap, sizeof(HashBucket));
    for (size_t i = 0; i < hn->cap; ++i) {
      hn->buckets[i].size = 0;
      hn->buckets[i].cap = HT_BUCKET_CAP;
      hn->buckets[i].entries =
          memory_calloc(NULL, hn->buckets[i].cap, sizeof(HashEntry));
    }

    // reinsert
    for (size_t i = 0; i < ht->cap; ++i) {
      HashBucket *bucket = &ht->buckets[i];
      for (size_t j = 0; j < bucket->size; ++j) {
        HashEntry he = bucket->entries[j];
        // WARNING: Recursive call, make sure this doesn't reshuffle
        ht_insert(hn, he.key, he.value);
      }
      memory_free(NULL, bucket->entries);
    }
    memory_free(NULL, ht->buckets);
    memcpy(ht, hn, sizeof(HashTable));
  }

  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  if (bucket->size + 1 == bucket->cap) {
    bucket->cap *= 2;
    bucket->entries =
        memory_realloc(NULL, bucket->entries, sizeof(HashEntry) * bucket->cap);
  }

  HashEntry be = {key, val};
  bucket->entries[bucket->size] = be;
  bucket->size++;
  ht->size++;

  return 0;
}

void *ht_remove(HashTable *ht, uint64_t key) {
  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  for (size_t i = 0; i < bucket->size; ++i)
    if (bucket->entries[i].key == key) {
      void *val = bucket->entries[i].value;
      // Shift all elements back one. This should be fast because of our low
      // loading factor.
      for (size_t j = i; j < bucket->size - 1; ++j)
        bucket->entries[j] = bucket->entries[j + 1];
      // memmove(&bucket->entries[i], &bucket->entries[i + 1],
      //         sizeof(HashEntry) * (bucket->size - i));
      bucket->size--;
      ht->size--;
      return val;
    }
  return NULL;
}

void ht_free(HashTable *ht) {
  for (size_t i = 0; i < ht->cap; ++i)
    memory_free(NULL, ht->buckets[i].entries);
  memory_free(NULL, ht->buckets);
  memory_free(NULL, ht);
}

size_t ht_size(HashTable *ht) { return ht->size; }