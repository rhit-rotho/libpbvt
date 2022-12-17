#include <assert.h>
#include <string.h>

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
    ht->buckets[i].keys =
        memory_calloc(NULL, ht->buckets[i].cap, sizeof(uint64_t));
    ht->buckets[i].values =
        memory_calloc(NULL, ht->buckets[i].cap, sizeof(void *));
  }
  return ht;
}

void *ht_get(HashTable *ht, uint64_t key) {
  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  for (size_t i = 0; i < bucket->size; ++i)
    if (bucket->keys[i] == key)
      return bucket->values[i];
  return NULL;
}

void ht_rekey(HashTable *ht) {
  HashTable hnt = {0};
  HashTable *hn = &hnt;
  hn->size = 0;
  hn->cap = ht->cap * 2;
  hn->buckets = memory_calloc(NULL, hn->cap, sizeof(HashBucket));
  for (size_t i = 0; i < hn->cap; ++i) {
    hn->buckets[i].size = 0;
    hn->buckets[i].cap = HT_BUCKET_CAP;
    hn->buckets[i].keys =
        memory_calloc(NULL, hn->buckets[i].cap, sizeof(uint64_t));
    hn->buckets[i].values =
        memory_calloc(NULL, hn->buckets[i].cap, sizeof(void *));
  }

  // reinsert
  for (size_t i = 0; i < ht->cap; ++i) {
    HashBucket *bucket = &ht->buckets[i];
    for (size_t j = 0; j < bucket->size; ++j) {
      // WARNING: Recursive call, make sure this doesn't reshuffle
      ht_insert(hn, bucket->keys[j], bucket->values[j]);
    }
    memory_free(NULL, bucket->keys);
    memory_free(NULL, bucket->values);
  }
  memory_free(NULL, ht->buckets);
  memcpy(ht, hn, sizeof(HashTable));
}

// Assumes caller does not try to insert duplicates
int ht_insert(HashTable *ht, uint64_t key, void *val) {
  assert(!ht_get(ht, key));

  // rekey and free
  if (ht->size == ht->cap * HT_LOADING_FACTOR)
    ht_rekey(ht);

  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  if (bucket->size + 1 == bucket->cap) {
    bucket->cap *= 2;
    bucket->keys =
        memory_realloc(NULL, bucket->keys, sizeof(uint64_t) * bucket->cap);
    bucket->values =
        memory_realloc(NULL, bucket->values, sizeof(void *) * bucket->cap);
  }

  bucket->keys[bucket->size] = key;
  bucket->values[bucket->size] = val;
  bucket->size++;
  ht->size++;

  return 0;
}

void *ht_remove(HashTable *ht, uint64_t key) {
  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  for (size_t i = 0; i < bucket->size; ++i)
    if (bucket->keys[i] == key) {
      void *val = bucket->values[i];
      // Shift all elements back one. This should be fast because of our low
      // loading factor.
      // for (size_t j = i; j < bucket->size - 1; ++j) {
      //   bucket->keys[j] = bucket->keys[j + 1];
      //   bucket->values[j] = bucket->values[j + 1];
      // }
      memmove(&bucket->keys[i], &bucket->keys[i + 1],
              sizeof(uint64_t) * (bucket->size - i));
      memmove(&bucket->values[i], &bucket->values[i + 1],
              sizeof(void *) * (bucket->size - i));
      bucket->size--;
      ht->size--;
      return val;
    }
  return NULL;
}

void ht_free(HashTable *ht) {
  for (size_t i = 0; i < ht->cap; ++i) {
    memory_free(NULL, ht->buckets[i].keys);
    memory_free(NULL, ht->buckets[i].values);
  }
  memory_free(NULL, ht->buckets);
  memory_free(NULL, ht);
}

size_t ht_size(HashTable *ht) { return ht->size; }