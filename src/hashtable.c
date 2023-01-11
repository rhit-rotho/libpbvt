#include <assert.h>
#include <string.h>

#include "hashtable.h"
#include "mmap_malloc.h"

HashTable *ht_create(void) {
  HashTable *ht = mmap_malloc(sizeof(HashTable));
  ht->cap = HT_INITIAL_CAP;
  ht->size = 0;
  ht->buckets = mmap_calloc(ht->cap, sizeof(HashBucket));

  for (size_t i = 0; i < ht->cap; ++i)
    ht->buckets[i].size = 0;

  return ht;
}

void *ht_get(HashTable *ht, uint64_t key) {
  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  for (size_t i = 0; i < bucket->size; ++i)
    if (bucket->keys[i] == key) {
#if 0
      if (i > 0) {
        uint64_t temp_key;
        void *temp_value;
        memcpy(&temp_key, &bucket->keys[i], sizeof(temp_key));
        memcpy(&temp_value, &bucket->values[i], sizeof(temp_value));

        memcpy(&bucket->keys[i], &bucket->keys[0], sizeof(temp_key));
        memcpy(&bucket->values[i], &bucket->values[0], sizeof(temp_value));

        memcpy(&bucket->keys[0], &temp_key, sizeof(temp_key));
        memcpy(&bucket->values[0], &temp_value, sizeof(temp_value));
      }
      return bucket->values[0];
#else
      return bucket->values[i];
#endif
    }
  return NULL;
}

void ht_rekey(HashTable *ht) {
  HashTable hnt = {0};
  HashTable *hn = &hnt;
  hn->size = 0;
  hn->cap = ht->cap * 2;
  hn->buckets = mmap_calloc(hn->cap, sizeof(HashBucket));

  for (size_t i = 0; i < hn->cap; ++i)
    hn->buckets[i].size = 0;

  // reinsert
  for (size_t i = 0; i < ht->cap; ++i) {
    HashBucket *bucket = &ht->buckets[i];
    for (size_t j = 0; j < bucket->size; ++j) {
      // WARNING: Recursive call, make sure this doesn't reshuffle
      ht_insert(hn, bucket->keys[j], bucket->values[j]);
    }
  }
  mmap_free(ht->buckets);
  memcpy(ht, hn, sizeof(HashTable));
}

// Assumes caller does not try to insert duplicates
int ht_insert(HashTable *ht, uint64_t key, void *val) {
  assert(!ht_get(ht, key));

  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  while (bucket->size + 1 >= HT_BUCKET_CAP) {
    ht_rekey(ht);
    bucket = &ht->buckets[key & (ht->cap - 1)];
  }

  bucket->keys[bucket->size] = key;
  bucket->values[bucket->size] = val;
  bucket->size++;
  ht->size++;

  return 0;
}

void *ht_remove(HashTable *ht, uint64_t key) {
  HashBucket *bucket = &ht->buckets[key & (ht->cap - 1)];
  for (size_t i = 0; i < bucket->size; ++i) {
    if (bucket->keys[i] == key) {
      void *val = bucket->values[i];
      // Shift all elements back one. This should be fast because of our low
      // loading factor.
      for (size_t j = i; j < bucket->size - 1; ++j) {
        bucket->keys[j] = bucket->keys[j + 1];
        bucket->values[j] = bucket->values[j + 1];
      }
      bucket->size--;
      bucket->keys[bucket->size] = 0x5555555555555555;
      bucket->values[bucket->size] = (void *)0x5555555555555555;
      ht->size--;
      return val;
    }
  }
  return NULL;
}

void ht_free(HashTable *ht) {
  mmap_free(ht->buckets);
  mmap_free(ht);
}

size_t ht_size(HashTable *ht) { return ht->size; }