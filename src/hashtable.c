#include "hashtable.h"

HashTable *ht_create(void) {
  HashTable *ht = malloc(sizeof(HashTable));
  ht->cap = HT_INITIAL_CAP;
  ht->size = 0;
  ht->buckets = calloc(sizeof(HashBucket) * ht->cap, 1);
  for (size_t i = 0; i < ht->cap; ++i) {
    ht->buckets[i].size = 0;
    ht->buckets[i].cap = HT_BUCKET_CAP;
    ht->buckets[i].entries = calloc(sizeof(HashEntry) * ht->buckets[i].cap, 1);
  }
  return ht;
}

void *ht_get(HashTable *ht, uint64_t key) {
  HashBucket bucket = ht->buckets[key % ht->cap];
  for (size_t i = 0; i < bucket.size; ++i)
    if (bucket.entries[i].key == key)
      return bucket.entries[i].value;
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
    hn->buckets = calloc(sizeof(HashBucket) * hn->cap, 1);
    for (size_t i = 0; i < hn->cap; ++i) {
      hn->buckets[i].size = 0;
      hn->buckets[i].cap = HT_BUCKET_CAP;
      hn->buckets[i].entries =
          calloc(sizeof(HashEntry) * hn->buckets[i].cap, 1);
    }

    // reinsert
    for (size_t i = 0; i < ht->cap; ++i) {
      for (size_t j = 0; j < ht->buckets[i].size; ++j) {
        HashEntry he = ht->buckets[i].entries[j];
        // WARNING: Recursive call, make sure this doesn't reshuffle
        ht_insert(hn, he.key, he.value);
      }
      free(ht->buckets[i].entries);
    }
    free(ht->buckets);
    ht->buckets = hn->buckets;
    ht->size = hn->size;
    ht->cap = hn->cap;
  }

  HashBucket *bucket = &ht->buckets[key % ht->cap];
  if (bucket->size == bucket->cap) {
    bucket->cap *= 2;
    bucket->entries = realloc(bucket->entries, sizeof(HashEntry) * bucket->cap);
  }

  HashEntry be = {key, val};
  bucket->entries[bucket->size++] = be;
  ht->size++;

  return 0;
}

void *ht_remove(HashTable *ht, uint64_t key) {
  uint64_t pos = key % ht->cap;
  HashBucket bucket = ht->buckets[pos];

  for (size_t i = 0; i < bucket.size; ++i)
    if (bucket.entries[i].key == key) {
      void *val = bucket.entries[i].value;
      // Shuffle all elements back one. This should be find because of our low
      // loading factor.
      for (size_t j = i; j < bucket.size - 1; ++j)
        bucket.entries[j] = bucket.entries[j + 1];
      return val;
    }
  return NULL;
}

void ht_free(HashTable *ht) {
  for (size_t i = 0; i < ht->size; ++i)
    free(ht->buckets[i].entries);
  free(ht->buckets);
  free(ht);
}