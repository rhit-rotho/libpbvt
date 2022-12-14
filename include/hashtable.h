#pragma once

#include <stddef.h>
#include <stdint.h>

// Basic implementation of hash table with bucketing

#define HT_INITIAL_CAP (512)
#define HT_LOADING_FACTOR (2)
#define HT_BUCKET_CAP HT_LOADING_FACTOR

typedef struct HashBucket {
  uint64_t *keys;
  void **values;

  size_t cap;
  size_t size;
} HashBucket;

typedef struct HashTable {
  HashBucket *buckets;
  size_t cap; // power of 2, number of buckets
  size_t size;
} HashTable;

// public operations
HashTable *ht_create(void);
int ht_insert(HashTable *ht, uint64_t key, void *val);
void *ht_get(HashTable *ht, uint64_t key);
void *ht_remove(HashTable *ht, uint64_t key);
void ht_free(HashTable *ht);
size_t ht_size(HashTable *ht);