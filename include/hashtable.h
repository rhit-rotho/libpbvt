#pragma once

#include <stddef.h>
#include <stdint.h>

// Basic implementation of hash table with bucketing

#define HT_INITIAL_CAP (0x4000)
#define HT_BUCKET_CAP (16)

typedef struct HashBucket {
  size_t size;
  uint64_t keys[HT_BUCKET_CAP];
  void *values[HT_BUCKET_CAP];
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