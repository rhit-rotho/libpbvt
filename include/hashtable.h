#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Basic implementation of hash table with chaining

#define HT_BUCKET_CAP (2)
#define HT_INITIAL_CAP (16)
#define HT_LOADING_FACTOR (2)

typedef struct HashEntry {
  uint64_t key;
  void *value;
} HashEntry;

typedef struct HashBucket {
  HashEntry *entries;
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
