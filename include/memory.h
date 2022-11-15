#include <stdint.h>
#include <stdlib.h>

typedef struct BinHdr BinHdr;

// cap is the total number of allocations that can be made to this chunk
// size is the current number of allocations
// Bin is always a multiple of page size
typedef struct BinHdr {
  BinHdr *next;
  BinHdr *prev;
  size_t cap;
  size_t sz;
  size_t memsz;
  uint8_t *bitmap;
  void *contents;
  // bitmap
  // contents
} BinHdr;

typedef struct MallocStats {
  size_t total_allocations;
  size_t current_bytes;
  size_t current_allocations;
  size_t current_pages;
} MallocStats;

// Each bin holds allocations of size 1 << i (down to 1-byte allocations)
#define NUM_BINS 12
#define BIN_SIZE (4 * 0x1000)

// For our bitvector, 8 bits per uint8_t
#define BITS_PER_BLOCK (8 * sizeof(uint8_t))

void *memory_calloc(size_t nmemb, size_t size);
void *memory_malloc(size_t size);
void *memory_realloc(void *ptr, size_t size);
void memory_free(void *ptr);

void print_malloc_stats(void);

// private operations
void bv_set(uint8_t *bv, uint64_t key);
void bv_unset(uint8_t *bv, uint64_t key);
int bv_is_set(uint8_t *bv, uint64_t key);
size_t bv_find_first_zero(uint8_t *bv, size_t cap);