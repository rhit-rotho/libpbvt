#include <stdint.h>
#include <stdlib.h>

// Each bin holds allocations of size 1 << i (down to 1-byte allocations)
#define NUM_BINS 12
#define BIN_SIZE (4 * 0x1000)

// For our bitvector, 8 bits per uint8_t
#define BITS_PER_BLOCK (8 * sizeof(uint8_t))

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

// TODO: Add fastbins
typedef struct MallocState {
  size_t total_allocations;
  size_t current_bytes;
  size_t current_allocations;
  size_t current_pages;

  // Last bin is a linked list for oversized allocations
  BinHdr *bins[NUM_BINS + 1];
} MallocState;

void *memory_calloc(MallocState *ms, size_t nmemb, size_t size);
void *memory_realloc(MallocState *ms, void *ptr, size_t size);
void *memory_malloc(MallocState *ms, size_t size);
void memory_free(MallocState *ms, void *ptr);
void print_malloc_stats(MallocState *ms);

// private operations
void bv_set(uint8_t *bv, uint64_t key);
void bv_unset(uint8_t *bv, uint64_t key);
int bv_is_set(uint8_t *bv, uint64_t key);
size_t bv_find_first_zero(uint8_t *bv, size_t cap);
BinHdr *allocate_bin(MallocState *ms, size_t size);
