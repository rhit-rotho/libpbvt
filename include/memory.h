#include <stdint.h>
#include <stdlib.h>

#include "hashtable.h"

/*

The main goal of our implementation is to avoid interfering with any client
application, and minimizing the amount of metadata that needs to be dirtied on
each call to malloc/free while still maintaining reasonable performance and
overhead for small allocations.

Our allocator consists of an array of pointers to a linked list of bins
(allocated directly from mmap).

Each bin has forward and backward pointers for supporting coalescing when one
bin is emptied (in future this could also be done even when bins aren't empty,
see e.g., "Mesh" by Emery Berger).

+--------+--------+--------+--------+
| next   | prev   | cap    | sz     |
+--------+--------+--------+--------+
| memsz  | bitmp* | cntns* |bbbbbbbb|
+--------+--------+--------+--------+
|bbbbbbbb| bb...  | allocations.... |
+--------+--------+--------+--------+
| ...                               |
+-----------------------------------+

Additionally, each bin has a bitmap immediately following the header that
represents which allocations are free. When first created, each bin is
configured to only accept allocations of a certain size (usually a power of 2),
with both bitmap and contents pointing to variable parts of the bin.

Allocations larger than BIN_SIZE are added to a catch-all linked list of bins,
with capacity 1 and a size large enough to contain at least one allocation of
the desired size.

All of our metadata is contained inside either the bin itself, or our
MallocState struct, to support write-tracking for our persistent heap
implementation. We call mmap instead of building on top of malloc to avoid
mucking around with any internal state in malloc.

*/

// Make sure this matches sizeof(BIN_SIZES)/sizeof(BIN_SIZES[0]) in memory.c
#define NUM_BINS (6)
// This can be tuned, must be power of 2 greater than pagesize
#define BIN_SIZE (1 << 14)

// For our bitvector, 8 bits per uint8_t
#define BITS_PER_BLOCK (8 * sizeof(uint8_t))

typedef struct BinHdr BinHdr;

// cap is the total number of allocations that can be made to this chunk
// size is the current number of allocations
// Bin is always a multiple of page size
typedef struct BinHdr {
  BinHdr *next;
  BinHdr *prev;
  size_t idx;
  size_t cap;
  size_t sz;
  size_t memsz;
  uint8_t *bitmap;
  void *contents;
  // bitmap
  // contents
} BinHdr;

typedef struct MallocState {
  size_t total_allocations;
  size_t current_bytes;
  size_t current_allocations;
  size_t current_pages;

  // Last bin is a linked list for oversized allocations
  BinHdr *bins[NUM_BINS + 1];

  HashTable *bt;

  void (*on_mmap)(BinHdr *);
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
