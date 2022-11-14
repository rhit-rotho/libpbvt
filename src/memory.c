#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "memory.h"

BinHdr *bins[NUM_BINS];

// Allocate new bin for holding allocations of size 1 << idx
BinHdr *allocate_bin(size_t idx) {
  BinHdr *bin = mmap(NULL, BIN_SIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  bin->next = NULL;
  bin->prev = NULL;

  // Calculate capacity, size of our header + bitmap + contents should be less
  // than our bin size
  size_t c = 0;
  for (; sizeof(BinHdr) + ((c + 7) / 8) + (c << idx) < BIN_SIZE; c++)
    ;
  c -= 1;
  printf("// Allocating new bin: size: %d, cap: %ld, bytes: %ld, efficiency: "
         "%f%%\n",
         1 << idx, c, c << idx, (float)(c << idx) / BIN_SIZE);

  bin->sz = 0;
  bin->cap = c;

  // Adjust pointers into our bin
  bin->bitmap = (uint8_t *)bin + sizeof(BinHdr);
  bin->contents = bin->bitmap + ((bin->cap + 7) / 8);
  // printf("BIN: %p %ld %p %p\n", bin, bin->cap, bin->bitmap, bin->contents);
  return bin;
}

void *memory_calloc(size_t nmemb, size_t size) {
  void *ptr = memory_malloc(nmemb * size);
  assert(ptr != NULL);
  memset(ptr, 0, nmemb * size);
  return ptr;
}

void *memory_realloc(void *ptr, size_t size) {
  size_t idx = 0;
  BinHdr *bin;
  for (; idx < NUM_BINS; ++idx) {
    bin = bins[idx];
    while (bin) {
      if (bin->contents <= ptr && ptr < bin->contents + BIN_SIZE)
        goto bin_found;
      bin = bin->next;
    }
  }

  assert(0 && "No bin found!");

bin_found:

  void *dstptr = memory_malloc(size);
  memcpy(dstptr, ptr, 1 << idx);
  memory_free(ptr);
  printf("realloc(%p, %ld); // bin: %p, %p\n", ptr, size, bin, dstptr);
  return dstptr;
}

void *memory_malloc(size_t size) {
  // round up to nearest power of 2
  size_t idx = 0;
  for (; idx <= NUM_BINS; ++idx)
    if (size <= (1UL << idx))
      break;
  // TODO: Add binning for "too large" allocations
  if (idx == NUM_BINS)
    assert(0 && "Allocation too big!");

  BinHdr *bin = bins[idx];
  if (!bin) {
    bin = allocate_bin(idx);
    bins[idx] = bin;
  }

  // Find bin with room for more allocations, keep a reference to the last
  // non-NULL bin.
  while (!(bin->sz < bin->cap) && bin->next)
    bin = bin->next;

  if (bin->sz == bin->cap) {
    bin->next = allocate_bin(idx);
    bin->next->prev = bin;
    bin = bin->next;
  }

  size_t i = bv_find_first_zero(bin->bitmap, bin->cap);
  bv_set(bin->bitmap, i);
  bin->sz += 1;
  void *ptr = bin->contents + (i << idx);
  printf("malloc(%ld); // bin: %p %p\n", size, bin, ptr);
  fflush(stdout);
  return ptr;
}

// TODO: Dumb code. Replace with hash lookup from (ptr & page_mask) -> chunk
// Since we are also writing our client code, we could also call free with the
// size of our allocation
void memory_free(void *ptr) {
  if (ptr == NULL)
    return;

  BinHdr *bin;
  size_t idx = 0;
  for (; idx < NUM_BINS; ++idx) {
    bin = bins[idx];
    while (bin) {
      if (bin->contents <= ptr && ptr < bin->contents + (bin->cap << idx))
        goto bin_found;
      bin = bin->next;
    }
  }

  assert(0 && "No bin found!");

bin_found:
  printf("free(%p); // bin: %p\n", ptr, bin);

  size_t i = (ptr - bin->contents) / (1 << idx);
  if (!bv_is_set(bin->bitmap, i)) {
    printf("FAIL: %p\n", ptr);
    fflush(stdout);
    fflush(stderr);
    assert(bv_is_set(bin->bitmap, i));
  }
  bv_unset(bin->bitmap, i);
  bin->sz -= 1;

  // coalesce
  if (bin->sz == 0) {
    if (bin->prev)
      bin->prev->next = bin->next;
    if (bin->next)
      bin->next->prev = bin->prev;
    if (bins[idx] == bin)
      bins[idx] = bin->next;
    if (munmap(bin, BIN_SIZE) == -1)
      assert(0 && "munmap failed!");
    printf("// Returned bin %p to OS\n", bin);
  }

  return;
}

void bv_set(uint8_t *bv, uint64_t key) {
  uint8_t *block = &bv[key / BITS_PER_BLOCK];
  *block |= 1 << (key % BITS_PER_BLOCK);
}

void bv_unset(uint8_t *bv, uint64_t key) {
  assert(bv_is_set(bv, key));
  uint8_t *block = &bv[key / BITS_PER_BLOCK];
  *block &= ~(1 << (key % BITS_PER_BLOCK));
}

int bv_is_set(uint8_t *bv, uint64_t key) {
  return (bv[key / BITS_PER_BLOCK] >> (key % BITS_PER_BLOCK)) & 1;
}

// TODO: Accelerate
size_t bv_find_first_zero(uint8_t *bv, size_t cap) {
  for (size_t i = 0; i < cap; ++i) {
    if (bv[i] == ((1UL << BITS_PER_BLOCK) - 1))
      continue;

    uint8_t val = bv[i];
    size_t j = 0;
    while (val & 1) {
      val >>= 1;
      j += 1;
    }
    return i * BITS_PER_BLOCK + j;
  }
  return -1;
}
