#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "memory.h"

// Make sure this matches NUM_BINS in memory.h
const size_t BIN_SIZES[] = {8, 24, 32, 64, 128, 272};

MallocState global_heap;
// Allocate new bin for holding allocations of `size`
BinHdr *allocate_bin(MallocState *ms, size_t size) {
  // Calculate capacity, size of our header + bitmap + alignment + contents
  // should be less than our bin size
  size_t c = 0;
  size_t sz = BIN_SIZE;
  for (; ((sizeof(BinHdr) + ((c + 7) / 8) + 0xf) & ~0xf) + (c * size) < sz; ++c)
    ;
  c -= 1;

  // Handle oversized allocations
  if (c < 1) {
    c = 1;
    // Pad to 16-byte alignment
    sz = (sizeof(BinHdr) + ((c + 7) / 8) + 0x0f) & ~0x0f;
    // Page-align
    sz = (sz + size + 0xfff) & ~0xfff;
  }

  BinHdr *bin = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  // HACK: Ugly, should be handled inside pbvt.c
  if (ms != &global_heap)
    pbvt_track_range(bin, sz);
  if (bin == MAP_FAILED)
    perror("mmap");
  bin->next = NULL;
  bin->prev = NULL;

#ifdef MDEBUG
  printf("// Allocating for %ld-byte, efficiency: %f%%\n", size,
         100.0 * (float)(c * size) / sz);
#endif

  bin->sz = 0;
  bin->cap = c;
  bin->memsz = sz;

  // Adjust pointers into our bin
  bin->bitmap = (uint8_t *)bin + sizeof(BinHdr);
  bin->contents =
      (void *)(((uintptr_t)bin->bitmap + ((bin->cap + 7) / 8) + 0x0f) & ~0xf);

  ms->current_pages += sz / 0x1000;
  return bin;
}

void *memory_calloc(MallocState *ms, size_t nmemb, size_t size) {
#ifdef LIBC_MALLOC
  return calloc(nmemb, size);
#endif

  if (!ms)
    ms = &global_heap;

  void *ptr = memory_malloc(ms, nmemb * size);
  assert(ptr != NULL);
  memset(ptr, 0, nmemb * size);
  return ptr;
}

void *memory_realloc(MallocState *ms, void *ptr, size_t size) {
#ifdef LIBC_MALLOC
  return realloc(ptr, size);
#endif

  if (!ms)
    ms = &global_heap;

  size_t idx = 0;
  BinHdr *bin;
  // Check, including oversize
  for (; idx < NUM_BINS + 1; ++idx) {
    bin = ms->bins[idx];
    while (bin) {
      if (bin->contents <= ptr && ptr < (void *)bin + bin->memsz)
        goto bin_found;
      bin = bin->next;
    }
  }

  assert(0 && "No bin found!");

bin_found:
  void *dstptr = memory_malloc(ms, size);
  if (idx < NUM_BINS)
    memcpy(dstptr, ptr, BIN_SIZES[idx]);
  else
    memcpy(dstptr, ptr, (void *)bin + bin->memsz - bin->contents);
  memory_free(ms, ptr);
#ifdef MDEBUG
  printf("realloc(%p, %ld); // bin: %p, %p\n", ptr, size, bin, dstptr);
#endif
  return dstptr;
}

void *memory_malloc(MallocState *ms, size_t size) {
  // if(size > 256)
  // asm("int3");
#ifdef LIBC_MALLOC
  return malloc(size);
#endif

  if (!ms)
    ms = &global_heap;

  // round up to nearest power of 2
  size_t idx = 0;
  for (; idx < NUM_BINS; ++idx)
    if (size <= BIN_SIZES[idx])
      goto found_size;

  // Binning for oversize allocations
  BinHdr *bin = allocate_bin(ms, size);
  if (ms->bins[idx])
    ms->bins[idx]->prev = bin;
  bin->next = ms->bins[NUM_BINS];
  ms->bins[idx] = bin;
  bin->sz += 1;
#ifdef MDEBUG
  printf("malloc(0x%lx); // oversize: %p\n", size, bin->contents);
#endif
  ms->current_bytes += bin->memsz;
  ms->current_allocations += 1;
  ms->total_allocations += 1;
  return bin->contents;

found_size:
  bin = ms->bins[idx];
  if (!bin) {
    bin = allocate_bin(ms, BIN_SIZES[idx]);
    ms->bins[idx] = bin;
  }

  // Find bin with room for more allocations, keep a reference to the last
  // non-NULL bin.
  while (!(bin->sz < bin->cap) && bin->next)
    bin = bin->next;

  if (bin->sz == bin->cap) {
    bin->next = allocate_bin(ms, BIN_SIZES[idx]);
    bin->next->prev = bin;
    bin = bin->next;
  }

  size_t i = bv_find_first_zero(bin->bitmap, bin->cap);
  bv_set(bin->bitmap, i);
  bin->sz += 1;
  void *ptr = bin->contents + i * BIN_SIZES[idx];
  ms->current_bytes += BIN_SIZES[idx];
  ms->current_allocations += 1;
  ms->total_allocations += 1;
#ifdef MDEBUG
  printf("malloc(0x%lx); // %p\n", size, ptr);
#endif
  return ptr;
}

// TODO: Dumb code. Replace with hash lookup from (ptr & page_mask) -> chunk
// Since we are also writing our client code, we could also call free with the
// size of our allocation
void memory_free(MallocState *ms, void *ptr) {
#ifdef LIBC_MALLOC
  return free(ptr);
#endif

  if (!ms)
    ms = &global_heap;

  if (ptr == NULL)
    return;

  BinHdr *bin;
  size_t idx = 0;
  for (; idx < NUM_BINS; ++idx) {
    bin = ms->bins[idx];
    while (bin) {
      if (bin->contents <= ptr && ptr < (void *)bin + bin->memsz)
        goto bin_found;
      bin = bin->next;
    }
  }

  // Check oversize allocations
  bin = ms->bins[NUM_BINS];
  while (bin) {
    if (bin->contents == ptr)
      goto coalesce;
    bin = bin->next;
  }

  assert(0 && "No bin found!");

bin_found:
  size_t i = (ptr - bin->contents) / BIN_SIZES[idx];
  assert(bv_is_set(bin->bitmap, i));
  bv_unset(bin->bitmap, i);

coalesce:
  ms->current_allocations -= 1;
  if (idx == NUM_BINS)
    ms->current_bytes -= bin->memsz;
  else
    ms->current_bytes -= BIN_SIZES[idx];

  bin->sz -= 1;
  // We can't coalesce bins if we're using a persistent heap, since if a page
  // is freed as part of one state it can be reclaimed by another part of the
  // system before we can mmap it back.
  if (bin->sz == 0 && ms == &global_heap) {
    if (bin->prev)
      bin->prev->next = bin->next;
    if (bin->next)
      bin->next->prev = bin->prev;
    if (ms->bins[idx] == bin)
      ms->bins[idx] = bin->next;
    ms->current_pages -= bin->memsz / 0x1000;
    if (munmap(bin, bin->memsz) == -1)
      assert(0 && "munmap failed!");
    // printf("// Returned bin %p to OS\n", bin);
  }

#ifdef MDEBUG
  printf("free(%p);\n", ptr);
#endif
  return;
}

void print_malloc_stats(MallocState *ms) {
#ifdef LIBC_MALLOC
  malloc_stats();
  return;
#endif
  if (!ms)
    ms = &global_heap;

  printf("Current number of bytes allocated: %ld\n", ms->current_bytes);
  printf("Current number of allocations: %ld\n", ms->current_allocations);
  printf("Current number of pages: %ld\n", ms->current_pages);
  printf("Amount of memory in use: %ld\n", ms->current_pages * 0x1000);
  printf("Efficiency: %f%%\n",
         100.0 * (float)ms->current_bytes / (ms->current_pages * 0x1000));
  BinHdr *bin;
  for (size_t idx = 0; idx < NUM_BINS; ++idx) {
    bin = ms->bins[idx];
    size_t total_sz = 0;
    size_t total_cap = 0;
    while (bin) {
      total_sz += bin->sz;
      total_cap += bin->cap;
      bin = bin->next;
    }
    if (total_sz > 0)
      printf("Bin %ld-byte allocations, total size: %ld, total capacity: %ld\n",
             BIN_SIZES[idx], total_sz, total_cap);
  }

  bin = ms->bins[NUM_BINS];
  size_t num_oversize = 0;
  size_t total_size = 0;
  while (bin) {
    num_oversize += 1;
    total_size += bin->memsz;
    bin = bin->next;
  }
  printf("Wilderness: %ld oversize, total size: %ld\n", num_oversize,
         total_size);
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

// TODO: Dumb code, can expand comparisons to be 8-bytes at a time
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
