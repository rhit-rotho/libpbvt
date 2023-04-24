// #include <assert.h>
#include <libunwind.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "fasthash.h"
#include "memory.h"

void my_assert(char *file, char *function, int line, char *str, int condition) {
  if (!condition) {
    unw_cursor_t cursor;
    unw_context_t context;

    unw_getcontext(&context);
    unw_init_local(&cursor, &context);

    fprintf(stderr, "%s:%ld: %s '%s' failed! Stack trace:\n", file, line,
            function, str);

    while (unw_step(&cursor) > 0) {
      unw_word_t offset, pc;
      char fname[64];

      unw_get_reg(&cursor, UNW_REG_IP, &pc);
      fname[0] = '\0';
      unw_get_proc_name(&cursor, fname, sizeof(fname), &offset);

      fprintf(stderr, "%p : (%s+0x%lx)\n", (void *)pc, fname, (long)offset);
    }

    exit(EXIT_FAILURE);
  }
}

#define assert(x) my_assert(__FILE__, __FUNCTION__, __LINE__, #x, x)

// Make sure this matches NUM_BINS in memory.h
// TODO: Add sizeof(PVector), sizeof(PVectorLeaf) as dedicated bin sizes
const size_t BIN_BITS[] = {3, 4, 5, 7, 8, 9};
const size_t BIN_SIZES[] = {8, 16, 32, 128, 256, 512};

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

  if (ms->bt == NULL)
    ms->bt = ht_create();

  uint64_t key = (uintptr_t)bin;
  while (key < (uintptr_t)bin + bin->memsz) {
    ht_insert(ms->bt, fasthash64(&key, sizeof(key), 0), bin);
    key += 0x1000;
  }

  // TODO: Add callbacks on_malloc, on_free, etc.
  if (ms->on_mmap)
    ms->on_mmap(bin);

  return bin;
}

// TODO: This should allocate nmemb all from the same bin
void *memory_calloc(MallocState *ms, size_t nmemb, size_t size) {
  if (!ms)
    ms = &global_heap;

  void *ptr = memory_malloc(ms, nmemb * size);
  assert(ptr != NULL);
  memset(ptr, 0, nmemb * size);
  return ptr;
}

void *memory_realloc(MallocState *ms, void *ptr, size_t size) {
  if (!ms)
    ms = &global_heap;

  if (ms->bt == NULL)
    ms->bt = ht_create();

  uint64_t key = ((uintptr_t)ptr) & ~0xfff;
  BinHdr *bin = ht_get(ms->bt, fasthash64(&key, sizeof(key), 0));
  size_t idx = bin->idx;

  assert(ptr < (void *)bin + bin->memsz);

  if (bin == NULL)
    assert(0 && "No bin found!");

  void *dstptr = memory_malloc(ms, size);
  if (idx < NUM_BINS)
    memcpy(dstptr, ptr, BIN_SIZES[idx]);
  else
    memcpy(dstptr, ptr, (void *)bin + bin->memsz - bin->contents);
  memory_free(ms, ptr);
#ifdef MDEBUG
  printf("realloc(%.16lx, %ld); // bin: %.16lx, %.16lx\n", ptr, size, bin,
         dstptr);
#endif

  return dstptr;
}

void *memory_malloc(MallocState *ms, size_t size) {
  if (!ms)
    ms = &global_heap;

  // round up to nearest power of 2
  size_t idx = 0;
  for (; idx < NUM_BINS; ++idx)
    if (size <= BIN_SIZES[idx])
      goto found_size;

  // Binning for oversize allocations
  BinHdr *bin = allocate_bin(ms, size);
  bin->idx = NUM_BINS;
  if (ms->bins[idx]) {
    bin->next = ms->bins[idx];
    bin->prev = ms->bins[idx]->prev;
    ms->bins[idx]->prev = bin;
  }
  ms->bins[idx] = bin;
  bin->sz += 1;
#ifdef MDEBUG
  printf("malloc(0x%lx); // oversize: %.16lx bin: %.16lx\n", size,
         bin->contents, bin);
#endif
  ms->current_bytes += bin->memsz;
  ms->current_allocations += 1;
  ms->total_allocations += 1;
  return bin->contents;

found_size:
  bin = ms->bins[idx];
  if (!bin) {
    bin = allocate_bin(ms, BIN_SIZES[idx]);
    bin->idx = idx;
    if (ms->bins[idx]) {
      bin->next = ms->bins[idx];
      bin->prev = ms->bins[idx]->prev;
      ms->bins[idx]->prev = bin;
    }
    ms->bins[idx] = bin;
  }

  // Ensure sure the first bin always has enough room for more allocations
  if (bin->sz + 1 == bin->cap) {
    BinHdr *nbin = allocate_bin(ms, BIN_SIZES[idx]);
    nbin->idx = idx;
    if (ms->bins[idx]) {
      nbin->next = ms->bins[idx];
      nbin->prev = ms->bins[idx]->prev;
      ms->bins[idx]->prev = nbin;
    }
    ms->bins[idx] = nbin;
    bin = nbin;
  }

  assert(bin->sz + 1 < bin->cap);

  size_t i = bv_find_first_zero(bin->bitmap, bin->cap);
  bv_set(bin->bitmap, i);
  bin->sz += 1;
  void *ptr = bin->contents + i * BIN_SIZES[idx];
  ms->current_bytes += BIN_SIZES[idx];
  ms->current_allocations += 1;
  ms->total_allocations += 1;
#ifdef MDEBUG
  printf("malloc(0x%lx); // %.16lx\n", size, ptr);
#endif
  return ptr;
}

void memory_free(MallocState *ms, void *ptr) {
  if (!ms)
    ms = &global_heap;
  if (ptr == NULL)
    return;

#ifdef MDEBUG
  printf("free(%.16lx);\n", ptr);
#endif

  if (ms->bt == NULL)
    ms->bt = ht_create();

  BinHdr *bin;
  size_t idx;

  uint64_t key = ((uintptr_t)ptr) & ~0xfff;
  bin = ht_get(ms->bt, fasthash64(&key, sizeof(key), 0));
  assert(bin && "WARNING: No bin found!");
  idx = bin->idx;

  // Is this an allocation in the wilderness?
  if (idx < NUM_BINS) {
    assert(bin <= ptr);
    assert(ptr < (void *)bin + bin->memsz);
    size_t i = (ptr - bin->contents) >> BIN_BITS[idx];
    if (!bv_is_set(bin->bitmap, i)) {
      printf("Bin: %.16lx idx: %.16lx ptr: %.16lx BIN_BITS: %.16lx i: %.16lx "
             "memsz: %.16lx\n",
             bin, idx, ptr, BIN_BITS[idx], ptr - bin->contents, bin->memsz);
    }
    assert(bv_is_set(bin->bitmap, i));
    bv_unset(bin->bitmap, i);
    memset(ptr, 0x54, BIN_SIZES[idx]);
  }

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

    uint64_t key = (uintptr_t)bin;
    while (key < (uintptr_t)bin + bin->memsz) {
      ht_remove(ms->bt, fasthash64(&key, sizeof(key), 0));
      key += 0x1000;
    }

    if (munmap(bin, bin->memsz) == -1)
      assert(0 && "munmap failed!");
  }

  return;
}

void print_malloc_stats(MallocState *ms) {
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

size_t bv_find_first_zero(uint8_t *bv, size_t cap) {
  size_t i = 0;
  for (; i < (cap & ~7); i += 8)
    if (*(uint64_t *)&bv[i] != UINT64_MAX)
      break;

  for (; i < cap; i += 1)
    if (bv[i] != UINT8_MAX)
      break;

  uint8_t val = bv[i];
  size_t j = i * BITS_PER_BLOCK;
  while (val & 1) {
    val >>= 1;
    j += 1;
  }

  return j;
}
