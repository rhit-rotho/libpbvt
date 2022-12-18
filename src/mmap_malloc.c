#include <string.h>

#include "mmap_malloc.h"

void *mmap_calloc(size_t nmemb, size_t size) {
  void *ptr = mmap_malloc(nmemb * size);
  memset(ptr, 0, nmemb * size);
  return ptr;
}

void *mmap_realloc(void *ptr, size_t size) {
  void *newptr = mmap_malloc(size);
  MappedChunk *chk = (void *)ptr - sizeof(MappedChunk);
  memcpy(newptr, ptr, chk->sz);
  mmap_free(ptr);
  return newptr;
}

void *mmap_malloc(size_t size) {
  uint64_t sz = size + sizeof(MappedChunk);
  sz = (sz + 0x1000) & ~0xfff;
  MappedChunk *chk = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  chk->sz = size;
  chk->mmap_sz = sz;
  return (void *)chk + sizeof(MappedChunk);
}

void mmap_free(void *ptr) {
  MappedChunk *chk = ptr - sizeof(MappedChunk);
  munmap(chk, chk->mmap_sz);
}
