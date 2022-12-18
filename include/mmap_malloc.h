#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct MappedChunk {
  size_t mmap_sz;
  size_t sz;
} MappedChunk;

void *mmap_calloc(size_t nmemb, size_t size);
void *mmap_realloc(void *ptr, size_t size);
void *mmap_malloc(size_t size);
void mmap_free(void *ptr);
