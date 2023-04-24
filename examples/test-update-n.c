#include "hashtable.h"
#include "memory.h"
#include "pvector.h"

#define BASE_ADDR (0x1000)

int main(int argc, char **argv) {
  char buf[0x1000];
  for (int i = 0; i < sizeof(buf) / sizeof(char); ++i)
    buf[i] = i % 0x40;

  PVector *v = memory_calloc(NULL, 1, sizeof(PVector));
  v->hash = 0UL;
  v->refcount = 1;

  ht = ht_create();
  ht_insert(ht, 0UL, v);

  for (int i = 0; i < 0x100; ++i) {
    PVector *t = pvector_update_n(v, BASE_ADDR, buf, sizeof(buf));
    pvector_gc(v, MAX_DEPTH - 1);
    v = t;
  }

  for (int i = 0; i < sizeof(buf); ++i) {
    if (buf[i] != pvector_get(v, BASE_ADDR + i)) {
      printf("mismatch at %d: buf[%d]==%d, v[%d]==%d", i, i, buf[i], i,
             pvector_get(v, BASE_ADDR + i));
    }
  }
  printf("All matched! %d\n", sizeof(buf));
  return 0;
}