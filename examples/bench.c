#include <stdint.h>
#include <stdlib.h>

#include "pbvt.h"

#define ARRAY_SIZE 10
#define KEY 0xAA

void encrypt(uint8_t *data, uint8_t key, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    data[i] ^= key;
  }
}

int main(int argc, char **argv) {
  pbvt_init();

  srand(0);

  size_t data_sz = 0x1000;
  uint8_t *data = pbvt_calloc(data_sz, sizeof(uint8_t));
  for (int i = 0; i < 0x80000; ++i) {
    for (int j = 0; j < data_sz; ++j)
      data[j] = rand();

    pbvt_commit();
    if (i % 0x1000 == 0)
      pbvt_stats();
  }

  return 0;
}