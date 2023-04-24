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

  size_t data_sz = 0x20;
  uint8_t *data = pbvt_calloc(data_sz, sizeof(uint8_t));
  for (int i = 0; i < data_sz; ++i)
    data[i] = i;

  for (int i = 0; i < 0x10000; ++i) {
    encrypt(data, i, data_sz);
    pbvt_commit();
  }
  pbvt_stats();

  return 0;
}