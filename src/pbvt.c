#include "pbvt.h"
#include <stdlib.h>
#include <stdint.h>

// TODO: We don't need all of malloc's functionality, a bump allocator would
// probably work just fine (this may or may not be necessary for performance)

#define BITS_PER_LEVEL 5
#define NUM_CHILDREN (1 << BITS_PER_LEVEL)

typedef union pvector
{
    struct pleaf;
    struct pedge;
} pvector_t;

typedef struct
{
    uint8_t populated[NUM_CHILDREN >> 3];
    pvector_t *children[NUM_CHILDREN];
} pleaf_t;

typedef struct
{
    uint8_t populated[NUM_CHILDREN >> 3];
    pvector_t *children[NUM_CHILDREN];
} pedge_t;

pvector_t *pbvt_create(void)
{
    pvector_t *v = (pvector_t *)malloc(sizeof(pvector_t));
    return v;
}

uint8_t pbvt_get(pvector_t *v, uint64_t idx)
{
    return -1;
}

pvector_t *pbvt_update(pvector_t *v, uint64_t idx, uint64_t val)
{
    return v;
}
