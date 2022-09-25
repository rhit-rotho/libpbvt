#include <stdint.h>
#include <stdlib.h>

#define INITIAL_CAPACITY (16);

typedef struct queue
{
    void **arr;
    uint64_t capacity;
    uint64_t pos;
} queue_t;

queue_t *queue_create(void);
void queue_push(queue_t *q, void *v);
void *queue_front(queue_t *q);
void queue_free(queue_t *q);
void *queue_popleft(queue_t *q);