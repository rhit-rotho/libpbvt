#include <stdint.h>
#include <stdlib.h>

#define INITIAL_CAPACITY (16);

typedef struct Queue {
  void** arr;
  uint64_t capacity;
  uint64_t pos;
} Queue;

// public methods
Queue *queue_create(void);

void queue_push(Queue *q, void *v);
void *queue_front(Queue *q);
void *queue_popleft(Queue *q);
void queue_free(Queue *q);
