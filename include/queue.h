#include <stdint.h>
#include <stdlib.h>

#define INITIAL_CAPACITY (4);

typedef struct Queue {
  void **arr;
  uint64_t capacity;
  uint64_t head;
  uint64_t tail;
} Queue;

// public methods
Queue *queue_create(void);
void queue_free(Queue *q);

void *queue_front(Queue *q);
void *queue_peekleft(Queue *q, uint64_t n);
void *queue_peekright(Queue *q, uint64_t n);

void queue_push(Queue *q, void *v);

void *queue_popleft(Queue *q);
void *queue_popright(Queue *q);

uint64_t queue_size(Queue *q);
