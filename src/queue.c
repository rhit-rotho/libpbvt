#include <assert.h>
#include <string.h>

#include "queue.h"

Queue *queue_create(void) {
  Queue *q = calloc(sizeof(Queue), 1);
  q->capacity = INITIAL_CAPACITY;
  q->arr = calloc(sizeof(void *) * q->capacity, 1);
  q->head = 0;
  q->tail = 0;
  return q;
}

uint64_t queue_size(Queue *q) {
  return (q->tail + q->capacity - q->head) & (q->capacity - 1);
}

void queue_push(Queue *q, void *v) {
  if (queue_size(q) + 1 == q->capacity) {
    q->arr = realloc(q->arr, sizeof(void *) * q->capacity * 2);
    if (q->head > q->tail) {
      uint64_t remaining = q->capacity - q->head;
      memmove(&q->arr[2 * q->capacity - remaining], &q->arr[q->head],
              sizeof(void *) * remaining);
      q->head = 2 * q->capacity - remaining;
    }
    q->capacity *= 2;
  }
  q->arr[q->tail] = v;
  q->tail = (q->tail + 1) & (q->capacity - 1);
}

void *queue_popleft(Queue *q) {
  assert(queue_size(q) > 0);
  void *v = q->arr[q->head];
  q->head = (q->head + 1) & (q->capacity - 1);
  return v;
}

void *queue_front(Queue *q) {
  assert(queue_size(q) > 0);
  return q->arr[(q->capacity + q->tail - 1) & (q->capacity - 1)];
}

void queue_free(Queue *q) {
  free(q->arr);
  free(q);
}