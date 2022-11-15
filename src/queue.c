#include <assert.h>
#include <string.h>

#include "memory.h"
#include "queue.h"

Queue *queue_create(void) {
  Queue *q = memory_calloc(NULL, 1, sizeof(Queue));
  q->capacity = INITIAL_CAPACITY;
  q->arr = memory_calloc(NULL, q->capacity, sizeof(void *));
  q->head = 0;
  q->tail = 0;
  return q;
}

uint64_t queue_size(Queue *q) {
  return (q->tail + q->capacity - q->head) & (q->capacity - 1);
}

void queue_push(Queue *q, void *v) {
  if (queue_size(q) + 1 == q->capacity) {
    q->arr = memory_realloc(NULL, q->arr, sizeof(void *) * q->capacity * 2);
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

void *queue_popright(Queue *q) {
  assert(queue_size(q) > 0);
  void *v = q->arr[(q->capacity + q->tail - 1) & (q->capacity - 1)];
  q->tail = (q->capacity + q->tail - 1) & (q->capacity - 1);
  return v;
}

void *queue_front(Queue *q) { return queue_peekright(q, 0); }

// What would be the result of doing popright n times
void *queue_peekright(Queue *q, uint64_t n) {
  assert(n < queue_size(q));
  return q->arr[(-1 + q->capacity + q->tail - n) & (q->capacity - 1)];
}

// What would be the result of doing popleft n times
void *queue_peekleft(Queue *q, uint64_t n) {
  assert(n < queue_size(q));
  return q->arr[(q->head + n) & (q->capacity - 1)];
}

void queue_free(Queue *q) {
  memory_free(NULL, q->arr);
  memory_free(NULL, q);
}